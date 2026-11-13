import { randomUUID } from 'node:crypto';
import { appendFileSync, readFileSync, writeFileSync } from 'node:fs';
import type pg from 'pg';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { recordEvent } from '../src/audit/audit.js';
import { getChainStatus, verifyAgainstFiles, verifyChain } from '../src/audit/verify.js';
import { adminPool, auditLogPath, closeAll, resetAuditLog, resetDb } from './helpers.js';

async function enModoReplica(fn: (client: pg.PoolClient) => Promise<void>): Promise<void> {
  const client = await adminPool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SET LOCAL session_replication_role = replica');
    await fn(client);
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

async function insertarTresEventos() {
  const primero = await recordEvent({
    type: 'auth.register.success',
    userId: randomUUID(),
    identifier: 'ana@ejemplo.test',
  });
  const segundo = await recordEvent({
    type: 'auth.login.failure',
    reason: 'bad_password',
    identifier: 'ana@ejemplo.test',
  });
  const tercero = await recordEvent({
    type: 'auth.login.success',
    userId: primero.eventId,
    identifier: 'ana@ejemplo.test',
  });
  return { primero, segundo, tercero };
}

beforeEach(async () => {
  await resetDb();
  resetAuditLog();
});

afterAll(async () => {
  await closeAll();
});

describe('verifyChain', () => {
  it('considera íntegra una tabla vacía con count 0', async () => {
    const res = await verifyChain();
    expect(res).toEqual({
      ok: true,
      count: 0,
      lastSeq: null,
      lastHash: null,
    });
  });

  it('considera íntegra una cadena de varios eventos insertados con recordEvent', async () => {
    const { tercero } = await insertarTresEventos();

    const res = await verifyChain();
    expect(res).toEqual({
      ok: true,
      count: 3,
      lastSeq: tercero.seq,
      lastHash: tercero.hash,
    });
  });

  it('detecta hash_mismatch en el seq de una fila intermedia alterada en modo replica', async () => {
    await insertarTresEventos();

    await enModoReplica(async (client) => {
      await client.query("UPDATE auth_events SET reason = 'unknown_user' WHERE seq = 2");
    });

    const res = await verifyChain();
    expect(res).toEqual({
      ok: false,
      count: 2,
      brokenSeq: 2,
      problem: 'hash_mismatch',
    });
  });

  it('detecta seq_gap en el seq siguiente tras borrar una fila intermedia en modo replica', async () => {
    await insertarTresEventos();

    await enModoReplica(async (client) => {
      await client.query('DELETE FROM auth_events WHERE seq = 2');
    });

    const res = await verifyChain();
    expect(res).toEqual({
      ok: false,
      count: 2,
      brokenSeq: 3,
      problem: 'seq_gap',
    });
  });

  it('detecta prev_hash_mismatch al cambiar el prev_hash de una fila', async () => {
    await insertarTresEventos();

    await enModoReplica(async (client) => {
      await client.query("UPDATE auth_events SET prev_hash = repeat('f', 64) WHERE seq = 2");
    });

    const res = await verifyChain();
    expect(res).toEqual({
      ok: false,
      count: 2,
      brokenSeq: 2,
      problem: 'prev_hash_mismatch',
    });
  });
});

describe('verifyAgainstFiles', () => {
  it('no encuentra diferencias tras eventos normales', async () => {
    await insertarTresEventos();

    const check = await verifyAgainstFiles();
    expect(check).toEqual({
      linesChecked: 3,
      malformedLines: 0,
      mismatches: [],
    });
  });

  it('detecta hash_differs cuando se recalcula en la base el hash de una fila alterada', async () => {
    await insertarTresEventos();

    await enModoReplica(async (client) => {
      await client.query("UPDATE auth_events SET reason = 'unknown_user' WHERE seq = 2");
      await client.query(`
        UPDATE auth_events e
        SET hash = encode(sha256(convert_to(e.prev_hash || auth_event_canonical(e), 'UTF8')), 'hex')
        WHERE e.seq = 2
      `);
    });

    const check = await verifyAgainstFiles();
    expect(check).toEqual({
      linesChecked: 3,
      malformedLines: 0,
      mismatches: [{ seq: 2, problem: 'hash_differs' }],
    });
  });

  it('detecta missing_in_file cuando falta en el archivo un seq dentro del rango cubierto', async () => {
    await insertarTresEventos();

    const lineas = readFileSync(auditLogPath, 'utf8')
      .split('\n')
      .filter((l) => l.trim() !== '')
      .filter((l) => {
        const parsed = JSON.parse(l) as { event?: { sequence?: number } };
        return parsed.event?.sequence !== 2;
      });
    writeFileSync(auditLogPath, `${lineas.join('\n')}\n`, 'utf8');

    const check = await verifyAgainstFiles();
    expect(check).toEqual({
      linesChecked: 2,
      malformedLines: 0,
      mismatches: [{ seq: 2, problem: 'missing_in_file' }],
    });
  });

  it('cuenta líneas malformadas (no JSON o sin sequence/hash) e ignora audit.write.failed', async () => {
    await insertarTresEventos();

    appendFileSync(
      auditLogPath,
      [
        'linea que no es json {',
        JSON.stringify({ message: 'auth.login.success', event: { action: 'auth.login.success' } }),
        JSON.stringify({
          message: 'audit.write.failed',
          event: { action: 'audit.write.failed', outcome: 'failure' },
        }),
      ].join('\n') + '\n',
      'utf8',
    );

    const check = await verifyAgainstFiles();
    expect(check).toEqual({
      linesChecked: 3,
      malformedLines: 2,
      mismatches: [],
    });
  });
});

describe('getChainStatus', () => {
  it('reutiliza el resultado en memoria dentro de la ventana salvo con force', async () => {
    await insertarTresEventos();
    const inicial = await getChainStatus({ force: true });
    expect(inicial.result).toMatchObject({ ok: true, count: 3 });

    await enModoReplica(async (client) => {
      await client.query("UPDATE auth_events SET reason = 'unknown_user' WHERE seq = 2");
    });

    const enCache = await getChainStatus();
    expect(enCache.result).toEqual(inicial.result);
    expect(enCache.verifiedAt.getTime()).toBe(inicial.verifiedAt.getTime());

    const forzado = await getChainStatus({ force: true });
    expect(forzado.result).toEqual({
      ok: false,
      count: 2,
      brokenSeq: 2,
      problem: 'hash_mismatch',
    });
  });
});
