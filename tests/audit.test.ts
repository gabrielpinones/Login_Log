import { readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { pool } from '../src/db.js';
import { config } from '../src/config.js';
import { recordEvent, AuditWriteError } from '../src/audit/audit.js';
import type { AuditEventInput } from '../src/audit/events.js';
import { adminPool, auditLogPath, closeAll, readAuditLines, resetAuditLog, resetDb } from './helpers.js';

const ZERO_HASH = '0'.repeat(64);
const HEX64 = /^[0-9a-f]{64}$/;
const CONTROL = /[\u0000-\u001F\u007F-\u009F\u2028\u2029]/;

const loginOk: AuditEventInput = { type: 'auth.login.success' };

async function rows() {
  const { rows } = await adminPool.query('SELECT * FROM auth_events ORDER BY seq');
  return rows;
}

beforeEach(async () => {
  vi.restoreAllMocks();
  await resetDb();
  await resetAuditLog();
});

afterAll(async () => {
  await closeAll();
});

describe('recordEvent: fila', () => {
  it('guarda todos los campos esperados', async () => {
    const requestId = randomUUID();
    const userId = randomUUID();
    const sessionId = randomUUID();
    const recorded = await recordEvent(
      {
        type: 'auth.login.failure',
        reason: 'bad_password',
        userId,
        sessionId,
        httpStatus: 401,
        details: { attempt: 3, remembered: false, note: null },
      },
      {
        requestId,
        sourceIp: '203.0.113.7',
        userAgent: 'Mozilla/5.0 prueba',
        method: 'POST',
        route: '/login',
      },
    );

    const [row] = await rows();
    expect(row).toMatchObject({
      event_id: recorded.eventId,
      event_type: 'auth.login.failure',
      outcome: 'failure',
      severity: 'warn',
      reason: 'bad_password',
      user_id: userId,
      session_id: sessionId,
      source_ip: '203.0.113.7',
      user_agent: 'Mozilla/5.0 prueba',
      http_method: 'POST',
      route: '/login',
      http_status: 401,
      request_id: requestId,
      service: config.serviceName,
      version: config.version,
      environment: config.env,
      hostname: config.hostname,
      details: { attempt: 3, remembered: false, note: null },
    });
    expect(row.identifier_hash).toBeNull();
    expect(new Date(row.occurred_at).getTime()).toBe(recorded.occurredAt.getTime());
  });

  it('encadena tres eventos seguidos desde el hash cero', async () => {
    const a = await recordEvent(loginOk);
    const b = await recordEvent(loginOk);
    const c = await recordEvent(loginOk);

    expect([a.seq, b.seq, c.seq]).toEqual([1, 2, 3]);
    expect(a.prevHash).toBe(ZERO_HASH);
    expect(b.prevHash).toBe(a.hash);
    expect(c.prevHash).toBe(b.hash);

    const stored = await rows();
    expect(stored.map((r) => r.prev_hash)).toEqual([ZERO_HASH, a.hash, b.hash]);
  });

  it('guarda 20 eventos concurrentes sin huecos y con la cadena íntegra', async () => {
    await Promise.all(Array.from({ length: 20 }, () => recordEvent(loginOk)));

    const stored = await rows();
    expect(stored.map((r) => r.seq)).toEqual(Array.from({ length: 20 }, (_, i) => i + 1));
    expect(stored[0].prev_hash).toBe(ZERO_HASH);
    for (let i = 1; i < stored.length; i++) {
      expect(stored[i].prev_hash).toBe(stored[i - 1].hash);
    }
  });
});

describe('recordEvent: línea JSONL', () => {
  it('contiene los campos ECS y coincide con la fila', async () => {
    const requestId = randomUUID();
    const userId = randomUUID();
    const recorded = await recordEvent(
      { type: 'session.expired', reason: 'idle_timeout', userId, httpStatus: 302, details: { minutes: 15 } },
      { requestId, sourceIp: '198.51.100.9', userAgent: 'curl/8', method: 'GET', route: '/panel' },
    );

    const [row] = await rows();
    const lines = readAuditLines();
    expect(lines).toHaveLength(1);
    const line = lines[0]!;

    expect(line['@timestamp']).toBe(recorded.occurredAt.toISOString());
    expect(line.ecs.version).toBe('8.11.0');
    expect(line.message).toBe('session.expired');
    expect(line.log.level).toBe('info');
    expect(line.event).toMatchObject({
      id: recorded.eventId,
      kind: 'event',
      category: ['session'],
      action: 'session.expired',
      outcome: 'success',
      reason: 'idle_timeout',
      sequence: row.seq,
      hash: row.hash,
    });
    expect(line.event.hash).toBe(recorded.hash);
    expect(line.user.id).toBe(userId);
    expect(line.source.ip).toBe('198.51.100.9');
    expect(line.user_agent.original).toBe('curl/8');
    expect(line.http.request).toEqual({ method: 'GET', id: requestId });
    expect(line.http.response.status_code).toBe(302);
    expect(line.url.path).toBe('/panel');
    expect(line.service).toEqual({
      name: config.serviceName,
      version: config.version,
      environment: config.env,
    });
    expect(line.host.hostname).toBe(config.hostname);
    expect(line.login_log.prev_hash).toBe(ZERO_HASH);
    expect(line.login_log.details).toEqual({ minutes: 15 });
  });

  it('omite las claves sin valor', async () => {
    await recordEvent(loginOk);
    const line = readAuditLines()[0]!;
    expect(line.user).toBeUndefined();
    expect(line.source).toBeUndefined();
    expect(line.http).toBeUndefined();
    expect(line.event.reason).toBeUndefined();
    expect(line.login_log.identifier_hash).toBeUndefined();
  });

  it('deja un User-Agent con saltos de línea y 5000 caracteres en una sola línea de 256', async () => {
    const ua = `Mozilla\r\n{"fake":"entry"}\n${'a'.repeat(5000)}`;
    await recordEvent(loginOk, { userAgent: ua });

    const raw = readFileSync(auditLogPath, 'utf8');
    expect(raw.split('\n').filter((l) => l !== '')).toHaveLength(1);

    const line = readAuditLines()[0]!;
    const original: string = line.user_agent.original;
    expect(original).toHaveLength(256);
    expect(CONTROL.test(original)).toBe(false);

    const [row] = await rows();
    expect(row.user_agent).toBe(original);
  });

  it('censura una clave password dentro de details', async () => {
    await recordEvent({ type: 'auth.login.success', details: { password: 'hunter2-secreto', ok: true } });

    const raw = readFileSync(auditLogPath, 'utf8');
    expect(raw).not.toContain('hunter2-secreto');
    const line = readAuditLines()[0]!;
    expect(line.login_log.details.password).toBe('[REDACTED]');
    expect(line.login_log.details.ok).toBe(true);
  });
});

describe('recordEvent: saneamiento', () => {
  it('nunca guarda el identificador en claro y su HMAC no depende de mayúsculas', async () => {
    const identifier = 'Persona.Reconocible@ejemplo.test';
    await recordEvent({ type: 'auth.login.success', identifier });
    await recordEvent({ type: 'auth.login.success', identifier: `  ${identifier.toUpperCase()} ` });

    const stored = await rows();
    const serialized = JSON.stringify(stored).toLowerCase();
    expect(serialized).not.toContain('reconocible');
    expect(readFileSync(auditLogPath, 'utf8').toLowerCase()).not.toContain('reconocible');

    expect(stored[0].identifier_hash).toMatch(HEX64);
    expect(stored[1].identifier_hash).toBe(stored[0].identifier_hash);
    expect(readAuditLines()[0]!.login_log.identifier_hash).toBe(stored[0].identifier_hash);
  });

  it('normaliza ::ffff:10.0.0.1, quita la zona IPv6 y guarda null para una IP inválida', async () => {
    await recordEvent(loginOk, { sourceIp: '::ffff:10.0.0.1' });
    await recordEvent(loginOk, { sourceIp: 'no-es-una-ip' });
    await recordEvent(loginOk, { sourceIp: 'fe80::1%eth0' });

    const stored = await rows();
    expect(stored[0].source_ip).toBe('10.0.0.1');
    expect(stored[1].source_ip).toBeNull();
    expect(stored[2].source_ip).toBe('fe80::1');
  });

  it('guarda null cuando request_id no es un uuid', async () => {
    await recordEvent(loginOk, { requestId: 'abc-123' });

    const [row] = await rows();
    expect(row.request_id).toBeNull();
  });
});

describe('recordEvent: fallo de escritura', () => {
  it('rechaza con AuditWriteError y deja el evento perdido en el archivo', async () => {
    vi.spyOn(pool, 'query').mockRejectedValue(new Error('base caída'));

    const identifier = 'victima@ejemplo.test';
    await expect(
      recordEvent(
        { type: 'auth.login.failure', reason: 'unknown_user', identifier, httpStatus: 401 },
        { sourceIp: '192.0.2.1', route: '/login', method: 'POST' },
      ),
    ).rejects.toBeInstanceOf(AuditWriteError);

    const lines = readAuditLines();
    expect(lines).toHaveLength(1);
    const line = lines[0]!;
    expect(line.log.level).toBe('error');
    expect(line.event.action).toBe('audit.write.failed');
    expect(line.login_log.lost_event).toMatchObject({
      event_type: 'auth.login.failure',
      reason: 'unknown_user',
      source_ip: '192.0.2.1',
      route: '/login',
      http_status: 401,
    });
    expect(line.login_log.lost_event.identifier_hash).toMatch(HEX64);
    expect(JSON.stringify(line)).not.toContain(identifier);
    expect(await rows()).toHaveLength(0);
  });
});
