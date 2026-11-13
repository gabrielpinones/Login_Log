import { randomUUID } from 'node:crypto';
import pg from 'pg';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { config } from '../src/config.js';
import { pool } from '../src/db.js';
import { adminPool, closeAll, resetDb } from './helpers.js';

const CEROS = '0'.repeat(64);

const COLUMNAS =
  'event_id, occurred_at, event_type, outcome, reason, severity, user_id, identifier_hash, session_id, ' +
  'source_ip, user_agent, http_method, route, http_status, request_id, service, version, environment, hostname, details';

function marcadores(desde: number, cantidad: number): string {
  return Array.from({ length: cantidad }, (_, i) => `$${desde + i}`).join(', ');
}

const INSERT_SQL = `INSERT INTO auth_events (${COLUMNAS}) VALUES (${marcadores(1, 20)}) RETURNING seq, prev_hash, hash`;

const RECALCULO_SQL = `
  SELECT seq, prev_hash, hash,
         encode(sha256(convert_to(prev_hash || auth_event_canonical(e), 'UTF8')), 'hex') AS recalculado,
         auth_event_canonical(e) AS canonico
  FROM auth_events e
  ORDER BY seq`;

type Encadenado = { seq: number; prev_hash: string; hash: string };
type Recalculo = Encadenado & { recalculado: string; canonico: string };
type Consulta = (sql: string, valores: unknown[]) => Promise<pg.QueryResult<Encadenado>>;

const conPoolApp: Consulta = (sql, valores) => pool.query<Encadenado>(sql, valores);

function valoresEvento(n: number, ocurrido: Date): unknown[] {
  const exito = n % 2 === 1;
  return [
    randomUUID(),
    ocurrido,
    exito ? 'login_success' : 'login_failure',
    exito ? 'success' : 'failure',
    exito ? null : 'invalid_credentials',
    exito ? 'info' : 'warn',
    randomUUID(),
    'ab'.repeat(32),
    null,
    '192.0.2.10',
    'vitest',
    'POST',
    '/login',
    exito ? 303 : 401,
    randomUUID(),
    'login-log',
    '0.0.0-test',
    'test',
    'host-de-prueba',
    // Texto no ASCII para ejercitar convert_to(..., 'UTF8') en el hash.
    JSON.stringify({ n, nota: 'ñandú "con comillas"' }),
  ];
}

function primera<T>(filas: T[]): T {
  const fila = filas[0];
  if (fila === undefined) throw new Error('La consulta no devolvió filas');
  return fila;
}

async function insertar(n: number, consulta: Consulta = conPoolApp, ocurrido = new Date()): Promise<Encadenado> {
  const { rows } = await consulta(INSERT_SQL, valoresEvento(n, ocurrido));
  return primera(rows);
}

// Recorre la cadena por seq como lo haría un verificador externo y devuelve los seq inválidos.
async function verificarCadena(): Promise<{ total: number; invalidas: number[] }> {
  const { rows } = await pool.query<Recalculo>(RECALCULO_SQL);
  const invalidas: number[] = [];
  let prevEsperado = CEROS;
  let seqEsperado = 1;
  for (const fila of rows) {
    if (fila.seq !== seqEsperado || fila.prev_hash !== prevEsperado || fila.hash !== fila.recalculado) {
      invalidas.push(fila.seq);
    }
    prevEsperado = fila.hash;
    seqEsperado = fila.seq + 1;
  }
  return { total: rows.length, invalidas };
}

async function contarEventos(): Promise<number> {
  const { rows } = await adminPool.query<{ n: number }>('SELECT count(*) AS n FROM auth_events');
  return primera(rows).n;
}

async function conZonaHoraria<T>(
  zona: 'UTC' | 'America/Santiago',
  fn: (cliente: pg.PoolClient) => Promise<T>,
): Promise<T> {
  const cliente = await pool.connect();
  try {
    await cliente.query(`SET TIME ZONE '${zona}'`);
    return await fn(cliente);
  } finally {
    // La conexión vuelve al pool: no debe arrastrar la zona horaria a otros tests.
    await cliente.query('RESET TIME ZONE');
    cliente.release();
  }
}

beforeEach(async () => {
  await resetDb();
});

afterAll(async () => {
  await closeAll();
});

describe('cadena de hashes de auth_events', () => {
  it('encadena tres inserciones con seq 1, 2 y 3', async () => {
    const a = await insertar(1);
    const b = await insertar(2);
    const c = await insertar(3);

    expect([a.seq, b.seq, c.seq]).toEqual([1, 2, 3]);
    expect(a.prev_hash).toBe(CEROS);
    expect(b.prev_hash).toBe(a.hash);
    expect(c.prev_hash).toBe(b.hash);
    for (const fila of [a, b, c]) expect(fila.hash).toMatch(/^[0-9a-f]{64}$/);

    const { rows } = await pool.query<Recalculo>(RECALCULO_SQL);
    expect(rows.map((f) => f.recalculado)).toEqual([a.hash, b.hash, c.hash]);
    expect(await verificarCadena()).toEqual({ total: 3, invalidas: [] });
  });

  it('el trigger sobrescribe seq, prev_hash y hash enviados por el cliente', async () => {
    const falso = 'a'.repeat(64);
    const { rows } = await pool.query<Encadenado>(
      `INSERT INTO auth_events (${COLUMNAS}, seq, prev_hash, hash)
       VALUES (${marcadores(1, 23)}) RETURNING seq, prev_hash, hash`,
      [...valoresEvento(1, new Date()), 999, 'f'.repeat(64), falso],
    );
    const fila = primera(rows);

    expect(fila.seq).toBe(1);
    expect(fila.prev_hash).toBe(CEROS);
    expect(fila.hash).not.toBe(falso);
    expect(await verificarCadena()).toEqual({ total: 1, invalidas: [] });
  });

  it('20 inserciones concurrentes dejan seq sin huecos y la cadena íntegra', async () => {
    // Pool propio con una conexión por inserción para que compitan de verdad por el bloqueo.
    const concurrente = new pg.Pool({ connectionString: config.databaseUrl, max: 20 });
    try {
      const resultados = await Promise.all(
        Array.from({ length: 20 }, (_, i) =>
          insertar(i + 1, (sql, valores) => concurrente.query<Encadenado>(sql, valores)),
        ),
      );
      const seqs = resultados.map((r) => r.seq).sort((x, y) => x - y);
      expect(seqs).toEqual(Array.from({ length: 20 }, (_, i) => i + 1));
    } finally {
      await concurrente.end();
    }
    expect(await verificarCadena()).toEqual({ total: 20, invalidas: [] });
  });

  it('el hash no depende de la zona horaria de la sesión', async () => {
    const ocurrido = new Date('2026-07-01T12:34:56.789Z');
    const consultaCon = (cliente: pg.PoolClient): Consulta => (sql, valores) =>
      cliente.query<Encadenado>(sql, valores);

    await conZonaHoraria('UTC', (c) => insertar(1, consultaCon(c), ocurrido));
    await conZonaHoraria('America/Santiago', (c) => insertar(2, consultaCon(c), ocurrido));

    const enSantiago = await conZonaHoraria('America/Santiago', (c) => c.query<Recalculo>(RECALCULO_SQL));
    const enUtc = await conZonaHoraria('UTC', (c) => c.query<Recalculo>(RECALCULO_SQL));

    expect(enSantiago.rows).toHaveLength(2);
    for (const fila of enSantiago.rows) {
      expect(fila.recalculado).toBe(fila.hash);
      const canonico = JSON.parse(fila.canonico) as { occurred_at: string };
      expect(canonico.occurred_at).toBe('2026-07-01T12:34:56.789000Z');
    }
    expect(enSantiago.rows.map((f) => f.canonico)).toEqual(enUtc.rows.map((f) => f.canonico));
    expect(await verificarCadena()).toEqual({ total: 2, invalidas: [] });
  });
});

describe('inmutabilidad de auth_events', () => {
  const MODIFICACIONES = [
    "UPDATE auth_events SET reason = 'alterado'",
    'DELETE FROM auth_events',
    'TRUNCATE auth_events',
  ];

  beforeEach(async () => {
    // Los triggers por fila solo se disparan si hay filas afectadas.
    await insertar(1);
  });

  it.each(MODIFICACIONES)('el rol de la aplicación no tiene permiso: %s', async (sql) => {
    await expect(pool.query(sql)).rejects.toMatchObject({ code: '42501' });
    expect(await contarEventos()).toBe(1);
  });

  it.each(MODIFICACIONES)('el trigger lo impide incluso al superusuario: %s', async (sql) => {
    await expect(adminPool.query(sql)).rejects.toMatchObject({
      code: 'P0001',
      message: expect.stringContaining('solo inserción'),
    });
    expect(await contarEventos()).toBe(1);
  });

  it('la verificación detecta exactamente la fila alterada saltándose los triggers', async () => {
    await insertar(2);
    await insertar(3);

    const cliente = await adminPool.connect();
    try {
      await cliente.query('BEGIN');
      await cliente.query('SET LOCAL session_replication_role = replica');
      const r = await cliente.query("UPDATE auth_events SET reason = 'alterado' WHERE seq = 2");
      await cliente.query('COMMIT');
      expect(r.rowCount).toBe(1);
    } catch (err) {
      await cliente.query('ROLLBACK');
      throw err;
    } finally {
      cliente.release();
    }

    expect(await verificarCadena()).toEqual({ total: 3, invalidas: [2] });
  });
});

describe('permisos de login_log_app sobre users', () => {
  beforeEach(async () => {
    await pool.query(
      "INSERT INTO users (email, password_hash) VALUES ('ana@ejemplo.test', 'hash-de-prueba')",
    );
  });

  it('el rol de la aplicación no puede borrar usuarios (DELETE FROM users)', async () => {
    await expect(pool.query('DELETE FROM users')).rejects.toMatchObject({ code: '42501' });
    const { rows } = await pool.query<{ n: number }>('SELECT count(*) AS n FROM users');
    expect(primera(rows).n).toBe(1);
  });

  it('el rol de la aplicación no puede modificar la columna role', async () => {
    await expect(pool.query("UPDATE users SET role = 'admin'")).rejects.toMatchObject({ code: '42501' });
    const { rows } = await pool.query<{ role: string }>(
      "SELECT role FROM users WHERE email = 'ana@ejemplo.test'",
    );
    expect(primera(rows).role).toBe('user');
  });

  it('el rol de la aplicación puede actualizar failed_attempts', async () => {
    const res = await pool.query(
      "UPDATE users SET failed_attempts = 3 WHERE email = 'ana@ejemplo.test'",
    );
    expect(res.rowCount).toBe(1);
    const { rows } = await pool.query<{ failed_attempts: number }>(
      "SELECT failed_attempts FROM users WHERE email = 'ana@ejemplo.test'",
    );
    expect(primera(rows).failed_attempts).toBe(3);
  });
});
