import { existsSync, readFileSync, truncateSync } from 'node:fs';
import path from 'node:path';
import pg from 'pg';
import { config } from '../src/config.js';
import { closePool } from '../src/db.js';

if (config.env !== 'test' || config.migrationDatabaseUrl === undefined) {
  throw new Error('tests/helpers.ts solo puede usarse con NODE_ENV=test y TEST_MIGRATION_DATABASE_URL');
}

export const adminPool = new pg.Pool({ connectionString: config.migrationDatabaseUrl });

export async function resetDb(): Promise<void> {
  const cliente = await adminPool.connect();
  try {
    await cliente.query('BEGIN');
    // El modo replica desactiva los triggers normales, incluido el que impide TRUNCATE en auth_events.
    await cliente.query('SET LOCAL session_replication_role = replica');
    await cliente.query('TRUNCATE users, sessions, auth_events CASCADE');
    await cliente.query('COMMIT');
  } catch (err) {
    await cliente.query('ROLLBACK');
    throw err;
  } finally {
    cliente.release();
  }
}

export const auditLogPath: string = path.join(config.logDir, 'auth-events.jsonl');

export function resetAuditLog(): void {
  // Truncar y no borrar: el logger mantiene abierto el descriptor y seguiría escribiendo en un archivo huérfano.
  if (existsSync(auditLogPath)) truncateSync(auditLogPath, 0);
}

export function readAuditLines(): Record<string, any>[] {
  if (!existsSync(auditLogPath)) return [];
  return readFileSync(auditLogPath, 'utf8')
    .split('\n')
    .filter((linea) => linea.trim() !== '')
    .map((linea) => JSON.parse(linea) as Record<string, any>);
}

let adminCerrado = false;

export async function closeAll(): Promise<void> {
  if (!adminCerrado) {
    adminCerrado = true;
    await adminPool.end();
  }
  await closePool();
}
