import { randomUUID } from 'node:crypto';
import type pg from 'pg';
import { pool } from '../db.js';
import { config } from '../config.js';
import { appLogger, auditLogger } from '../logging/logger.js';
import { EVENT_CATALOG, type AuditDetails, type AuditEventInput, type EventType } from './events.js';
import type { AuditContext } from './context.js';
import { cleanText, identifierHash, normalizeIp } from './sanitize.js';

export class AuditWriteError extends Error {
  constructor(message = 'No se pudo persistir el evento de auditoría', options?: ErrorOptions) {
    super(message, options);
    this.name = 'AuditWriteError';
  }
}

export interface RecordedEvent {
  eventId: string;
  seq: number;
  prevHash: string;
  hash: string;
  occurredAt: Date;
}

/** Registro con la forma de la fila de auth_events (sin las columnas que asigna el trigger). */
export interface AuditRecord {
  event_id: string;
  occurred_at: Date;
  event_type: EventType;
  outcome: 'success' | 'failure';
  reason: string | null;
  severity: 'info' | 'warn' | 'error';
  category: string;
  user_id: string | null;
  identifier_hash: string | null;
  session_id: string | null;
  source_ip: string | null;
  user_agent: string | null;
  http_method: string | null;
  route: string | null;
  http_status: number | null;
  request_id: string | null;
  service: string;
  version: string;
  environment: string;
  hostname: string;
  details: AuditDetails;
}

interface Chain {
  seq: number;
  prevHash: string;
  hash: string;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ECS_VERSION = '8.11.0';
const SECRET_DETAIL_KEYS = new Set([
  'password',
  'currentPassword',
  'newPassword',
  'token',
  'cookie',
  'authorization',
]);

function redactDetails(details: AuditDetails | undefined): AuditDetails {
  if (!details) return {};
  const sanitized: AuditDetails = {};
  for (const [key, value] of Object.entries(details)) {
    if (value === undefined) continue;
    sanitized[key] = SECRET_DETAIL_KEYS.has(key) ? '[REDACTED]' : value;
  }
  return sanitized;
}

function buildRecord(input: AuditEventInput, ctx: AuditContext): AuditRecord {
  const entry = EVENT_CATALOG[input.type];
  return {
    event_id: randomUUID(),
    occurred_at: new Date(),
    event_type: input.type,
    outcome: entry.outcome,
    reason: input.reason ?? null,
    severity: entry.severity,
    category: entry.category,
    user_id: input.userId ?? null,
    identifier_hash: input.identifier === undefined ? null : identifierHash(input.identifier),
    session_id: input.sessionId ?? null,
    source_ip: normalizeIp(ctx.sourceIp),
    user_agent: cleanText(ctx.userAgent, 256),
    http_method: cleanText(ctx.method, 16),
    route: cleanText(ctx.route, 256),
    http_status: input.httpStatus ?? null,
    request_id: ctx.requestId !== undefined && UUID_RE.test(ctx.requestId) ? ctx.requestId : null,
    service: config.serviceName,
    version: config.version,
    environment: config.env,
    hostname: config.hostname,
    details: redactDetails(input.details),
  };
}

function compact<T extends Record<string, unknown>>(obj: T): Partial<T> | undefined {
  const entries = Object.entries(obj).filter(([, v]) => v !== undefined && v !== null);
  return entries.length === 0 ? undefined : (Object.fromEntries(entries) as Partial<T>);
}

/** Documento ECS 8.x; lo propio de la aplicación va bajo `login_log`. Omite las claves sin valor. */
export function toEcs(record: AuditRecord, chain?: Chain): Record<string, unknown> {
  const doc = {
    '@timestamp': record.occurred_at.toISOString(),
    ecs: { version: ECS_VERSION },
    message: record.event_type,
    event: compact({
      id: record.event_id,
      kind: 'event',
      category: [record.category],
      action: record.event_type,
      outcome: record.outcome,
      reason: record.reason,
      sequence: chain?.seq,
      hash: chain?.hash,
    }),
    user: compact({ id: record.user_id }),
    source: compact({ ip: record.source_ip }),
    user_agent: compact({ original: record.user_agent }),
    http: compact({
      request: compact({ method: record.http_method, id: record.request_id }),
      response: compact({ status_code: record.http_status }),
    }),
    url: compact({ path: record.route }),
    service: {
      name: record.service,
      version: record.version,
      environment: record.environment,
    },
    host: { hostname: record.hostname },
    login_log: compact({
      prev_hash: chain?.prevHash,
      identifier_hash: record.identifier_hash,
      session_id: record.session_id,
      details: Object.keys(record.details).length > 0 ? record.details : undefined,
    }),
  };
  return Object.fromEntries(Object.entries(doc).filter(([, v]) => v !== undefined));
}

const INSERT_SQL = `INSERT INTO auth_events (event_id, occurred_at, event_type, outcome, reason, severity, user_id, identifier_hash, session_id, source_ip, user_agent, http_method, route, http_status, request_id, service, version, environment, hostname, details)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
RETURNING seq, prev_hash, hash`;

function errorCode(err: unknown): string | undefined {
  const code = (err as { code?: unknown } | null)?.code;
  return typeof code === 'string' ? code : undefined;
}

function reportFailure(record: AuditRecord, err: unknown): void {
  const doc = toEcs({
    ...record,
    event_type: 'audit.write.failed',
    outcome: 'failure',
    severity: 'error',
    category: EVENT_CATALOG['audit.write.failed'].category,
    reason: null,
    details: {},
  });
  // El evento perdido va completo en el archivo para poder reconstruirlo; error.* queda sin mensaje del driver.
  const lost = { ...record, occurred_at: record.occurred_at.toISOString() };
  const line = {
    ...doc,
    error: compact({ code: errorCode(err), type: err instanceof Error ? err.name : undefined }),
    login_log: { lost_event: lost },
  };
  try {
    auditLogger.error(line);
  } catch (writeErr) {
    appLogger.error({ errCode: errorCode(writeErr) }, 'audit.write.failed: tampoco se pudo escribir en el archivo');
  }
  appLogger.error(
    { eventId: record.event_id, eventType: record.event_type, errCode: errorCode(err) },
    'audit.write.failed',
  );
}

interface Queryable {
  query<R extends pg.QueryResultRow = pg.QueryResultRow>(
    text: string,
    values?: unknown[],
  ): Promise<{ rows: R[] }>;
}

async function insertRecord(db: Queryable, record: AuditRecord): Promise<Chain> {
  const result = await db.query<{ seq: number; prev_hash: string; hash: string }>(INSERT_SQL, [
    record.event_id,
    record.occurred_at,
    record.event_type,
    record.outcome,
    record.reason,
    record.severity,
    record.user_id,
    record.identifier_hash,
    record.session_id,
    record.source_ip,
    record.user_agent,
    record.http_method,
    record.route,
    record.http_status,
    record.request_id,
    record.service,
    record.version,
    record.environment,
    record.hostname,
    JSON.stringify(record.details),
  ]);
  const first = result.rows[0];
  if (!first) throw new Error('INSERT sin fila de retorno');
  return { seq: first.seq, prevHash: first.prev_hash, hash: first.hash };
}

function writeAuditLine(record: AuditRecord, chain: Chain): void {
  try {
    auditLogger[record.severity](toEcs(record, chain));
  } catch (err) {
    // La fila ya está en la base: un fallo del archivo no debe anular el evento.
    appLogger.error({ eventId: record.event_id, errCode: errorCode(err) }, 'audit: fallo al escribir el archivo');
  }
}

export async function recordEvent(input: AuditEventInput, ctx: AuditContext = {}): Promise<RecordedEvent> {
  const record = buildRecord(input, ctx);

  let chain: Chain;
  try {
    // pool.query toma su propia conexión en autocommit: el evento persiste aunque la operación del llamador haga rollback.
    chain = await insertRecord(pool, record);
  } catch (err) {
    reportFailure(record, err);
    throw new AuditWriteError(undefined, { cause: err });
  }

  writeAuditLine(record, chain);

  return {
    eventId: record.event_id,
    seq: chain.seq,
    prevHash: chain.prevHash,
    hash: chain.hash,
    occurredAt: record.occurred_at,
  };
}

export interface AuditTx {
  client: pg.PoolClient;
  record(input: AuditEventInput, ctxOverride?: AuditContext): void;
}

export async function withAudit<T>(
  ctx: AuditContext,
  fn: (tx: AuditTx) => Promise<T>,
  db: pg.Pool = pool,
): Promise<T> {
  const queued: AuditRecord[] = [];
  const record = (input: AuditEventInput, ctxOverride?: AuditContext): void => {
    queued.push(buildRecord(input, ctxOverride ? { ...ctx, ...ctxOverride } : ctx));
  };

  const client = await db.connect();
  let discardClient = false;
  let result: T;
  const inserted: { record: AuditRecord; chain: Chain }[] = [];

  try {
    await client.query('BEGIN');
    result = await fn({ client, record });

    try {
      // Los eventos se insertan justo antes del COMMIT para minimizar el tiempo de retención del bloqueo consultivo de la cadena.
      for (const rec of queued) {
        const chain = await insertRecord(client, rec);
        inserted.push({ record: rec, chain });
      }
      await client.query('COMMIT');
    } catch (auditErr) {
      try {
        await client.query('ROLLBACK');
      } catch {
        // Si ROLLBACK falla, la conexión queda en estado desconocido y debe descartarse del pool.
        discardClient = true;
      }
      for (const rec of queued) {
        reportFailure(rec, auditErr);
      }
      throw new AuditWriteError(undefined, { cause: auditErr });
    }
  } catch (err) {
    if (!(err instanceof AuditWriteError)) {
      try {
        await client.query('ROLLBACK');
      } catch {
        // Si ROLLBACK falla, se descarta la conexión sin ocultar el error original.
        discardClient = true;
      }
    }
    throw err;
  } finally {
    client.release(discardClient);
  }

  for (const item of inserted) {
    writeAuditLine(item.record, item.chain);
  }

  return result;
}
