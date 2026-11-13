import type pg from 'pg';
import { config } from '../config.js';
import { pool } from '../db.js';
import { normalizeIp } from '../audit/sanitize.js';

export interface Queryable {
  query<R extends pg.QueryResultRow = pg.QueryResultRow>(
    text: string,
    values?: unknown[],
  ): Promise<{ rows: R[] }>;
}

export interface IpRateLimitStatus {
  exceeded: boolean;
  alreadyTriggered: boolean;
}

interface IpRateLimitRow {
  failure_count: number;
  already_triggered: boolean;
}

export async function checkIpRateLimit(
  rawIp: string | undefined,
  db: Queryable = pool,
): Promise<IpRateLimitStatus> {
  const ip = normalizeIp(rawIp);
  if (ip === null) {
    return { exceeded: false, alreadyTriggered: false };
  }

  const { rows } = await db.query<IpRateLimitRow>(
    `SELECT
       COUNT(*) FILTER (
         WHERE event_type = 'auth.login.failure'
           AND reason IS DISTINCT FROM 'rate_limited'
       ) AS failure_count,
       EXISTS (
         SELECT 1
         FROM auth_events
         WHERE source_ip = $1::inet
           AND event_type = 'auth.ratelimit.triggered'
           AND occurred_at >= now() - ($2::int * interval '1 minute')
       ) AS already_triggered
     FROM auth_events
     WHERE source_ip = $1::inet
       AND occurred_at >= now() - ($2::int * interval '1 minute')`,
    [ip, config.ipRateLimit.windowMinutes],
  );

  const row = rows[0];
  const failureCount = Number(row?.failure_count ?? 0);
  return {
    exceeded: failureCount >= config.ipRateLimit.max,
    alreadyTriggered: Boolean(row?.already_triggered),
  };
}

export async function checkPasswordChangeRateLimit(
  userId: string,
  db: Queryable = pool,
): Promise<boolean> {
  const { rows } = await db.query<{ failure_count: number }>(
    `SELECT COUNT(*) AS failure_count
     FROM auth_events
     WHERE user_id = $1
       AND event_type = 'auth.password.change.failure'
       AND reason = 'bad_current_password'
       AND occurred_at >= now() - ($2::int * interval '1 minute')`,
    [userId, config.lockout.minutes],
  );
  const failureCount = Number(rows[0]?.failure_count ?? 0);
  return failureCount >= config.lockout.threshold;
}

export async function clearExpiredLock(
  userId: string,
  db: Queryable = pool,
): Promise<boolean> {
  const { rows } = await db.query<{ id: string }>(
    `UPDATE users
     SET failed_attempts = 0, locked_until = NULL
     WHERE id = $1 AND locked_until IS NOT NULL AND locked_until <= now()
     RETURNING id`,
    [userId],
  );
  return rows.length > 0;
}

export interface FailedAttemptResult {
  attempts: number;
  lockedUntil: Date | null;
  justLocked: boolean;
}

export async function recordFailedLoginAttempt(
  userId: string,
  db: Queryable = pool,
): Promise<FailedAttemptResult> {
  // Incremento y bloqueo en una sola sentencia UPDATE atómica; locked_until solo se fija
  // al alcanzar exactamente el umbral para que peticiones concurrentes no dupliquen auth.account.locked.
  const { rows } = await db.query<{ failed_attempts: number; locked_until: Date | null }>(
    `UPDATE users
     SET
       failed_attempts = failed_attempts + 1,
       locked_until = CASE
         WHEN failed_attempts + 1 = $2 THEN now() + ($3::int * interval '1 minute')
         ELSE locked_until
       END
     WHERE id = $1
     RETURNING failed_attempts, locked_until`,
    [userId, config.lockout.threshold, config.lockout.minutes],
  );

  const row = rows[0];
  if (!row) {
    throw new Error('Usuario no encontrado al registrar intento fallido');
  }

  const attempts = Number(row.failed_attempts);
  const justLocked = attempts === config.lockout.threshold && row.locked_until !== null;
  return {
    attempts,
    lockedUntil: row.locked_until,
    justLocked,
  };
}

export async function resetFailedAttempts(
  userId: string,
  db: Queryable = pool,
): Promise<void> {
  await db.query(
    `UPDATE users
     SET failed_attempts = 0, locked_until = NULL
     WHERE id = $1 AND (failed_attempts <> 0 OR locked_until IS NOT NULL)`,
    [userId],
  );
}
