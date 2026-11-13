import { createHash, randomBytes, randomUUID } from 'node:crypto';
import type { CookieOptions, Response } from 'express';
import type pg from 'pg';
import { config } from '../config.js';
import { pool } from '../db.js';
import { withAudit, type AuditTx } from '../audit/audit.js';
import { cleanText, normalizeIp } from '../audit/sanitize.js';

export interface Queryable {
  query<R extends pg.QueryResultRow = pg.QueryResultRow>(
    text: string,
    values?: unknown[],
  ): Promise<{ rows: R[] }>;
}

export const SESSION_COOKIE_NAME = 'sid';

export type UserRole = 'user' | 'admin';

export type SessionEndReason = 'logout' | 'idle_timeout' | 'absolute_timeout' | 'password_change';

export interface AuthSession {
  sessionId: string;
  userId: string;
  email: string;
  role: UserRole;
}

export type SessionValidationResult =
  | { status: 'active'; auth: AuthSession }
  | {
      status: 'expired';
      reason: 'idle_timeout' | 'absolute_timeout';
      sessionId: string;
      userId: string;
    }
  | { status: 'invalid' };

function baseCookieOptions(): CookieOptions {
  return {
    httpOnly: true,
    sameSite: 'strict',
    path: '/',
    secure: config.env === 'production',
  };
}

export function setSessionCookie(res: Response, token: string): void {
  res.cookie(SESSION_COOKIE_NAME, token, {
    ...baseCookieOptions(),
    maxAge: config.session.absoluteHours * 3600 * 1000,
  });
}

export function clearSessionCookie(res: Response): void {
  res.clearCookie(SESSION_COOKIE_NAME, baseCookieOptions());
}

export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

export function generateSessionCredentials(): {
  sessionId: string;
  token: string;
  tokenHash: string;
} {
  const sessionId = randomUUID();
  const token = randomBytes(32).toString('base64url');
  const tokenHash = hashToken(token);
  return { sessionId, token, tokenHash };
}

export async function insertSession(
  params: {
    sessionId: string;
    tokenHash: string;
    userId: string;
    sourceIp?: string;
    userAgent?: string;
  },
  db: Queryable = pool,
): Promise<void> {
  await db.query(
    `INSERT INTO sessions (id, token_hash, user_id, expires_at, source_ip, user_agent)
     VALUES ($1, $2, $3, now() + ($4::int * interval '1 hour'), $5, $6)`,
    [
      params.sessionId,
      params.tokenHash,
      params.userId,
      config.session.absoluteHours,
      normalizeIp(params.sourceIp),
      cleanText(params.userAgent, 256),
    ],
  );
}

export async function deleteSessionById(sessionId: string, db: Queryable = pool): Promise<void> {
  await db.query('DELETE FROM sessions WHERE id = $1', [sessionId]);
}

interface SessionLookupRow {
  session_id: string;
  user_id: string;
  revoked_at: Date | null;
  is_absolute_expired: boolean;
  is_idle_expired: boolean;
  email: string;
  role: UserRole;
}

export async function validateAndTouchSession(
  token: string,
  db: Queryable = pool,
): Promise<SessionValidationResult> {
  if (typeof token !== 'string' || token === '') {
    return { status: 'invalid' };
  }

  const tokenHash = hashToken(token);
  const { rows } = await db.query<SessionLookupRow>(
    `SELECT
       s.id AS session_id,
       s.user_id,
       s.revoked_at,
       (now() >= s.expires_at) AS is_absolute_expired,
       (now() > s.last_seen_at + ($2::int * interval '1 minute')) AS is_idle_expired,
       u.email,
       u.role
     FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = $1`,
    [tokenHash, config.session.idleMinutes],
  );

  const row = rows[0];
  if (!row || row.revoked_at !== null) {
    return { status: 'invalid' };
  }

  if (row.is_absolute_expired || row.is_idle_expired) {
    const reason = row.is_absolute_expired ? 'absolute_timeout' : 'idle_timeout';
    return {
      status: 'expired',
      reason,
      sessionId: row.session_id,
      userId: row.user_id,
    };
  }

  const touched = await db.query<{ id: string }>(
    `UPDATE sessions
     SET last_seen_at = now()
     WHERE id = $1 AND revoked_at IS NULL
     RETURNING id`,
    [row.session_id],
  );
  if (!touched.rows[0]) {
    return { status: 'invalid' };
  }

  return {
    status: 'active',
    auth: {
      sessionId: row.session_id,
      userId: row.user_id,
      email: row.email,
      role: row.role,
    },
  };
}

export async function closeSession(
  sessionId: string,
  reason: SessionEndReason,
  db: Queryable = pool,
): Promise<boolean> {
  const { rows } = await db.query<{ id: string }>(
    `UPDATE sessions
     SET revoked_at = now(), end_reason = $2
     WHERE id = $1 AND revoked_at IS NULL
     RETURNING id`,
    [sessionId, reason],
  );
  return rows.length > 0;
}

export async function revokeOtherUserSessions(
  userId: string,
  currentSessionId: string,
  reason: SessionEndReason = 'password_change',
  db: Queryable = pool,
): Promise<string[]> {
  const { rows } = await db.query<{ id: string }>(
    `WITH activas AS (
       SELECT id
       FROM sessions
       WHERE user_id = $1 AND id <> $2 AND revoked_at IS NULL
       ORDER BY created_at ASC, id ASC
       FOR UPDATE
     )
     UPDATE sessions s
     SET revoked_at = now(), end_reason = $3
     FROM activas a
     WHERE s.id = a.id
     RETURNING s.id`,
    [userId, currentSessionId, reason],
  );
  return rows.map((r) => r.id);
}

interface ExpiredSessionRow {
  id: string;
  user_id: string;
  end_reason: 'idle_timeout' | 'absolute_timeout';
}

async function expireStaleSessionsInTx(userId: string | undefined, tx: AuditTx): Promise<string[]> {
  const { rows } = await tx.client.query<ExpiredSessionRow>(
    `WITH vencidas AS (
       SELECT
         id,
         CASE
           WHEN now() >= expires_at THEN 'absolute_timeout'
           ELSE 'idle_timeout'
         END AS reason
       FROM sessions
       WHERE revoked_at IS NULL
         AND (now() >= expires_at OR now() > last_seen_at + ($1::int * interval '1 minute'))
         AND ($2::uuid IS NULL OR user_id = $2::uuid)
       ORDER BY created_at ASC, id ASC
       FOR UPDATE
     )
     UPDATE sessions s
     SET revoked_at = now(), end_reason = v.reason
     FROM vencidas v
     WHERE s.id = v.id
     RETURNING s.id, s.user_id, s.end_reason`,
    [config.session.idleMinutes, userId ?? null],
  );

  for (const row of rows) {
    tx.record({
      type: 'session.expired',
      reason: row.end_reason,
      userId: row.user_id,
      sessionId: row.id,
    });
  }

  return rows.map((r) => r.id);
}

export async function expireStaleSessions(userId?: string, tx?: AuditTx): Promise<string[]> {
  if (tx !== undefined) {
    return expireStaleSessionsInTx(userId, tx);
  }
  return withAudit({}, (newTx) => expireStaleSessionsInTx(userId, newTx));
}
