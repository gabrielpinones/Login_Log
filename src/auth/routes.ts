import { Router, type Response } from 'express';
import { z } from 'zod';
import { pool } from '../db.js';
import { recordEvent, withAudit } from '../audit/audit.js';
import { auditContextFrom } from '../audit/context.js';
import { requireSession } from '../middleware/requireSession.js';
import {
  checkPasswordPolicy,
  hashPassword,
  verifyDummyPassword,
  verifyPassword,
} from './passwords.js';
import {
  clearSessionCookie,
  closeSession,
  expireStaleSessions,
  generateSessionCredentials,
  insertSession,
  revokeOtherUserSessions,
  setSessionCookie,
  type UserRole,
} from './sessions.js';
import {
  checkIpRateLimit,
  checkPasswordChangeRateLimit,
  clearExpiredLock,
  recordFailedLoginAttempt,
  resetFailedAttempts,
} from './lockout.js';

const emailSchema = z.email().max(254);

// Serializa por correo normalizado sin retener conexiones de base durante argon2, y limpia la entrada al vaciarse.
const loginQueues = new Map<string, Promise<unknown>>();

function withEmailLock<T>(email: string, fn: () => Promise<T>): Promise<T> {
  const previous = loginQueues.get(email) ?? Promise.resolve();
  const current = previous.then(fn);
  const tracked = current
    .then(
      () => undefined,
      () => undefined,
    )
    .finally(() => {
      if (loginQueues.get(email) === tracked) {
        loginQueues.delete(email);
      }
    });
  loginQueues.set(email, tracked);
  return current;
}

function normalizeAndValidateEmail(raw: string): string | null {
  const normalized = raw.trim().toLowerCase();
  if (normalized.length === 0 || normalized.length > 254) {
    return null;
  }
  const parsed = emailSchema.safeParse(normalized);
  return parsed.success ? parsed.data : null;
}

function pgErrorCode(err: unknown): string | undefined {
  if (typeof err === 'object' && err !== null && 'code' in err && typeof err.code === 'string') {
    return err.code;
  }
  return undefined;
}

// Los pasos 3, 4 y 6 de POST /login deben producir exactamente el mismo estado y cuerpo HTML
// para impedir la enumeración de cuentas o la detección del estado de bloqueo.
function renderInvalidCredentials(res: Response): void {
  res.status(401).render('login', {
    error: 'Credenciales inválidas',
    registrado: false,
  });
}

interface LoginUserRow {
  id: string;
  email: string;
  password_hash: string;
  role: UserRole;
  failed_attempts: number;
  locked_until: Date | null;
  is_locked: boolean;
  is_lock_expired: boolean;
}

export function authRouter(): Router {
  const router = Router();

  router.get('/', (req, res) => {
    res.redirect(302, req.auth ? '/cuenta' : '/login');
  });

  router.get('/registro', (_req, res) => {
    res.status(200).render('registro', {
      error: null,
    });
  });

  router.post('/registro', async (req, res) => {
    const ctx = auditContextFrom(req);
    const rawEmail: string | undefined =
      typeof req.body?.email === 'string' ? req.body.email : undefined;
    const rawPassword: string | undefined =
      typeof req.body?.password === 'string' ? req.body.password : undefined;

    const email = rawEmail !== undefined ? normalizeAndValidateEmail(rawEmail) : null;
    if (email === null || rawPassword === undefined || rawPassword.length === 0) {
      await recordEvent(
        {
          type: 'auth.register.failure',
          reason: 'invalid_input',
          identifier: rawEmail,
          httpStatus: 400,
        },
        ctx,
      );
      res.status(400).render('registro', {
        error: 'Introduce un correo electrónico válido y una contraseña.',
      });
      return;
    }

    const policy = checkPasswordPolicy(rawPassword, email);
    if (!policy.ok) {
      await recordEvent(
        {
          type: 'auth.register.failure',
          reason: 'weak_password',
          identifier: rawEmail,
          httpStatus: 400,
        },
        ctx,
      );
      res.status(400).render('registro', {
        error: policy.message,
      });
      return;
    }

    const existing = await pool.query<{ id: string }>('SELECT id FROM users WHERE email = $1', [
      email,
    ]);
    if (existing.rows[0]) {
      await verifyDummyPassword(rawPassword);
      await recordEvent(
        {
          type: 'auth.register.failure',
          reason: 'email_taken',
          userId: existing.rows[0].id,
          identifier: rawEmail,
          httpStatus: 409,
        },
        ctx,
      );
      res.status(409).render('registro', {
        error: 'No se pudo completar el registro con ese correo.',
      });
      return;
    }

    const passwordHash = await hashPassword(rawPassword);
    try {
      await withAudit(ctx, async (tx) => {
        const inserted = await tx.client.query<{ id: string }>(
          'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id',
          [email, passwordHash],
        );
        const row = inserted.rows[0];
        if (!row) {
          throw new Error('INSERT INTO users no devolvió fila');
        }
        tx.record({
          type: 'auth.register.success',
          userId: row.id,
          identifier: rawEmail,
          httpStatus: 303,
        });
      });
    } catch (err) {
      if (pgErrorCode(err) === '23505') {
        const concurrent = await pool.query<{ id: string }>(
          'SELECT id FROM users WHERE email = $1',
          [email],
        );
        await recordEvent(
          {
            type: 'auth.register.failure',
            reason: 'email_taken',
            userId: concurrent.rows[0]?.id ?? null,
            identifier: rawEmail,
            httpStatus: 409,
          },
          ctx,
        );
        res.status(409).render('registro', {
          error: 'No se pudo completar el registro con ese correo.',
        });
        return;
      }
      throw err;
    }

    res.redirect(303, '/login?registrado=1');
  });

  router.get('/login', (req, res) => {
    if (req.auth) {
      res.redirect(302, '/cuenta');
      return;
    }
    res.status(200).render('login', {
      error: null,
      registrado: req.query.registrado === '1',
    });
  });

  router.post('/login', async (req, res) => {
    const ctx = auditContextFrom(req);
    const rawEmail: string | undefined =
      typeof req.body?.email === 'string' ? req.body.email : undefined;
    const rawPassword: string | undefined =
      typeof req.body?.password === 'string' ? req.body.password : undefined;

    // 1. Límite por IP
    const rateLimit = await checkIpRateLimit(req.ip);
    if (rateLimit.exceeded) {
      if (!rateLimit.alreadyTriggered) {
        await recordEvent(
          {
            type: 'auth.ratelimit.triggered',
            httpStatus: 429,
          },
          ctx,
        );
      }
      await recordEvent(
        {
          type: 'auth.login.failure',
          reason: 'rate_limited',
          identifier: rawEmail,
          httpStatus: 429,
        },
        ctx,
      );
      res.status(429).render('login', {
        error: 'Demasiados intentos de inicio de sesión. Inténtalo de nuevo más tarde.',
        registrado: false,
      });
      return;
    }

    // 2. Entrada inválida
    const email = rawEmail !== undefined ? normalizeAndValidateEmail(rawEmail) : null;
    if (
      email === null ||
      rawPassword === undefined ||
      rawPassword.length === 0 ||
      rawPassword.length > 1024
    ) {
      await recordEvent(
        {
          type: 'auth.login.failure',
          reason: 'invalid_input',
          identifier: rawEmail,
          httpStatus: 400,
        },
        ctx,
      );
      res.status(400).render('login', {
        error: 'Introduce un correo válido y una contraseña.',
        registrado: false,
      });
      return;
    }

    await withEmailLock(email, async () => {
      const { rows } = await pool.query<LoginUserRow>(
        `SELECT
           id,
           email,
           password_hash,
           role,
           failed_attempts,
           locked_until,
           (locked_until IS NOT NULL AND locked_until > now()) AS is_locked,
           (locked_until IS NOT NULL AND locked_until <= now()) AS is_lock_expired
         FROM users
         WHERE email = $1`,
        [email],
      );
      const user = rows[0];

      // 3. Usuario inexistente
      if (!user) {
        await verifyDummyPassword(rawPassword);
        await recordEvent(
          {
            type: 'auth.login.failure',
            reason: 'unknown_user',
            identifier: rawEmail,
            httpStatus: 401,
          },
          ctx,
        );
        renderInvalidCredentials(res);
        return;
      }

      // 4. Cuenta bloqueada (locked_until > now)
      if (user.is_locked) {
        await verifyDummyPassword(rawPassword);
        await recordEvent(
          {
            type: 'auth.login.failure',
            reason: 'account_locked',
            userId: user.id,
            identifier: rawEmail,
            httpStatus: 401,
          },
          ctx,
        );
        renderInvalidCredentials(res);
        return;
      }

      const passwordValid = await verifyPassword(user.password_hash, rawPassword);
      const responseStatus = passwordValid ? 303 : 401;

      const loginOutcome = await withAudit(ctx, async (tx) => {
        // Se relee la fila con FOR UPDATE tras argon2 para garantizar que ningún bloqueo concurrente quede ignorado.
        const lockedRes = await tx.client.query<LoginUserRow>(
          `SELECT
             id,
             email,
             password_hash,
             role,
             failed_attempts,
             locked_until,
             (locked_until IS NOT NULL AND locked_until > now()) AS is_locked,
             (locked_until IS NOT NULL AND locked_until <= now()) AS is_lock_expired
           FROM users
           WHERE id = $1
           FOR UPDATE`,
          [user.id],
        );
        const currentUser = lockedRes.rows[0];
        if (!currentUser) {
          throw new Error('Usuario no encontrado durante la transacción de inicio de sesión');
        }

        if (currentUser.is_locked) {
          tx.record({
            type: 'auth.login.failure',
            reason: 'account_locked',
            userId: currentUser.id,
            identifier: rawEmail,
            httpStatus: 401,
          });
          return { ok: false as const };
        }

        // 5. Bloqueo vencido (locked_until <= now)
        if (currentUser.is_lock_expired) {
          const lockCleared = await clearExpiredLock(currentUser.id, tx.client);
          if (lockCleared) {
            tx.record({
              type: 'auth.account.unlocked',
              userId: currentUser.id,
              httpStatus: responseStatus,
              details: { cause: 'lock_expired' },
            });
          }
        }

        // 6. Contraseña incorrecta
        if (!passwordValid) {
          const attemptInfo = await recordFailedLoginAttempt(currentUser.id, tx.client);
          tx.record({
            type: 'auth.login.failure',
            reason: 'bad_password',
            userId: currentUser.id,
            identifier: rawEmail,
            httpStatus: 401,
            details: { attempt: attemptInfo.attempts },
          });
          if (attemptInfo.justLocked && attemptInfo.lockedUntil !== null) {
            tx.record({
              type: 'auth.account.locked',
              userId: currentUser.id,
              httpStatus: 401,
              details: {
                failed_attempts: attemptInfo.attempts,
                locked_until: attemptInfo.lockedUntil.toISOString(),
              },
            });
          }
          return { ok: false as const };
        }

        // 7. Contraseña correcta
        await resetFailedAttempts(currentUser.id, tx.client);
        const { sessionId, token, tokenHash } = generateSessionCredentials();

        tx.record({
          type: 'auth.login.success',
          userId: currentUser.id,
          sessionId,
          identifier: rawEmail,
          httpStatus: 303,
        });

        await insertSession(
          {
            sessionId,
            tokenHash,
            userId: currentUser.id,
            sourceIp: req.ip,
            userAgent: req.get('user-agent'),
          },
          tx.client,
        );

        tx.record({
          type: 'session.created',
          userId: currentUser.id,
          sessionId,
          httpStatus: 303,
        });

        if (req.auth) {
          const closedPrev = await closeSession(req.auth.sessionId, 'logout', tx.client);
          if (closedPrev) {
            tx.record({
              type: 'auth.logout',
              userId: req.auth.userId,
              sessionId: req.auth.sessionId,
              httpStatus: 303,
              details: { cause: 'relogin' },
            });
          }
        }

        return { ok: true as const, token };
      });

      if (!loginOutcome.ok) {
        renderInvalidCredentials(res);
        return;
      }

      setSessionCookie(res, loginOutcome.token);
      res.redirect(303, '/cuenta');
    });
  });

  router.post('/logout', requireSession, async (req, res) => {
    const auth = req.auth!;
    await withAudit(auditContextFrom(req), async (tx) => {
      await closeSession(auth.sessionId, 'logout', tx.client);
      tx.record({
        type: 'auth.logout',
        userId: auth.userId,
        sessionId: auth.sessionId,
        httpStatus: 303,
      });
    });
    clearSessionCookie(res);
    res.redirect(303, '/login');
  });

  router.get('/cuenta', requireSession, (req, res) => {
    const auth = req.auth!;
    res.status(200).render('cuenta', {
      email: auth.email,
      error: null,
      cambiada: req.query.cambiada === '1',
    });
  });

  router.post('/cuenta/password', requireSession, async (req, res) => {
    const auth = req.auth!;
    const ctx = auditContextFrom(req);
    const currentPassword: string | undefined =
      typeof req.body?.currentPassword === 'string' ? req.body.currentPassword : undefined;
    const newPassword: string | undefined =
      typeof req.body?.newPassword === 'string' ? req.body.newPassword : undefined;

    if (await checkPasswordChangeRateLimit(auth.userId)) {
      await recordEvent(
        {
          type: 'auth.password.change.failure',
          reason: 'rate_limited',
          userId: auth.userId,
          sessionId: auth.sessionId,
          httpStatus: 429,
        },
        ctx,
      );
      res.status(429).render('cuenta', {
        email: auth.email,
        error: 'Demasiados intentos de cambio de contraseña. Inténtalo de nuevo más tarde.',
        cambiada: false,
      });
      return;
    }

    if (
      currentPassword === undefined ||
      currentPassword.length === 0 ||
      currentPassword.length > 1024 ||
      newPassword === undefined ||
      newPassword.length === 0
    ) {
      await recordEvent(
        {
          type: 'auth.password.change.failure',
          reason: 'invalid_input',
          userId: auth.userId,
          sessionId: auth.sessionId,
          httpStatus: 400,
        },
        ctx,
      );
      res.status(400).render('cuenta', {
        email: auth.email,
        error: 'Debes indicar la contraseña actual y la nueva contraseña.',
        cambiada: false,
      });
      return;
    }

    const { rows } = await pool.query<{ password_hash: string; email: string }>(
      'SELECT password_hash, email FROM users WHERE id = $1',
      [auth.userId],
    );
    const userRow = rows[0];
    if (!userRow) {
      res.redirect(303, '/login');
      return;
    }

    const currentValid = await verifyPassword(userRow.password_hash, currentPassword);
    if (!currentValid) {
      await recordEvent(
        {
          type: 'auth.password.change.failure',
          reason: 'bad_current_password',
          userId: auth.userId,
          sessionId: auth.sessionId,
          httpStatus: 400,
        },
        ctx,
      );
      res.status(400).render('cuenta', {
        email: auth.email,
        error: 'La contraseña actual no es correcta.',
        cambiada: false,
      });
      return;
    }

    const policy = checkPasswordPolicy(newPassword, userRow.email);
    if (!policy.ok) {
      await recordEvent(
        {
          type: 'auth.password.change.failure',
          reason: 'weak_password',
          userId: auth.userId,
          sessionId: auth.sessionId,
          httpStatus: 400,
        },
        ctx,
      );
      res.status(400).render('cuenta', {
        email: auth.email,
        error: policy.message,
        cambiada: false,
      });
      return;
    }

    const newHash = await hashPassword(newPassword);
    await withAudit(ctx, async (tx) => {
      await tx.client.query(
        'UPDATE users SET password_hash = $1, password_changed_at = now() WHERE id = $2',
        [newHash, auth.userId],
      );

      tx.record({
        type: 'auth.password.change.success',
        userId: auth.userId,
        sessionId: auth.sessionId,
        httpStatus: 303,
      });

      await expireStaleSessions(auth.userId, tx);

      const revokedSessionIds = await revokeOtherUserSessions(
        auth.userId,
        auth.sessionId,
        'password_change',
        tx.client,
      );
      for (const revokedId of revokedSessionIds) {
        tx.record({
          type: 'session.revoked',
          reason: 'password_change',
          userId: auth.userId,
          sessionId: revokedId,
          httpStatus: 303,
        });
      }
    });

    res.redirect(303, '/cuenta?cambiada=1');
  });

  return router;
}
