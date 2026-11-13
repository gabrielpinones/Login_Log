import type { NextFunction, Request, Response } from 'express';
import { withAudit } from '../audit/audit.js';
import { auditContextFrom } from '../audit/context.js';
import {
  clearSessionCookie,
  closeSession,
  SESSION_COOKIE_NAME,
  validateAndTouchSession,
  type AuthSession,
} from '../auth/sessions.js';

declare module 'express-serve-static-core' {
  interface Request {
    auth?: AuthSession;
  }
}

export async function loadSession(req: Request, res: Response, next: NextFunction): Promise<void> {
  const rawToken: unknown = req.cookies?.[SESSION_COOKIE_NAME];
  if (typeof rawToken !== 'string' || rawToken === '') {
    next();
    return;
  }

  const result = await validateAndTouchSession(rawToken);

  if (result.status === 'active') {
    req.auth = result.auth;
    res.locals.auth = { email: result.auth.email, role: result.auth.role };
    next();
    return;
  }

  if (result.status === 'expired') {
    await withAudit(auditContextFrom(req), async (tx) => {
      // El cierre condicionado a revoked_at IS NULL evita emitir session.expired dos veces en peticiones concurrentes.
      const closed = await closeSession(result.sessionId, result.reason, tx.client);
      if (closed) {
        tx.record({
          type: 'session.expired',
          reason: result.reason,
          userId: result.userId,
          sessionId: result.sessionId,
        });
      }
    });
  }

  clearSessionCookie(res);
  next();
}
