import type { NextFunction, Request, Response } from 'express';
import { recordEvent } from '../audit/audit.js';
import { auditContextFrom } from '../audit/context.js';
import './loadSession.js';

export async function requireAdmin(req: Request, res: Response, next: NextFunction): Promise<void> {
  if (!req.auth) {
    await recordEvent(
      {
        type: 'authz.denied',
        reason: 'no_session',
        httpStatus: 303,
      },
      auditContextFrom(req),
    );
    res.redirect(303, '/login');
    return;
  }

  if (req.auth.role !== 'admin') {
    await recordEvent(
      {
        type: 'authz.denied',
        reason: 'insufficient_role',
        userId: req.auth.userId,
        sessionId: req.auth.sessionId,
        httpStatus: 403,
      },
      auditContextFrom(req),
    );
    res.status(403).render('error', {
      title: 'Acceso restringido',
      message: 'No tienes permisos suficientes para acceder a este recurso.',
    });
    return;
  }

  next();
}
