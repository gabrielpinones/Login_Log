import type { NextFunction, Request, Response } from 'express';
import { recordEvent } from '../audit/audit.js';
import { auditContextFrom } from '../audit/context.js';
import './loadSession.js';

export async function requireSession(req: Request, res: Response, next: NextFunction): Promise<void> {
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

  next();
}
