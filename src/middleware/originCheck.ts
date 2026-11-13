import type { NextFunction, Request, Response } from 'express';
import { config } from '../config.js';
import { recordEvent } from '../audit/audit.js';
import { auditContextFrom } from '../audit/context.js';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
const EXPECTED_ORIGIN = new URL(config.appOrigin).origin;

function parseOrigin(urlOrOrigin: string): string | null {
  try {
    return new URL(urlOrOrigin).origin;
  } catch {
    return null;
  }
}

export async function originCheck(req: Request, res: Response, next: NextFunction): Promise<void> {
  if (SAFE_METHODS.has(req.method.toUpperCase())) {
    next();
    return;
  }

  const originHeader = req.get('origin')?.trim();
  const refererHeader = req.get('referer')?.trim();

  if (!originHeader && !refererHeader) {
    await recordEvent(
      {
        type: 'security.csrf.rejected',
        reason: 'origin_missing',
        userId: req.auth?.userId ?? null,
        sessionId: req.auth?.sessionId ?? null,
        httpStatus: 403,
      },
      auditContextFrom(req),
    );
    res.status(403).render('error', {
      title: 'Acceso denegado',
      message: 'Solicitud rechazada por falta de origen válido.',
    });
    return;
  }

  const candidateOrigin = originHeader ? parseOrigin(originHeader) : parseOrigin(refererHeader!);

  if (candidateOrigin !== EXPECTED_ORIGIN) {
    await recordEvent(
      {
        type: 'security.csrf.rejected',
        reason: 'origin_mismatch',
        userId: req.auth?.userId ?? null,
        sessionId: req.auth?.sessionId ?? null,
        httpStatus: 403,
      },
      auditContextFrom(req),
    );
    res.status(403).render('error', {
      title: 'Acceso denegado',
      message: 'El origen de la solicitud no coincide con el esperado.',
    });
    return;
  }

  next();
}
