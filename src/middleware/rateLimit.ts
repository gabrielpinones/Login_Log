import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { normalizeIp } from '../audit/sanitize.js';
import { appLogger } from '../logging/logger.js';

export interface RateLimitOptions {
  max: number;
  windowSeconds: number;
}

interface IpWindowState {
  count: number;
  warned: boolean;
}

export function createRateLimit(options: RateLimitOptions): RequestHandler {
  const windowMs = Math.max(1, options.windowSeconds) * 1000;
  let windowResetAt = 0;
  const entries = new Map<string, IpWindowState>();

  return (req: Request, res: Response, next: NextFunction): void => {
    if (req.path === '/healthz' || req.originalUrl.split('?')[0] === '/healthz') {
      next();
      return;
    }

    const now = Date.now();
    if (now >= windowResetAt) {
      entries.clear();
      windowResetAt = now + windowMs;
    }

    const ip = normalizeIp(req.ip) ?? req.ip ?? 'unknown';
    let state = entries.get(ip);
    if (!state) {
      state = { count: 0, warned: false };
      entries.set(ip, state);
    }

    state.count += 1;

    if (state.count <= options.max) {
      next();
      return;
    }

    if (!state.warned) {
      state.warned = true;
      appLogger.warn({ ip }, 'http.ratelimit');
    }

    const retryAfter = Math.max(1, Math.ceil((windowResetAt - now) / 1000));
    res.set('Retry-After', String(retryAfter));
    res.status(429).type('text/plain').send('Demasiadas solicitudes');
  };
}
