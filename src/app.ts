import path from 'node:path';
import express, { type Express, type NextFunction, type Request, type Response } from 'express';
import { pinoHttp } from 'pino-http';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import { config } from './config.js';
import { pool } from './db.js';
import { appLogger } from './logging/logger.js';
import { AuditWriteError } from './audit/audit.js';
import { adminRouter } from './admin/routes.js';
import { authRouter } from './auth/routes.js';
import { loadSession } from './middleware/loadSession.js';
import { originCheck } from './middleware/originCheck.js';
import { createRateLimit } from './middleware/rateLimit.js';
import { requestId } from './middleware/requestId.js';

export function createApp(): Express {
  const app = express();

  app.set('trust proxy', config.trustProxy);
  app.disable('x-powered-by');
  app.set('view engine', 'ejs');
  app.set('views', path.join(import.meta.dirname, 'views'));

  app.use(requestId);
  app.use(
    pinoHttp({
      logger: appLogger,
      genReqId: (req) => (req as Request).requestId,
      // Solo método y ruta sin query: nunca cabeceras, cookies ni cuerpos.
      serializers: {
        req: (req: { id?: unknown; method?: string; url?: string }) => ({
          id: req.id,
          method: req.method,
          url: req.url?.split('?')[0],
        }),
        res: (res: { statusCode?: number }) => ({ statusCode: res.statusCode }),
      },
    }),
  );
  app.use(createRateLimit(config.httpRateLimit));
  // El valor por defecto de helmet (no-referrer) hace que el navegador envíe "Origin: null" en los POST
  // del mismo origen, y originCheck los rechazaría. same-origin conserva Origin y Referer reales.
  app.use(helmet({ referrerPolicy: { policy: 'same-origin' } }));
  app.use(express.static(path.join(import.meta.dirname, 'public')));
  app.use(express.urlencoded({ extended: false, limit: '10kb' }));
  app.use(cookieParser());

  app.get('/healthz', async (req, res) => {
    try {
      await pool.query('SELECT 1');
      res.json({ status: 'ok' });
    } catch (err) {
      req.log.error({ err }, 'healthz: base de datos no disponible');
      res.status(503).json({ status: 'unavailable' });
    }
  });

  app.use(loadSession);
  app.use(originCheck);
  app.use(authRouter());
  app.use(adminRouter());

  app.use((_req, res) => {
    res.status(404).render('error', {
      title: 'No encontrado',
      message: 'La página solicitada no existe.',
    });
  });

  app.use((err: unknown, req: Request, res: Response, next: NextFunction) => {
    req.log.error({ err }, 'error no controlado');
    if (res.headersSent) {
      next(err);
      return;
    }
    if (err instanceof AuditWriteError) {
      res.status(503).render('error', {
        title: 'Servicio no disponible',
        message: 'Servicio temporalmente no disponible.',
      });
      return;
    }
    res.status(500).render('error', {
      title: 'Error interno del servidor',
      message: 'Error interno del servidor.',
    });
  });

  return app;
}
