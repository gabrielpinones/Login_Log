import type { Server } from 'node:http';
import { createApp } from './app.js';
import { expireStaleSessions } from './auth/sessions.js';
import { config } from './config.js';
import { closePool } from './db.js';
import { appLogger, flushLogs } from './logging/logger.js';
import { purgeOldLogs } from './logging/retention.js';

const PURGE_INTERVAL_MS = 24 * 60 * 60 * 1000;
const EXPIRE_SESSIONS_INTERVAL_MS = 5 * 60 * 1000;

async function runPurge(): Promise<void> {
  try {
    await purgeOldLogs();
  } catch (err) {
    appLogger.error({ err }, 'log.retention.error');
  }
}

async function runExpireSessions(): Promise<void> {
  try {
    await expireStaleSessions();
  } catch (err) {
    appLogger.error({ err }, 'session.expiration.error');
  }
}

const app = createApp();
const server = app.listen(config.port, () => {
  appLogger.info({ port: config.port, version: config.version, environment: config.env }, 'app.start');
});

void runPurge();
const purgeTimer = setInterval(() => void runPurge(), PURGE_INTERVAL_MS);
purgeTimer.unref();

const expireSessionsTimer = setInterval(() => void runExpireSessions(), EXPIRE_SESSIONS_INTERVAL_MS);
expireSessionsTimer.unref();

function closeServer(s: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    s.close((err) => (err ? reject(err) : resolve()));
    s.closeIdleConnections();
  });
}

let shuttingDown = false;

async function shutdown(signal: string): Promise<void> {
  if (shuttingDown) return;
  shuttingDown = true;
  clearInterval(purgeTimer);
  clearInterval(expireSessionsTimer);
  let exitCode = 0;
  try {
    await closeServer(server);
    await closePool();
  } catch (err) {
    exitCode = 1;
    appLogger.error({ err }, 'app.stop: fallo durante el cierre');
  }
  appLogger.info({ signal }, 'app.stop');
  await flushLogs();
  process.exit(exitCode);
}

process.on('SIGTERM', () => void shutdown('SIGTERM'));
process.on('SIGINT', () => void shutdown('SIGINT'));
