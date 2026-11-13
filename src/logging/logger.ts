import { chmodSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { pino, type DestinationStream, type Logger, type LoggerOptions } from 'pino';
import { config } from '../config.js';

const CENSOR = '[REDACTED]';
const SECRET_KEYS = ['password', 'currentPassword', 'newPassword', 'token', 'cookie', 'authorization'];

// fast-redact no admite comodines recursivos: se enumeran los niveles donde pueden aparecer.
const REDACT_PATHS = [
  ...SECRET_KEYS,
  ...SECRET_KEYS.map((k) => `*.${k}`),
  ...SECRET_KEYS.map((k) => `*.*.${k}`),
  ...SECRET_KEYS.map((k) => `login_log.details.${k}`),
  ...SECRET_KEYS.map((k) => `login_log.lost_event.details.${k}`),
  'req.headers.cookie',
  'req.headers.authorization',
  'req.body.password',
  'res.headers["set-cookie"]',
  'headers.cookie',
  'headers.authorization',
  'headers["set-cookie"]',
];

const redact = { paths: REDACT_PATHS, censor: CENSOR };

interface SerializedError {
  type: string;
  message: string;
  code?: string | number;
  stack?: string;
  cause?: SerializedError;
}

// Excluye detail, where, parameters y demás campos adjuntados por el driver de PostgreSQL.
function serializeError(err: unknown, seen = new Set<unknown>()): SerializedError {
  if (typeof err !== 'object' || err === null) {
    return { type: typeof err, message: String(err) };
  }
  const obj = err as {
    name?: unknown;
    type?: unknown;
    message?: unknown;
    code?: unknown;
    stack?: unknown;
    cause?: unknown;
  };
  const type =
    typeof obj.name === 'string' && obj.name !== ''
      ? obj.name
      : typeof obj.type === 'string' && obj.type !== ''
        ? obj.type
        : 'Error';
  const message = typeof obj.message === 'string' ? obj.message : '';
  const out: SerializedError = { type, message };
  if (typeof obj.code === 'string' || typeof obj.code === 'number') {
    out.code = obj.code;
  }
  if (typeof obj.stack === 'string') {
    out.stack = obj.stack;
  }
  seen.add(err);
  if (obj.cause !== undefined && obj.cause !== null && !seen.has(obj.cause)) {
    out.cause = serializeError(obj.cause, seen);
  }
  return out;
}

mkdirSync(config.logDir, { recursive: true, mode: 0o700 });
chmodSync(config.logDir, 0o700);

function rollTarget(name: 'app' | 'auth-events') {
  return {
    target: 'pino-roll',
    options: {
      // La extensión se incluye en el nombre porque pino-roll 4.0.0 ignora la opción extension.
      file: path.join(config.logDir, `${name}.jsonl`),
      frequency: 'daily',
      dateFormat: 'yyyy-MM-dd',
      size: config.logMaxFileSize,
      mkdir: true,
      mode: 0o600,
    },
  };
}

function syncFile(name: 'app' | 'auth-events'): DestinationStream {
  const dest = path.join(config.logDir, `${name}.jsonl`);
  const stream = pino.destination({ dest, sync: true, mkdir: true, mode: 0o600 });
  chmodSync(dest, 0o600);
  return stream;
}

const isTest = config.env === 'test';

const appOptions: LoggerOptions = {
  level: 'info',
  redact,
  serializers: { err: serializeError },
  // pino-http reemplaza serializers.err en el hijo que crea; se restablece aquí.
  onChild: (child) => {
    const table = (child as unknown as Record<symbol, Record<string, unknown>>)[
      pino.symbols.serializersSym
    ];
    if (table !== undefined) {
      table.err = serializeError;
    }
  },
};

export const appLogger: Logger = isTest
  ? pino(appOptions, syncFile('app'))
  : pino({
      ...appOptions,
      transport: {
        targets: [
          { ...rollTarget('app'), level: 'info' },
          { target: 'pino/file', options: { destination: 1 }, level: 'info' },
        ],
      },
    });

const auditOptions: LoggerOptions = {
  level: 'info',
  base: undefined,
  // El @timestamp es el del evento (occurred_at), no el momento de escritura.
  timestamp: false,
  messageKey: 'message',
  formatters: { level: (label) => ({ log: { level: label } }) },
  redact,
};

export const auditLogger: Logger = isTest
  ? pino(auditOptions, syncFile('auth-events'))
  : pino({ ...auditOptions, transport: rollTarget('auth-events') });

function flushOne(logger: Logger): Promise<void> {
  return new Promise((resolve) => {
    try {
      logger.flush(() => resolve());
    } catch {
      resolve();
    }
  });
}

export async function flushLogs(): Promise<void> {
  await Promise.all([flushOne(appLogger), flushOne(auditLogger)]);
}
