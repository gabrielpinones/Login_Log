import { existsSync, readFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { z } from 'zod';

export type Config = Readonly<{
  env: 'development' | 'test' | 'production';
  port: number;
  appOrigin: string;
  databaseUrl: string;
  migrationDatabaseUrl?: string;
  logDir: string;
  logRetentionDays: number;
  logMaxFileSize: string;
  auditHmacKey: string;
  serviceName: string;
  version: string;
  hostname: string;
  trustProxy: number;
  session: { idleMinutes: number; absoluteHours: number };
  lockout: { threshold: number; minutes: number };
  ipRateLimit: { max: number; windowMinutes: number };
  httpRateLimit: { max: number; windowSeconds: number };
}>;

if (existsSync('.env')) {
  // Las variables ya presentes en el entorno (por ejemplo NODE_ENV=test en la línea de comandos)
  // deben ganar sobre .env, sin depender de si loadEnvFile sobrescribe o no.
  const previas = { ...process.env };
  process.loadEnvFile('.env');
  Object.assign(process.env, previas);
}

const urlPostgres = z.string().refine((valor) => {
  try {
    const { protocol } = new URL(valor);
    return protocol === 'postgres:' || protocol === 'postgresql:';
  } catch {
    return false;
  }
});

const entero = (porDefecto: number, minimo = 1) =>
  z.coerce.number().int().min(minimo).default(porDefecto);

const MARCADOR_HMAC_EJEMPLO = 'CAMBIAR_CLAVE_HMAC_DE_AL_MENOS_32_CARACTERES';

const esquema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    PORT: z.coerce.number().int().min(1).max(65535).default(3000),
    APP_ORIGIN: z.url({ protocol: /^https?$/ }),
    DATABASE_URL: urlPostgres.optional(),
    MIGRATION_DATABASE_URL: urlPostgres.optional(),
    TEST_DATABASE_URL: urlPostgres.optional(),
    TEST_MIGRATION_DATABASE_URL: urlPostgres.optional(),
    AUDIT_HMAC_KEY: z.string().min(32),
    SERVICE_NAME: z.string().min(1).default('login-log'),
    LOG_DIR: z.string().min(1).default('logs'),
    LOG_RETENTION_DAYS: entero(90),
    LOG_MAX_FILE_SIZE: z.string().regex(/^\d+[kmg]?$/i).default('20m'),
    TRUST_PROXY: entero(0, 0),
    SESSION_IDLE_MINUTES: entero(30),
    SESSION_ABSOLUTE_HOURS: entero(8),
    LOCKOUT_THRESHOLD: entero(5),
    LOCKOUT_MINUTES: entero(15),
    IP_RATE_LIMIT_MAX: entero(20),
    IP_RATE_LIMIT_WINDOW_MINUTES: entero(15),
    HTTP_RATE_LIMIT_MAX: entero(120),
    HTTP_RATE_LIMIT_WINDOW_SECONDS: entero(60),
  })
  .superRefine((v, ctx) => {
    const requeridas =
      v.NODE_ENV === 'test'
        ? (['TEST_DATABASE_URL', 'TEST_MIGRATION_DATABASE_URL'] as const)
        : (['DATABASE_URL'] as const);
    for (const nombre of requeridas) {
      if (v[nombre] === undefined) {
        ctx.addIssue({ code: 'custom', path: [nombre], message: 'requerida' });
      }
    }
    if (v.NODE_ENV === 'production') {
      if (v.AUDIT_HMAC_KEY.startsWith('CAMBIAR') || v.AUDIT_HMAC_KEY === MARCADOR_HMAC_EJEMPLO) {
        ctx.addIssue({
          code: 'custom',
          path: ['AUDIT_HMAC_KEY'],
          message: 'no puede usar un valor de ejemplo en producción',
        });
      }
      if (!v.APP_ORIGIN.startsWith('https://')) {
        ctx.addIssue({
          code: 'custom',
          path: ['APP_ORIGIN'],
          message: 'debe usar https:// en producción',
        });
      }
    }
  });

// Una variable definida pero vacía se trata como ausente para que aplique su valor por defecto.
const entrada = Object.fromEntries(
  Object.entries(process.env).filter(([, valor]) => valor !== undefined && valor !== ''),
);

const resultado = esquema.safeParse(entrada);
if (!resultado.success) {
  // Solo nombres: los valores pueden contener contraseñas o claves.
  const nombres = [
    ...new Set(resultado.error.issues.map((issue) => String(issue.path[0] ?? '(desconocida)'))),
  ];
  process.stderr.write(`Configuración inválida. Revisa estas variables de entorno: ${nombres.join(', ')}\n`);
  process.exit(1);
}

const e = resultado.data;
const esTest = e.NODE_ENV === 'test';

function obligatoria(valor: string | undefined, nombre: string): string {
  if (valor === undefined) throw new Error(`Falta la variable de entorno ${nombre}`);
  return valor;
}

const paquete: unknown = JSON.parse(
  readFileSync(path.join(import.meta.dirname, '..', 'package.json'), 'utf8'),
);
const { version } = z.object({ version: z.string() }).parse(paquete);

export const config: Config = Object.freeze({
  env: e.NODE_ENV,
  port: e.PORT,
  appOrigin: e.APP_ORIGIN,
  databaseUrl: esTest
    ? obligatoria(e.TEST_DATABASE_URL, 'TEST_DATABASE_URL')
    : obligatoria(e.DATABASE_URL, 'DATABASE_URL'),
  migrationDatabaseUrl: esTest ? e.TEST_MIGRATION_DATABASE_URL : e.MIGRATION_DATABASE_URL,
  logDir: esTest ? path.join(e.LOG_DIR, 'test') : e.LOG_DIR,
  logRetentionDays: e.LOG_RETENTION_DAYS,
  logMaxFileSize: e.LOG_MAX_FILE_SIZE,
  auditHmacKey: e.AUDIT_HMAC_KEY,
  serviceName: e.SERVICE_NAME,
  version,
  hostname: os.hostname(),
  trustProxy: e.TRUST_PROXY,
  session: Object.freeze({
    idleMinutes: e.SESSION_IDLE_MINUTES,
    absoluteHours: e.SESSION_ABSOLUTE_HOURS,
  }),
  lockout: Object.freeze({ threshold: e.LOCKOUT_THRESHOLD, minutes: e.LOCKOUT_MINUTES }),
  ipRateLimit: Object.freeze({
    max: e.IP_RATE_LIMIT_MAX,
    windowMinutes: e.IP_RATE_LIMIT_WINDOW_MINUTES,
  }),
  httpRateLimit: Object.freeze({
    max: e.HTTP_RATE_LIMIT_MAX,
    windowSeconds: e.HTTP_RATE_LIMIT_WINDOW_SECONDS,
  }),
});
