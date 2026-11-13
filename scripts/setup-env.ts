import { randomBytes } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import path from 'node:path';

const destino = path.join(import.meta.dirname, '..', '.env');

// La misma contraseña sirve para desarrollo y pruebas porque el rol login_log_app es del clúster.
const passwordApp = randomBytes(24).toString('hex');
const claveHmac = randomBytes(32).toString('hex');

const contenido = `NODE_ENV=development
PORT=3000
APP_ORIGIN=http://localhost:3000
DATABASE_URL=postgres://login_log_app:${passwordApp}@localhost:5432/login_log
MIGRATION_DATABASE_URL=postgres://postgres@localhost:5432/login_log
TEST_DATABASE_URL=postgres://login_log_app:${passwordApp}@localhost:5432/login_log_test
TEST_MIGRATION_DATABASE_URL=postgres://postgres@localhost:5432/login_log_test
AUDIT_HMAC_KEY=${claveHmac}
`;

try {
  // 'wx' falla si el archivo ya existe, sin ventana entre comprobar y crear.
  writeFileSync(destino, contenido, { mode: 0o600, flag: 'wx' });
  console.log('.env creado con permisos 0600. Ejecuta ahora npm run migrate.');
} catch (err) {
  if (typeof err === 'object' && err !== null && 'code' in err && err.code === 'EEXIST') {
    console.log('.env ya existe: no se modificó.');
  } else {
    console.error(`No se pudo crear .env: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 1;
  }
}
