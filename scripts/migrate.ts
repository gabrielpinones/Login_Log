import { createHash, createHmac, pbkdf2Sync, randomBytes } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

const DIRECTORIO_MIGRACIONES = path.join(import.meta.dirname, '..', 'migrations');
const ROL_APP = 'login_log_app';
// Evita que dos procesos de migración trabajen a la vez sobre la misma base.
const CLAVE_BLOQUEO_MIGRACION = 7305214486019002;

function codigoPg(err: unknown): string | undefined {
  if (typeof err === 'object' && err !== null && 'code' in err && typeof err.code === 'string') {
    return err.code;
  }
  return undefined;
}

function mensaje(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function nombreBase(url: string): string {
  const nombre = decodeURIComponent(new URL(url).pathname.replace(/^\//, ''));
  if (nombre === '') throw new Error('La URL de migración no indica la base de datos');
  return nombre;
}

async function conectar(url: string): Promise<pg.Client> {
  const cliente = new pg.Client({ connectionString: url });
  await cliente.connect();
  return cliente;
}

async function conectarCreandoBase(migrationUrl: string): Promise<pg.Client> {
  try {
    return await conectar(migrationUrl);
  } catch (err) {
    if (codigoPg(err) !== '3D000') throw err;
  }

  const destino = nombreBase(migrationUrl);
  const urlMantenimiento = new URL(migrationUrl);
  urlMantenimiento.pathname = '/postgres';
  const mantenimiento = await conectar(urlMantenimiento.toString());
  try {
    await mantenimiento.query(`CREATE DATABASE ${pg.escapeIdentifier(destino)}`);
  } catch (err) {
    if (codigoPg(err) !== '42P04') throw err;
  } finally {
    await mantenimiento.end();
  }
  return conectar(migrationUrl);
}

function verificadorScramSha256(password: string): string {
  const iteraciones = 4096;
  const sal = randomBytes(16);
  const saltedPassword = pbkdf2Sync(password, sal, iteraciones, 32, 'sha256');
  const clientKey = createHmac('sha256', saltedPassword).update('Client Key').digest();
  const storedKey = createHash('sha256').update(clientKey).digest();
  const serverKey = createHmac('sha256', saltedPassword).update('Server Key').digest();
  return `SCRAM-SHA-256$${iteraciones}:${sal.toString('base64')}$${storedKey.toString('base64')}:${serverKey.toString('base64')}`;
}

async function sincronizarPasswordRol(cliente: pg.Client, appUrl: string): Promise<void> {
  const url = new URL(appUrl);
  if (decodeURIComponent(url.username) !== ROL_APP || url.password === '') return;
  const password = decodeURIComponent(url.password);
  const verificador = verificadorScramSha256(password);

  await cliente.query('BEGIN');
  try {
    const { rows } = await cliente.query<{ superusuario: string }>(
      "SELECT current_setting('is_superuser') AS superusuario",
    );
    if (rows[0]?.superusuario === 'on') {
      // Defensa adicional para que tampoco el verificador quede en el log del servidor.
      await cliente.query("SET LOCAL log_statement = 'none'");
      await cliente.query('SET LOCAL log_min_duration_statement = -1');
      await cliente.query("SET LOCAL log_min_error_statement = 'panic'");
    }
    // ALTER ROLE no admite parámetros enlazados; escapeLiteral evita la inyección.
    await cliente.query(`ALTER ROLE ${ROL_APP} PASSWORD ${pg.escapeLiteral(verificador)}`);
    await cliente.query('COMMIT');
  } catch (err) {
    await cliente.query('ROLLBACK');
    throw new Error(`No se pudo sincronizar la contraseña de ${ROL_APP}: ${mensaje(err)}`, {
      cause: err,
    });
  }
}

export async function migrate(opts: { migrationUrl: string; appUrl: string }): Promise<string[]> {
  const cliente = await conectarCreandoBase(opts.migrationUrl);
  try {
    await cliente.query('SELECT pg_advisory_lock($1)', [CLAVE_BLOQUEO_MIGRACION]);
    await cliente.query(
      'CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, applied_at timestamptz DEFAULT now())',
    );

    const { rows } = await cliente.query<{ name: string }>('SELECT name FROM schema_migrations');
    const yaAplicadas = new Set(rows.map((fila) => fila.name));
    const archivos = (await readdir(DIRECTORIO_MIGRACIONES))
      .filter((archivo) => archivo.endsWith('.sql'))
      .sort();

    const aplicadas: string[] = [];
    for (const archivo of archivos) {
      if (yaAplicadas.has(archivo)) continue;
      const sql = await readFile(path.join(DIRECTORIO_MIGRACIONES, archivo), 'utf8');
      await cliente.query('BEGIN');
      try {
        await cliente.query(sql);
        await cliente.query('INSERT INTO schema_migrations (name) VALUES ($1)', [archivo]);
        await cliente.query('COMMIT');
      } catch (err) {
        await cliente.query('ROLLBACK');
        throw new Error(`Falló la migración ${archivo}: ${mensaje(err)}`, { cause: err });
      }
      aplicadas.push(archivo);
    }

    await sincronizarPasswordRol(cliente, opts.appUrl);
    return aplicadas;
  } finally {
    await cliente.end();
  }
}

const rutaScript = process.argv[1];
const invocadoComoCli =
  rutaScript !== undefined && path.resolve(rutaScript) === fileURLToPath(import.meta.url);

if (invocadoComoCli) {
  const { config } = await import('../src/config.js');
  try {
    if (config.migrationDatabaseUrl === undefined) {
      throw new Error('Falta MIGRATION_DATABASE_URL (o TEST_MIGRATION_DATABASE_URL en modo test)');
    }
    const aplicadas = await migrate({
      migrationUrl: config.migrationDatabaseUrl,
      appUrl: config.databaseUrl,
    });
    console.log(
      aplicadas.length > 0
        ? `Migraciones aplicadas en ${config.env}: ${aplicadas.join(', ')}`
        : `Sin migraciones pendientes en ${config.env}`,
    );
  } catch (err) {
    console.error(`Error de migración: ${mensaje(err)}`);
    process.exitCode = 1;
  }
}
