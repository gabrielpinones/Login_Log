import { migrate } from '../../scripts/migrate.js';
import { config } from '../../src/config.js';

export default async function setup(): Promise<void> {
  // Los tests vacían las tablas: nunca deben correr contra la base de desarrollo.
  if (config.env !== 'test') {
    throw new Error('Los tests requieren NODE_ENV=test (usa npm test)');
  }
  if (config.migrationDatabaseUrl === undefined) {
    throw new Error('Falta TEST_MIGRATION_DATABASE_URL');
  }
  await migrate({ migrationUrl: config.migrationDatabaseUrl, appUrl: config.databaseUrl });
}
