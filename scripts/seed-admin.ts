import pg from 'pg';
import { z } from 'zod';
import { config } from '../src/config.js';
import { closePool } from '../src/db.js';
import { withAudit } from '../src/audit/audit.js';
import { flushLogs } from '../src/logging/logger.js';
import { checkPasswordPolicy, hashPassword } from '../src/auth/passwords.js';

const emailSchema = z.email().max(254);

async function main(): Promise<void> {
  const rawEmail = process.env.ADMIN_EMAIL;
  const rawPassword = process.env.ADMIN_PASSWORD;

  if (rawEmail === undefined || rawEmail.trim() === '' || rawPassword === undefined || rawPassword === '') {
    process.stderr.write('Debes definir ADMIN_EMAIL y ADMIN_PASSWORD en el entorno.\n');
    process.exitCode = 1;
    return;
  }

  if (config.migrationDatabaseUrl === undefined) {
    process.stderr.write('Debes definir MIGRATION_DATABASE_URL en el entorno.\n');
    process.exitCode = 1;
    return;
  }

  const email = rawEmail.trim().toLowerCase();
  if (!emailSchema.safeParse(email).success) {
    process.stderr.write('ADMIN_EMAIL no tiene un formato de correo válido.\n');
    process.exitCode = 1;
    return;
  }

  const policy = checkPasswordPolicy(rawPassword, email);
  if (!policy.ok) {
    process.stderr.write(`ADMIN_PASSWORD no cumple la política: ${policy.message}\n`);
    process.exitCode = 1;
    return;
  }

  const passwordHash = await hashPassword(rawPassword);
  const migrationPool = new pg.Pool({ connectionString: config.migrationDatabaseUrl, max: 1 });
  migrationPool.on('error', (err) => {
    process.stderr.write(`Error en conexión de migración de PostgreSQL: ${err.message}\n`);
  });

  try {
    const action = await withAudit(
      {},
      async (tx) => {
        const existing = await tx.client.query<{ id: string; role: string }>(
          'SELECT id, role FROM users WHERE email = $1 FOR UPDATE',
          [email],
        );
        if (existing.rows[0]) {
          const userId = existing.rows[0].id;
          const previousRole = existing.rows[0].role;

          await tx.client.query(
            "UPDATE users SET role = 'admin', password_hash = $1, password_changed_at = now() WHERE id = $2",
            [passwordHash, userId],
          );

          if (previousRole !== 'admin') {
            tx.record({
              type: 'auth.role.changed',
              userId,
              details: { from: previousRole, to: 'admin', via: 'seed_script' },
            });
          }

          tx.record({
            type: 'auth.password.change.success',
            userId,
            details: { via: 'seed_script' },
          });

          const revoked = await tx.client.query<{ id: string }>(
            `UPDATE sessions
             SET revoked_at = now(), end_reason = 'password_change'
             WHERE user_id = $1 AND revoked_at IS NULL
             RETURNING id`,
            [userId],
          );

          for (const session of revoked.rows) {
            tx.record({
              type: 'session.revoked',
              reason: 'password_change',
              userId,
              sessionId: session.id,
            });
          }

          return 'elevated' as const;
        }

        const inserted = await tx.client.query<{ id: string }>(
          "INSERT INTO users (email, password_hash, role) VALUES ($1, $2, 'admin') RETURNING id",
          [email, passwordHash],
        );
        const created = inserted.rows[0];
        if (!created) {
          throw new Error('No se pudo crear el usuario administrador');
        }

        tx.record({
          type: 'auth.register.success',
          userId: created.id,
          identifier: rawEmail,
          details: { role: 'admin', via: 'seed_script' },
        });

        return 'created' as const;
      },
      migrationPool,
    );

    if (action === 'elevated') {
      process.stdout.write(`Usuario existente elevado a admin: ${email}\n`);
    } else {
      process.stdout.write(`Usuario admin creado: ${email}\n`);
    }
  } finally {
    await migrationPool.end();
  }
}

try {
  await main();
} catch (err) {
  const msg = err instanceof Error ? err.message : String(err);
  process.stderr.write(`Error en seed-admin: ${msg}\n`);
  process.exitCode = 1;
} finally {
  await closePool();
  await flushLogs();
}
