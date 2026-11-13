import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { config } from '../src/config.js';
import { flushLogs } from '../src/logging/logger.js';
import { auditLogPath, closeAll, resetAuditLog, resetDb } from './helpers.js';
import {
  getPage,
  loginUser,
  postForm,
  readAuthEvents,
  readSessions,
  registerUser,
} from './support/client.js';

beforeEach(async () => {
  vi.restoreAllMocks();
  await resetDb();
  resetAuditLog();
});

afterAll(async () => {
  await closeAll();
});

describe('ausencia de secretos y datos sensibles en BD y logs', () => {
  it('nunca persiste contraseñas, tokens sid ni el correo en claro tras un recorrido completo', async () => {
    const emailLocal = 'persona.secreta.reconocible';
    const email = 'Persona.Secreta.Reconocible@Ejemplo.Test';
    const initialPassword = 'ClaveInicialReconocible-9876';
    const wrongPassword = 'ClaveFallidaReconocible-5432';
    const newPassword = 'ClaveNuevaReconocible-1357';

    const regRes = await registerUser(email, initialPassword);
    expect(regRes.status).toBe(303);

    const failLogin = await loginUser(email, wrongPassword);
    expect(failLogin.res.status).toBe(401);

    const firstLogin = await loginUser(email, initialPassword);
    expect(firstLogin.res.status).toBe(303);
    const firstSid = firstLogin.sid;
    if (firstSid === undefined) throw new Error('Se esperaba cookie sid en el primer login');

    const cuentaRes = await getPage('/cuenta', { sid: firstSid });
    expect(cuentaRes.status).toBe(200);

    const changeRes = await postForm(
      '/cuenta/password',
      { currentPassword: initialPassword, newPassword },
      { sid: firstSid },
    );
    expect(changeRes.status).toBe(303);

    const firstLogout = await postForm('/logout', {}, { sid: firstSid });
    expect(firstLogout.status).toBe(303);

    const secondLogin = await loginUser(email, newPassword);
    expect(secondLogin.res.status).toBe(303);
    const secondSid = secondLogin.sid;
    if (secondSid === undefined) throw new Error('Se esperaba cookie sid en el segundo login');

    const secondLogout = await postForm('/logout', {}, { sid: secondSid });
    expect(secondLogout.status).toBe(303);

    await flushLogs();

    const secrets = [initialPassword, wrongPassword, newPassword, firstSid, secondSid];

    const events = await readAuthEvents();
    const sessions = await readSessions();
    expect(events.length).toBeGreaterThan(0);
    expect(sessions.length).toBeGreaterThan(0);

    const eventsJson = JSON.stringify(events);
    const sessionsJson = JSON.stringify(sessions);

    for (const secret of secrets) {
      expect(eventsJson).not.toContain(secret);
      expect(sessionsJson).not.toContain(secret);
    }
    expect(eventsJson.toLowerCase()).not.toContain(emailLocal);

    const entries = readdirSync(config.logDir);
    const files = entries.filter((name) => statSync(path.join(config.logDir, name)).isFile());
    expect(files.length).toBeGreaterThan(0);

    for (const file of files) {
      const content = readFileSync(path.join(config.logDir, file), 'utf8');
      for (const secret of secrets) {
        expect(content).not.toContain(secret);
      }
    }

    const auditContent = readFileSync(auditLogPath, 'utf8');
    expect(auditContent.trim()).not.toBe('');
    expect(auditContent.toLowerCase()).not.toContain(emailLocal);
  });
});
