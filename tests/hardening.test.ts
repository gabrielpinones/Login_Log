import express from 'express';
import request from 'supertest';
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { recordEvent } from '../src/audit/audit.js';
import { config } from '../src/config.js';
import { flushLogs } from '../src/logging/logger.js';
import { createRateLimit } from '../src/middleware/rateLimit.js';
import { adminPool, closeAll, readAuditLines, resetAuditLog, resetDb } from './helpers.js';
import {
  assertHttpEvents,
  extractSid,
  findSidSetCookie,
  getPage,
  loginUser,
  postForm,
  readAuthEvents,
  readSessions,
  readUsers,
  registerAndLogin,
  registerUser,
  withAuditWriteFailure,
  withNewEvents,
} from './support/client.js';

const PASSWORD_VALIDA = 'nube-montana-rio-71';
const PASSWORD_NUEVA = 'bosque-lluvia-sol-84';
const PASSWORD_ERRONEA = 'clave-erronea-concurrencia';

beforeEach(async () => {
  vi.restoreAllMocks();
  await resetDb();
  resetAuditLog();
});

afterAll(async () => {
  await closeAll();
});

describe('C1: atomicidad ante fallos de escritura de auditoría', () => {
  it('(a) POST /registro responde 503, no crea usuario y escribe audit.write.failed en JSONL', async () => {
    const res = await withAuditWriteFailure(() => registerUser('c1a@ejemplo.test', PASSWORD_VALIDA));

    expect(res.status).toBe(503);
    expect(await readUsers()).toHaveLength(0);
    expect(await readAuthEvents()).toHaveLength(0);

    await flushLogs();
    const lines = readAuditLines();
    expect(lines.some((line) => line.event?.action === 'audit.write.failed')).toBe(true);
  });

  it('(b) POST /login correcto responde 503, sin cookie sid, sin sesión en BD y con audit.write.failed', async () => {
    const email = 'c1b@ejemplo.test';
    await registerUser(email, PASSWORD_VALIDA);
    const linesBefore = readAuditLines().length;

    const { res, sid } = await withAuditWriteFailure(() => loginUser(email, PASSWORD_VALIDA));

    expect(res.status).toBe(503);
    expect(sid).toBeUndefined();
    expect(findSidSetCookie(res)).toBeUndefined();
    expect(await readSessions()).toHaveLength(0);

    await flushLogs();
    const newLines = readAuditLines().slice(linesBefore);
    expect(newLines.some((line) => line.event?.action === 'audit.write.failed')).toBe(true);
  });

  it('(c) POST /logout responde 503, deja la sesión activa y escribe audit.write.failed', async () => {
    const { sessionId, sid } = await registerAndLogin('c1c@ejemplo.test', PASSWORD_VALIDA);
    const linesBefore = readAuditLines().length;

    const res = await withAuditWriteFailure(() => postForm('/logout', {}, { sid }));

    expect(res.status).toBe(503);

    const sessions = await readSessions();
    const session = sessions.find((s) => s.id === sessionId);
    expect(session?.revoked_at).toBeNull();
    expect(session?.end_reason).toBeNull();

    await flushLogs();
    const newLines = readAuditLines().slice(linesBefore);
    expect(newLines.some((line) => line.event?.action === 'audit.write.failed')).toBe(true);

    // La sesión sigue siendo utilizable tras recuperar la escritura de auditoría.
    const cuentaRes = await getPage('/cuenta', { sid });
    expect(cuentaRes.status).toBe(200);
  });

  it('(d) POST /cuenta/password responde 503, conserva la contraseña anterior y mantiene otras sesiones', async () => {
    const email = 'c1d@ejemplo.test';
    const { sid: sidA } = await registerAndLogin(email, PASSWORD_VALIDA);
    const { sid: sidB } = await loginUser(email, PASSWORD_VALIDA);
    if (sidB === undefined) throw new Error('Se esperaba cookie sid para sesión B');

    const linesBefore = readAuditLines().length;

    const changeRes = await withAuditWriteFailure(() =>
      postForm(
        '/cuenta/password',
        { currentPassword: PASSWORD_VALIDA, newPassword: PASSWORD_NUEVA },
        { sid: sidA },
      ),
    );
    expect(changeRes.status).toBe(503);

    await flushLogs();
    const newLines = readAuditLines().slice(linesBefore);
    expect(newLines.some((line) => line.event?.action === 'audit.write.failed')).toBe(true);

    // La contraseña anterior sigue funcionando y la nueva no.
    expect((await loginUser(email, PASSWORD_VALIDA)).res.status).toBe(303);
    expect((await loginUser(email, PASSWORD_NUEVA)).res.status).toBe(401);

    // La otra sesión del usuario sigue activa.
    expect((await getPage('/cuenta', { sid: sidB })).status).toBe(200);
  });

  it('(e) una sesión vencida por inactividad no queda cerrada si falla el evento de auditoría', async () => {
    const { sessionId, sid } = await registerAndLogin('c1e@ejemplo.test', PASSWORD_VALIDA);

    await adminPool.query(
      "UPDATE sessions SET last_seen_at = now() - (($1::int + 1) * interval '1 minute') WHERE id = $2",
      [config.session.idleMinutes, sessionId],
    );

    const linesBefore = readAuditLines().length;
    const res = await withAuditWriteFailure(() => getPage('/cuenta', { sid }));

    expect(res.status).toBe(503);

    const sessions = await readSessions();
    const session = sessions.find((s) => s.id === sessionId);
    expect(session?.revoked_at).toBeNull();
    expect(session?.end_reason).toBeNull();

    await flushLogs();
    const newLines = readAuditLines().slice(linesBefore);
    expect(newLines.some((line) => line.event?.action === 'audit.write.failed')).toBe(true);
  });
});

describe('C3: login concurrente sin condición de carrera', () => {
  it('threshold + 3 fallos concurrentes emiten un único auth.account.locked y dejan failed_attempts en threshold', async () => {
    const email = 'c3-bloqueo@ejemplo.test';
    await registerUser(email, PASSWORD_VALIDA);

    const responses = await Promise.all(
      Array.from({ length: config.lockout.threshold + 3 }, () => loginUser(email, PASSWORD_ERRONEA)),
    );

    for (const out of responses) {
      expect(out.res.status).toBe(401);
      expect(out.sid).toBeUndefined();
    }

    const events = await readAuthEvents();
    const lockedEvents = events.filter((ev) => ev.event_type === 'auth.account.locked');
    expect(lockedEvents).toHaveLength(1);

    const user = (await readUsers())[0];
    expect(user?.failed_attempts).toBe(config.lockout.threshold);
  });

  it('threshold fallos y un intento correcto concurrentes nunca dejan auth.login.success tras auth.account.locked sin desbloqueo', async () => {
    const email = 'c3-carrera@ejemplo.test';
    await registerUser(email, PASSWORD_VALIDA);

    await Promise.all([
      ...Array.from({ length: config.lockout.threshold }, () => loginUser(email, PASSWORD_ERRONEA)),
      loginUser(email, PASSWORD_VALIDA),
    ]);

    const events = await readAuthEvents();
    let isLocked = false;
    for (const ev of events) {
      if (ev.event_type === 'auth.account.locked') {
        isLocked = true;
      } else if (ev.event_type === 'auth.account.unlocked') {
        isLocked = false;
      } else if (ev.event_type === 'auth.login.success') {
        expect(isLocked).toBe(false);
      }
    }
  });
});

describe('C4: login con sesión activa en cookie', () => {
  it('cierra la sesión anterior como logout y emite auth.logout con cause relogin tras session.created', async () => {
    const email = 'c4-relogin@ejemplo.test';
    const { userId, sessionId: firstSessionId, sid: firstSid } = await registerAndLogin(
      email,
      PASSWORD_VALIDA,
    );

    const { result: secondRes, events } = await withNewEvents(() =>
      postForm('/login', { email, password: PASSWORD_VALIDA }, { sid: firstSid }),
    );

    expect(secondRes.status).toBe(303);
    expect(secondRes.get('Location')).toBe('/cuenta');
    const secondSid = extractSid(secondRes);
    expect(secondSid).toBeDefined();
    expect(secondSid).not.toBe(firstSid);

    const sessions = await readSessions();
    expect(sessions).toHaveLength(2);
    const firstSession = sessions.find((s) => s.id === firstSessionId);
    const secondSession = sessions.find((s) => s.id !== firstSessionId);
    if (!firstSession || !secondSession) throw new Error('Se esperaban dos sesiones');

    expect(firstSession.revoked_at).not.toBeNull();
    expect(firstSession.end_reason).toBe('logout');
    expect(secondSession.revoked_at).toBeNull();

    assertHttpEvents(
      events,
      secondRes,
      { method: 'POST', route: '/login' },
      [
        { type: 'auth.login.success' },
        { type: 'session.created' },
        { type: 'auth.logout' },
      ],
    );
    expect(events[0]?.session_id).toBe(secondSession.id);
    expect(events[1]?.session_id).toBe(secondSession.id);
    expect(events[2]?.user_id).toBe(userId);
    expect(events[2]?.session_id).toBe(firstSessionId);
    expect(events[2]?.details).toEqual({ cause: 'relogin' });
  });
});

describe('C5: expiración previa al revocar otras sesiones en cambio de contraseña', () => {
  it('emite session.expired/idle_timeout y ningún session.revoked para la sesión ya vencida', async () => {
    const email = 'c5-expirada@ejemplo.test';
    const { userId, sessionId: sessionAId } = await registerAndLogin(email, PASSWORD_VALIDA);
    const { res: loginB, sid: sidB } = await loginUser(email, PASSWORD_VALIDA);
    expect(loginB.status).toBe(303);
    if (sidB === undefined) throw new Error('Se esperaba cookie sid para sesión B');

    const sessionB = (await readSessions()).find((s) => s.id !== sessionAId);
    if (!sessionB) throw new Error('Se esperaba sesión B');

    await adminPool.query(
      "UPDATE sessions SET last_seen_at = now() - (($1::int + 1) * interval '1 minute') WHERE id = $2",
      [config.session.idleMinutes, sessionAId],
    );

    const { result: changeRes, events } = await withNewEvents(() =>
      postForm(
        '/cuenta/password',
        { currentPassword: PASSWORD_VALIDA, newPassword: PASSWORD_NUEVA },
        { sid: sidB },
      ),
    );

    expect(changeRes.status).toBe(303);
    expect(changeRes.get('Location')).toBe('/cuenta?cambiada=1');

    expect(events.filter((ev) => ev.event_type === 'session.revoked')).toHaveLength(0);

    const expiredEv = events.find((ev) => ev.event_type === 'session.expired');
    expect(expiredEv).toBeDefined();
    expect(expiredEv?.reason).toBe('idle_timeout');
    expect(expiredEv?.user_id).toBe(userId);
    expect(expiredEv?.session_id).toBe(sessionAId);
    expect(expiredEv?.http_status).toBeNull();

    const changeEv = events.find((ev) => ev.event_type === 'auth.password.change.success');
    expect(changeEv).toBeDefined();
    expect(changeEv?.user_id).toBe(userId);
    expect(changeEv?.session_id).toBe(sessionB.id);
    expect(changeEv?.http_status).toBe(303);

    const sessionsAfter = await readSessions();
    const sessionA = sessionsAfter.find((s) => s.id === sessionAId);
    const sessionBAfter = sessionsAfter.find((s) => s.id === sessionB.id);
    expect(sessionA?.revoked_at).not.toBeNull();
    expect(sessionA?.end_reason).toBe('idle_timeout');
    expect(sessionBAfter?.revoked_at).toBeNull();
  });
});

describe('C6: límite de intentos fallidos en cambio de contraseña', () => {
  it('responde 429 con rate_limited tras threshold fallos aunque la contraseña actual sea correcta', async () => {
    const email = 'c6-cambio@ejemplo.test';
    const { userId, sessionId, sid } = await registerAndLogin(email, PASSWORD_VALIDA);

    for (let i = 0; i < config.lockout.threshold; i++) {
      const failRes = await postForm(
        '/cuenta/password',
        { currentPassword: 'clave-actual-equivocada', newPassword: PASSWORD_NUEVA },
        { sid },
      );
      expect(failRes.status).toBe(400);
    }

    const { result: limitedRes, events } = await withNewEvents(() =>
      postForm(
        '/cuenta/password',
        { currentPassword: PASSWORD_VALIDA, newPassword: PASSWORD_NUEVA },
        { sid },
      ),
    );

    expect(limitedRes.status).toBe(429);
    assertHttpEvents(
      events,
      limitedRes,
      { method: 'POST', route: '/cuenta/password' },
      [{ type: 'auth.password.change.failure', reason: 'rate_limited' }],
    );
    expect(events[0]?.user_id).toBe(userId);
    expect(events[0]?.session_id).toBe(sessionId);

    // La contraseña no debe haber cambiado.
    expect((await loginUser(email, PASSWORD_VALIDA)).res.status).toBe(303);
    expect((await loginUser(email, PASSWORD_NUEVA)).res.status).toBe(401);
  });
});

describe('C7: orden de middlewares (loadSession antes de originCheck)', () => {
  it('incluye user_id y session_id en security.csrf.rejected cuando hay sesión válida', async () => {
    const { userId, sessionId, sid } = await registerAndLogin('c7-csrf@ejemplo.test', PASSWORD_VALIDA);

    const { result: res, events } = await withNewEvents(() =>
      postForm('/logout', {}, { origin: 'https://atacante.ejemplo', sid }),
    );

    expect(res.status).toBe(403);
    assertHttpEvents(
      events,
      res,
      { method: 'POST', route: '/logout' },
      [{ type: 'security.csrf.rejected', reason: 'origin_mismatch' }],
    );
    expect(events[0]?.user_id).toBe(userId);
    expect(events[0]?.session_id).toBe(sessionId);
  });
});

describe('C8: middleware createRateLimit en memoria', () => {
  it('bloquea la cuarta petición con 429, Retry-After y texto esperado sin escribir en auth_events', async () => {
    const miniApp = express();
    miniApp.use(createRateLimit({ max: 3, windowSeconds: 60 }));
    miniApp.get('/ping', (_req, res) => {
      res.status(200).send('ok');
    });

    for (let i = 0; i < 3; i++) {
      const okRes = await request(miniApp).get('/ping');
      expect(okRes.status).toBe(200);
    }

    const blockedRes = await request(miniApp).get('/ping');
    expect(blockedRes.status).toBe(429);
    expect(blockedRes.text).toBe('Demasiadas solicitudes');
    expect(Number(blockedRes.get('Retry-After'))).toBeGreaterThan(0);

    expect(await readAuthEvents()).toHaveLength(0);
  });
});

describe('C9: censura de claves sensibles en details antes de INSERT', () => {
  it('persiste [REDACTED] en la columna details de auth_events y conserva las demás claves', async () => {
    await recordEvent({
      type: 'auth.login.success',
      details: { password: 'x', token: 'y', ok: true },
    });

    const events = await readAuthEvents();
    expect(events).toHaveLength(1);
    expect(events[0]?.details).toEqual({
      password: '[REDACTED]',
      token: '[REDACTED]',
      ok: true,
    });
  });
});

describe('C11: registro con correo existente', () => {
  it('responde 409 y emite auth.register.failure/email_taken', async () => {
    const email = 'c11-repetido@ejemplo.test';
    await registerUser(email, PASSWORD_VALIDA);
    const existing = (await readUsers())[0];
    if (!existing) throw new Error('Se esperaba usuario existente');

    const { result: dupRes, events } = await withNewEvents(() =>
      registerUser(email, PASSWORD_NUEVA),
    );

    expect(dupRes.status).toBe(409);
    expect(await readUsers()).toHaveLength(1);
    assertHttpEvents(
      events,
      dupRes,
      { method: 'POST', route: '/registro' },
      [{ type: 'auth.register.failure', reason: 'email_taken' }],
    );
    expect(events[0]?.user_id).toBe(existing.id);
  });
});
