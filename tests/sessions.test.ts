import { createHash } from 'node:crypto';
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { config } from '../src/config.js';
import { adminPool, closeAll, resetAuditLog, resetDb } from './helpers.js';
import {
  assertHttpEvents,
  extractSid,
  findSidSetCookie,
  getPage,
  loginUser,
  readAuthEvents,
  readSessions,
  registerAndLogin,
  registerUser,
  withAuditWriteFailure,
  withNewEvents,
} from './support/client.js';

const PASSWORD_VALIDA = 'nube-montana-rio-71';

beforeEach(async () => {
  vi.restoreAllMocks();
  await resetDb();
  resetAuditLog();
});

afterAll(async () => {
  await closeAll();
});

describe('expiración y validación de sesiones', () => {
  it('cierra la sesión por inactividad (idle_timeout), limpia la cookie y no repite session.expired', async () => {
    const { userId, sessionId, sid } = await registerAndLogin('inactiva@ejemplo.test', PASSWORD_VALIDA);

    await adminPool.query(
      "UPDATE sessions SET last_seen_at = now() - (($1::int + 1) * interval '1 minute') WHERE id = $2",
      [config.session.idleMinutes, sessionId],
    );

    const { result: firstRes, events: firstEvents } = await withNewEvents(() =>
      getPage('/cuenta', { sid }),
    );
    expect(firstRes.status).toBe(303);
    expect(firstRes.get('Location')).toBe('/login');
    expect(extractSid(firstRes)).toBeUndefined();
    expect(findSidSetCookie(firstRes)).toBeDefined();

    assertHttpEvents(
      firstEvents,
      firstRes,
      { method: 'GET', route: '/cuenta' },
      [
        { type: 'session.expired', reason: 'idle_timeout' },
        { type: 'authz.denied', reason: 'no_session' },
      ],
    );
    expect(firstEvents[0]?.user_id).toBe(userId);
    expect(firstEvents[0]?.session_id).toBe(sessionId);

    const sessions = await readSessions();
    expect(sessions[0]?.revoked_at).not.toBeNull();
    expect(sessions[0]?.end_reason).toBe('idle_timeout');

    const { result: secondRes, events: secondEvents } = await withNewEvents(() =>
      getPage('/cuenta', { sid }),
    );
    expect(secondRes.status).toBe(303);
    expect(secondRes.get('Location')).toBe('/login');
    assertHttpEvents(
      secondEvents,
      secondRes,
      { method: 'GET', route: '/cuenta' },
      [{ type: 'authz.denied', reason: 'no_session' }],
    );
  });

  it('cierra la sesión al superar el límite absoluto (absolute_timeout)', async () => {
    const { userId, sessionId, sid } = await registerAndLogin('absoluta@ejemplo.test', PASSWORD_VALIDA);

    await adminPool.query("UPDATE sessions SET expires_at = now() - interval '1 minute' WHERE id = $1", [
      sessionId,
    ]);

    const { result: res, events } = await withNewEvents(() => getPage('/cuenta', { sid }));
    expect(res.status).toBe(303);
    expect(res.get('Location')).toBe('/login');
    expect(extractSid(res)).toBeUndefined();
    expect(findSidSetCookie(res)).toBeDefined();

    assertHttpEvents(
      events,
      res,
      { method: 'GET', route: '/cuenta' },
      [
        { type: 'session.expired', reason: 'absolute_timeout' },
        { type: 'authz.denied', reason: 'no_session' },
      ],
    );
    expect(events[0]?.user_id).toBe(userId);
    expect(events[0]?.session_id).toBe(sessionId);

    const sessions = await readSessions();
    expect(sessions[0]?.revoked_at).not.toBeNull();
    expect(sessions[0]?.end_reason).toBe('absolute_timeout');

    const { result: secondRes, events: secondEvents } = await withNewEvents(() =>
      getPage('/cuenta', { sid }),
    );
    expect(secondRes.status).toBe(303);
    assertHttpEvents(
      secondEvents,
      secondRes,
      { method: 'GET', route: '/cuenta' },
      [{ type: 'authz.denied', reason: 'no_session' }],
    );
  });

  it('una cookie sid con valor inventado no da acceso y no emite session.expired', async () => {
    const res = await getPage('/cuenta', { sid: 'token-inventado-que-no-existe-en-la-base' });

    expect(res.status).toBe(303);
    expect(res.get('Location')).toBe('/login');
    expect(extractSid(res)).toBeUndefined();
    expect(findSidSetCookie(res)).toBeDefined();

    assertHttpEvents(
      await readAuthEvents(),
      res,
      { method: 'GET', route: '/cuenta' },
      [{ type: 'authz.denied', reason: 'no_session' }],
    );
  });

  it('guarda solo el hash SHA-256 en sessions.token_hash y nunca el token en claro', async () => {
    const { sid } = await registerAndLogin('hash@ejemplo.test', PASSWORD_VALIDA);

    const sessions = await readSessions();
    expect(sessions).toHaveLength(1);
    const session = sessions[0];
    if (!session) throw new Error('Se esperaba una fila en sessions');

    const expectedHash = createHash('sha256').update(sid).digest('hex');
    expect(session.token_hash).toBe(expectedHash);
    expect(session.token_hash).not.toBe(sid);
    expect(JSON.stringify(session)).not.toContain(sid);
  });
});

describe('garantías ante fallo de auditoría', () => {
  it('responde 503, no envía cookie sid y no crea sesión si falla INSERT INTO auth_events', async () => {
    const email = 'fallo-audit@ejemplo.test';
    await registerUser(email, PASSWORD_VALIDA);

    const { res, sid } = await withAuditWriteFailure(() => loginUser(email, PASSWORD_VALIDA));

    expect(res.status).toBe(503);
    expect(sid).toBeUndefined();
    expect(findSidSetCookie(res)).toBeUndefined();
    expect(await readSessions()).toHaveLength(0);
  });
});
