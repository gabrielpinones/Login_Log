import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { config } from '../src/config.js';
import { identifierHash } from '../src/audit/sanitize.js';
import { adminPool, closeAll, resetAuditLog, resetDb } from './helpers.js';
import {
  assertHttpEvents,
  loginUser,
  readSessions,
  readUsers,
  registerUser,
  withNewEvents,
} from './support/client.js';

const PASSWORD_VALIDA = 'nube-montana-rio-71';
const PASSWORD_ERRONEA = 'clave-erronea-para-bloqueo';

beforeEach(async () => {
  vi.restoreAllMocks();
  await resetDb();
  resetAuditLog();
});

afterAll(async () => {
  await closeAll();
});

describe('bloqueo de cuenta por intentos fallidos', () => {
  it('bloquea al alcanzar lockout.threshold fallos y rechaza la contraseña correcta con el mismo 401', async () => {
    const email = 'bloqueo@ejemplo.test';
    await registerUser(email, PASSWORD_VALIDA);
    const user = (await readUsers())[0];
    if (!user) throw new Error('Se esperaba el usuario');

    let body401: string | undefined;

    for (let attempt = 1; attempt <= config.lockout.threshold; attempt++) {
      const { result: out, events } = await withNewEvents(() => loginUser(email, PASSWORD_ERRONEA));
      expect(out.res.status).toBe(401);
      expect(out.sid).toBeUndefined();
      body401 ??= out.res.text;
      expect(out.res.text).toBe(body401);

      if (attempt < config.lockout.threshold) {
        assertHttpEvents(
          events,
          out.res,
          { method: 'POST', route: '/login' },
          [{ type: 'auth.login.failure', reason: 'bad_password' }],
        );
        expect(events[0]?.user_id).toBe(user.id);
        expect(events[0]?.details).toEqual({ attempt });
      } else {
        assertHttpEvents(
          events,
          out.res,
          { method: 'POST', route: '/login' },
          [
            { type: 'auth.login.failure', reason: 'bad_password' },
            { type: 'auth.account.locked' },
          ],
        );
        expect(events[0]?.user_id).toBe(user.id);
        expect(events[0]?.details).toEqual({ attempt });

        const lockEv = events[1];
        if (!lockEv) throw new Error('Se esperaba el evento auth.account.locked');
        expect(lockEv.user_id).toBe(user.id);
        expect(lockEv.details.failed_attempts).toBe(attempt);
        expect(typeof lockEv.details.locked_until).toBe('string');
        expect(new Date(String(lockEv.details.locked_until)).getTime()).toBeGreaterThan(Date.now());
      }
    }

    const { result: blockedOut, events: blockedEvents } = await withNewEvents(() =>
      loginUser(email, PASSWORD_VALIDA),
    );
    expect(blockedOut.res.status).toBe(401);
    expect(blockedOut.res.text).toBe(body401);
    expect(blockedOut.sid).toBeUndefined();
    expect(await readSessions()).toHaveLength(0);

    assertHttpEvents(
      blockedEvents,
      blockedOut.res,
      { method: 'POST', route: '/login' },
      [{ type: 'auth.login.failure', reason: 'account_locked' }],
    );
    expect(blockedEvents[0]?.user_id).toBe(user.id);
    expect(blockedEvents[0]?.identifier_hash).toBe(identifierHash(email));

    const userAfter = (await readUsers())[0];
    expect(userAfter?.failed_attempts).toBe(config.lockout.threshold);
    expect(userAfter?.locked_until).not.toBeNull();
  });

  it('desbloquea al vencer locked_until y permite entrar con contraseña correcta', async () => {
    const email = 'vencido@ejemplo.test';
    await registerUser(email, PASSWORD_VALIDA);
    const user = (await readUsers())[0];
    if (!user) throw new Error('Se esperaba el usuario');

    for (let i = 0; i < config.lockout.threshold; i++) {
      await loginUser(email, PASSWORD_ERRONEA);
    }

    await adminPool.query("UPDATE users SET locked_until = now() - interval '1 minute' WHERE id = $1", [
      user.id,
    ]);

    const { result: okOut, events } = await withNewEvents(() => loginUser(email, PASSWORD_VALIDA));
    expect(okOut.res.status).toBe(303);
    expect(okOut.res.get('Location')).toBe('/cuenta');
    expect(okOut.sid).toBeDefined();

    assertHttpEvents(
      events,
      okOut.res,
      { method: 'POST', route: '/login' },
      [
        { type: 'auth.account.unlocked' },
        { type: 'auth.login.success' },
        { type: 'session.created' },
      ],
    );
    expect(events[0]?.user_id).toBe(user.id);
    expect(events[0]?.details).toEqual({ cause: 'lock_expired' });

    const userAfter = (await readUsers())[0];
    expect(userAfter?.failed_attempts).toBe(0);
    expect(userAfter?.locked_until).toBeNull();
  });

  it('un login correcto antes del umbral reinicia failed_attempts a 0', async () => {
    const email = 'reinicio@ejemplo.test';
    await registerUser(email, PASSWORD_VALIDA);

    const preFailures = Math.max(1, config.lockout.threshold - 1);
    for (let i = 0; i < preFailures; i++) {
      const { res } = await loginUser(email, PASSWORD_ERRONEA);
      expect(res.status).toBe(401);
    }

    const { res: okRes } = await loginUser(email, PASSWORD_VALIDA);
    expect(okRes.status).toBe(303);

    const userAfterOk = (await readUsers())[0];
    expect(userAfterOk?.failed_attempts).toBe(0);

    // Un nuevo fallo después del login correcto empieza de nuevo en attempt = 1.
    if (config.lockout.threshold > 1) {
      const { result: nextFail, events } = await withNewEvents(() => loginUser(email, PASSWORD_ERRONEA));
      expect(nextFail.res.status).toBe(401);
      assertHttpEvents(
        events,
        nextFail.res,
        { method: 'POST', route: '/login' },
        [{ type: 'auth.login.failure', reason: 'bad_password' }],
      );
      expect(events[0]?.details).toEqual({ attempt: 1 });
    }
  });
});

describe('límite de intentos por IP', () => {
  it('responde 429 tras ipRateLimit.max fallos y emite auth.ratelimit.triggered solo la primera vez', async () => {
    for (let i = 0; i < config.ipRateLimit.max; i++) {
      const { result: failOut, events } = await withNewEvents(() =>
        loginUser(`inexistente-${i}@ejemplo.test`, PASSWORD_ERRONEA),
      );
      expect(failOut.res.status).toBe(401);
      assertHttpEvents(
        events,
        failOut.res,
        { method: 'POST', route: '/login' },
        [{ type: 'auth.login.failure', reason: 'unknown_user' }],
      );
    }

    const { result: first429, events: first429Events } = await withNewEvents(() =>
      loginUser('otro-inexistente@ejemplo.test', PASSWORD_ERRONEA),
    );
    expect(first429.res.status).toBe(429);
    expect(first429.sid).toBeUndefined();
    assertHttpEvents(
      first429Events,
      first429.res,
      { method: 'POST', route: '/login' },
      [
        { type: 'auth.ratelimit.triggered' },
        { type: 'auth.login.failure', reason: 'rate_limited' },
      ],
    );

    const { result: second429, events: second429Events } = await withNewEvents(() =>
      loginUser('aun-otro@ejemplo.test', PASSWORD_ERRONEA),
    );
    expect(second429.res.status).toBe(429);
    expect(second429.sid).toBeUndefined();
    assertHttpEvents(
      second429Events,
      second429.res,
      { method: 'POST', route: '/login' },
      [{ type: 'auth.login.failure', reason: 'rate_limited' }],
    );
  });
});
