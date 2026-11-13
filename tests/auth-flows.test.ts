import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { config } from '../src/config.js';
import { identifierHash } from '../src/audit/sanitize.js';
import { closeAll, resetAuditLog, resetDb } from './helpers.js';
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
  withNewEvents,
} from './support/client.js';

const PASSWORD_VALIDA = 'nube-montana-rio-71';
const PASSWORD_NUEVA = 'bosque-lluvia-sol-84';

beforeEach(async () => {
  vi.restoreAllMocks();
  await resetDb();
  resetAuditLog();
});

afterAll(async () => {
  await closeAll();
});

describe('páginas públicas y redirección raíz', () => {
  it('GET /login y GET /registro responden 200 con formulario y no emiten eventos', async () => {
    const registroRes = await getPage('/registro');
    expect(registroRes.status).toBe(200);
    expect(registroRes.text).toMatch(/name=["']email["']/);
    expect(registroRes.text).toMatch(/name=["']password["']/);

    const loginRes = await getPage('/login');
    expect(loginRes.status).toBe(200);
    expect(loginRes.text).toMatch(/name=["']email["']/);
    expect(loginRes.text).toMatch(/name=["']password["']/);

    expect(await readAuthEvents()).toHaveLength(0);
  });

  it('GET / redirige a /login sin sesión y a /cuenta con sesión; GET /login redirige a /cuenta con sesión', async () => {
    const rootAnon = await getPage('/');
    expect(rootAnon.status).toBe(302);
    expect(rootAnon.get('Location')).toBe('/login');
    expect(await readAuthEvents()).toHaveLength(0);

    const { sid } = await registerAndLogin('raiz@ejemplo.test', PASSWORD_VALIDA);

    const { result: rootAuth, events: evRoot } = await withNewEvents(() => getPage('/', { sid }));
    expect(rootAuth.status).toBe(302);
    expect(rootAuth.get('Location')).toBe('/cuenta');
    expect(evRoot).toHaveLength(0);

    const { result: loginAuth, events: evLogin } = await withNewEvents(() => getPage('/login', { sid }));
    expect(loginAuth.status).toBe(302);
    expect(loginAuth.get('Location')).toBe('/cuenta');
    expect(evLogin).toHaveLength(0);
  });
});

describe('registro de usuarios', () => {
  it('registra correctamente, normaliza el correo, emite auth.register.success y no inicia sesión', async () => {
    const rawEmail = '  Ana.Perez@Ejemplo.Test  ';
    const res = await registerUser(rawEmail, PASSWORD_VALIDA);

    expect(res.status).toBe(303);
    expect(res.get('Location')).toBe('/login?registrado=1');
    expect(extractSid(res)).toBeUndefined();
    expect(await readSessions()).toHaveLength(0);

    const users = await readUsers();
    expect(users).toHaveLength(1);
    const user = users[0];
    if (!user) throw new Error('Se esperaba un usuario creado');
    expect(user.email).toBe('ana.perez@ejemplo.test');

    const events = assertHttpEvents(
      await readAuthEvents(),
      res,
      { method: 'POST', route: '/registro' },
      [{ type: 'auth.register.success' }],
    );
    const ev = events[0];
    if (!ev) throw new Error('Se esperaba el evento auth.register.success');
    expect(ev.user_id).toBe(user.id);
    expect(ev.identifier_hash).toBe(identifierHash(rawEmail));
  });

  it('rechaza correo inválido con 400 y auth.register.failure/invalid_input', async () => {
    const rawEmail = 'correo-invalido';
    const res = await registerUser(rawEmail, PASSWORD_VALIDA);

    expect(res.status).toBe(400);
    expect(await readUsers()).toHaveLength(0);

    const events = assertHttpEvents(
      await readAuthEvents(),
      res,
      { method: 'POST', route: '/registro' },
      [{ type: 'auth.register.failure', reason: 'invalid_input' }],
    );
    expect(events[0]?.identifier_hash).toBe(identifierHash(rawEmail));
  });

  it('rechaza contraseña débil (< 12 caracteres) con 400 y auth.register.failure/weak_password', async () => {
    const res = await registerUser('debil@ejemplo.test', 'corta123');

    expect(res.status).toBe(400);
    expect(await readUsers()).toHaveLength(0);

    assertHttpEvents(
      await readAuthEvents(),
      res,
      { method: 'POST', route: '/registro' },
      [{ type: 'auth.register.failure', reason: 'weak_password' }],
    );
  });

  it('rechaza contraseña que contiene la parte local del correo (>= 4 caracteres) con weak_password', async () => {
    const res = await registerUser('alejandro@ejemplo.test', 'clave-alejandro-99');

    expect(res.status).toBe(400);
    expect(await readUsers()).toHaveLength(0);

    assertHttpEvents(
      await readAuthEvents(),
      res,
      { method: 'POST', route: '/registro' },
      [{ type: 'auth.register.failure', reason: 'weak_password' }],
    );
  });

  it('rechaza correo repetido con 409 y auth.register.failure/email_taken apuntando al usuario existente', async () => {
    await registerUser('duplicado@ejemplo.test', PASSWORD_VALIDA);
    const users = await readUsers();
    const existing = users[0];
    if (!existing) throw new Error('Se esperaba el usuario registrado');

    const { result: dupRes, events } = await withNewEvents(() =>
      registerUser('DUPLICADO@ejemplo.test', PASSWORD_NUEVA),
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

describe('inicio de sesión', () => {
  it('inicia sesión, emite [auth.login.success, session.created] y entrega cookie sid segura', async () => {
    await registerUser('sesion@ejemplo.test', PASSWORD_VALIDA);
    const users = await readUsers();
    const user = users[0];
    if (!user) throw new Error('Se esperaba usuario');

    const { result: loginOut, events } = await withNewEvents(() =>
      loginUser('sesion@ejemplo.test', PASSWORD_VALIDA),
    );
    const { res, sid } = loginOut;

    expect(res.status).toBe(303);
    expect(res.get('Location')).toBe('/cuenta');

    expect(sid).toBeDefined();
    if (sid === undefined) throw new Error('Falta la cookie sid');
    expect(sid).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(Buffer.from(sid, 'base64url').length).toBe(32);

    const setCookie = findSidSetCookie(res);
    expect(setCookie).toBeDefined();
    expect(setCookie).toMatch(/;\s*HttpOnly\b/i);
    expect(setCookie).toMatch(/;\s*SameSite=Strict\b/i);
    expect(setCookie).toMatch(/;\s*Path=\//i);
    expect(setCookie).toMatch(new RegExp(`;\\s*Max-Age=${config.session.absoluteHours * 3600}\\b`, 'i'));
    expect(setCookie).not.toMatch(/;\s*Secure\b/i);

    const sessions = await readSessions();
    expect(sessions).toHaveLength(1);
    const session = sessions[0];
    if (!session) throw new Error('Se esperaba una sesión en la base');

    assertHttpEvents(
      events,
      res,
      { method: 'POST', route: '/login' },
      [{ type: 'auth.login.success' }, { type: 'session.created' }],
    );

    expect(events[0]?.user_id).toBe(user.id);
    expect(events[0]?.session_id).toBe(session.id);
    expect(events[1]?.user_id).toBe(user.id);
    expect(events[1]?.session_id).toBe(session.id);
  });

  it('rechaza entrada inválida en login con 400 y auth.login.failure/invalid_input', async () => {
    const { result: res, events } = await withNewEvents(() =>
      postForm('/login', { email: 'no-es-correo', password: PASSWORD_VALIDA }),
    );

    expect(res.status).toBe(400);
    assertHttpEvents(
      events,
      res,
      { method: 'POST', route: '/login' },
      [{ type: 'auth.login.failure', reason: 'invalid_input' }],
    );
  });

  it('devuelve 401 idéntico byte a byte para usuario inexistente y contraseña incorrecta sin repetir el correo', async () => {
    const unknownEmail = 'noexiste@ejemplo.test';
    const realEmail = 'real@ejemplo.test';
    await registerUser(realEmail, PASSWORD_VALIDA);
    const user = (await readUsers())[0];
    if (!user) throw new Error('Se esperaba usuario');

    const { result: unknownOut, events: evUnknown } = await withNewEvents(() =>
      loginUser(unknownEmail, PASSWORD_VALIDA),
    );
    expect(unknownOut.res.status).toBe(401);
    expect(unknownOut.sid).toBeUndefined();
    expect(unknownOut.res.text).toContain('Credenciales inválidas');
    expect(unknownOut.res.text).not.toContain(unknownEmail);

    assertHttpEvents(
      evUnknown,
      unknownOut.res,
      { method: 'POST', route: '/login' },
      [{ type: 'auth.login.failure', reason: 'unknown_user' }],
    );
    expect(evUnknown[0]?.user_id).toBeNull();

    const { result: badPassOut, events: evBadPass } = await withNewEvents(() =>
      loginUser(realEmail, 'clave-incorrecta-123'),
    );
    expect(badPassOut.res.status).toBe(401);
    expect(badPassOut.sid).toBeUndefined();
    expect(badPassOut.res.text).toBe(unknownOut.res.text);
    expect(badPassOut.res.text).not.toContain(realEmail);

    assertHttpEvents(
      evBadPass,
      badPassOut.res,
      { method: 'POST', route: '/login' },
      [{ type: 'auth.login.failure', reason: 'bad_password' }],
    );
    expect(evBadPass[0]?.user_id).toBe(user.id);
    expect(evBadPass[0]?.details).toEqual({ attempt: 1 });
  });
});

describe('autorización, cuenta y cierre de sesión', () => {
  it('GET /cuenta sin sesión redirige 303 a /login y emite authz.denied/no_session', async () => {
    const res = await getPage('/cuenta');

    expect(res.status).toBe(303);
    expect(res.get('Location')).toBe('/login');

    assertHttpEvents(
      await readAuthEvents(),
      res,
      { method: 'GET', route: '/cuenta' },
      [{ type: 'authz.denied', reason: 'no_session' }],
    );
  });

  it('POST /logout cierra la sesión, borra la cookie, emite auth.logout e invalida accesos posteriores', async () => {
    const { userId, sessionId, sid } = await registerAndLogin('salir@ejemplo.test', PASSWORD_VALIDA);

    const cuentaRes = await getPage('/cuenta', { sid });
    expect(cuentaRes.status).toBe(200);
    expect(cuentaRes.text).toContain('salir@ejemplo.test');
    expect(cuentaRes.text).toMatch(/name=["']currentPassword["']/);
    expect(cuentaRes.text).toMatch(/name=["']newPassword["']/);
    expect(cuentaRes.text).toContain('/logout');

    const { result: logoutRes, events: logoutEvents } = await withNewEvents(() =>
      postForm('/logout', {}, { sid }),
    );
    expect(logoutRes.status).toBe(303);
    expect(logoutRes.get('Location')).toBe('/login');
    expect(extractSid(logoutRes)).toBeUndefined();
    expect(findSidSetCookie(logoutRes)).toBeDefined();

    assertHttpEvents(
      logoutEvents,
      logoutRes,
      { method: 'POST', route: '/logout' },
      [{ type: 'auth.logout' }],
    );
    expect(logoutEvents[0]?.user_id).toBe(userId);
    expect(logoutEvents[0]?.session_id).toBe(sessionId);

    const sessions = await readSessions();
    expect(sessions[0]?.revoked_at).not.toBeNull();
    expect(sessions[0]?.end_reason).toBe('logout');

    const { result: afterRes, events: afterEvents } = await withNewEvents(() =>
      getPage('/cuenta', { sid }),
    );
    expect(afterRes.status).toBe(303);
    expect(afterRes.get('Location')).toBe('/login');
    assertHttpEvents(
      afterEvents,
      afterRes,
      { method: 'GET', route: '/cuenta' },
      [{ type: 'authz.denied', reason: 'no_session' }],
    );
  });
});

describe('protección CSRF (originCheck)', () => {
  it('rechaza POST sin Origin ni Referer con 403 y security.csrf.rejected/origin_missing', async () => {
    const res = await postForm(
      '/login',
      { email: 'csrf@ejemplo.test', password: PASSWORD_VALIDA },
      { origin: null },
    );

    expect(res.status).toBe(403);
    assertHttpEvents(
      await readAuthEvents(),
      res,
      { method: 'POST', route: '/login' },
      [{ type: 'security.csrf.rejected', reason: 'origin_missing' }],
    );
  });

  it('rechaza POST con Origin ajeno con 403 y security.csrf.rejected/origin_mismatch', async () => {
    const res = await postForm(
      '/login',
      { email: 'csrf@ejemplo.test', password: PASSWORD_VALIDA },
      { origin: 'https://atacante.ejemplo' },
    );

    expect(res.status).toBe(403);
    assertHttpEvents(
      await readAuthEvents(),
      res,
      { method: 'POST', route: '/login' },
      [{ type: 'security.csrf.rejected', reason: 'origin_mismatch' }],
    );
  });

  it('GET /login envía Referrer-Policy: same-origin para que el navegador mande Origin real', async () => {
    const res = await getPage('/login');

    expect(res.get('Referrer-Policy')).toBe('same-origin');
  });

  it('rechaza POST con Origin "null" (texto literal) con 403 y security.csrf.rejected/origin_mismatch', async () => {
    const res = await postForm(
      '/login',
      { email: 'csrf@ejemplo.test', password: PASSWORD_VALIDA },
      { origin: 'null' },
    );

    expect(res.status).toBe(403);
    assertHttpEvents(
      await readAuthEvents(),
      res,
      { method: 'POST', route: '/login' },
      [{ type: 'security.csrf.rejected', reason: 'origin_mismatch' }],
    );
  });

  it('acepta POST sin Origin cuando Referer coincide con appOrigin', async () => {
    const res = await postForm(
      '/login',
      { email: 'noexiste@ejemplo.test', password: PASSWORD_VALIDA },
      { origin: null, referer: `${config.appOrigin}/login` },
    );

    expect(res.status).toBe(401);
    assertHttpEvents(
      await readAuthEvents(),
      res,
      { method: 'POST', route: '/login' },
      [{ type: 'auth.login.failure', reason: 'unknown_user' }],
    );
  });
});

describe('cambio de contraseña', () => {
  it('rechaza contraseña actual incorrecta y nueva contraseña débil o inválida', async () => {
    const { userId, sessionId, sid } = await registerAndLogin('cambio@ejemplo.test', PASSWORD_VALIDA);

    const { result: badCurrent, events: evBadCurrent } = await withNewEvents(() =>
      postForm(
        '/cuenta/password',
        { currentPassword: 'clave-actual-equivocada', newPassword: PASSWORD_NUEVA },
        { sid },
      ),
    );
    expect(badCurrent.status).toBe(400);
    assertHttpEvents(
      evBadCurrent,
      badCurrent,
      { method: 'POST', route: '/cuenta/password' },
      [{ type: 'auth.password.change.failure', reason: 'bad_current_password' }],
    );
    expect(evBadCurrent[0]?.user_id).toBe(userId);
    expect(evBadCurrent[0]?.session_id).toBe(sessionId);

    const { result: weakNew, events: evWeak } = await withNewEvents(() =>
      postForm(
        '/cuenta/password',
        { currentPassword: PASSWORD_VALIDA, newPassword: 'corta123' },
        { sid },
      ),
    );
    expect(weakNew.status).toBe(400);
    assertHttpEvents(
      evWeak,
      weakNew,
      { method: 'POST', route: '/cuenta/password' },
      [{ type: 'auth.password.change.failure', reason: 'weak_password' }],
    );
    expect(evWeak[0]?.user_id).toBe(userId);
    expect(evWeak[0]?.session_id).toBe(sessionId);

    const { result: invalidRes, events: evInvalid } = await withNewEvents(() =>
      postForm('/cuenta/password', { currentPassword: PASSWORD_VALIDA }, { sid }),
    );
    expect(invalidRes.status).toBe(400);
    assertHttpEvents(
      evInvalid,
      invalidRes,
      { method: 'POST', route: '/cuenta/password' },
      [{ type: 'auth.password.change.failure', reason: 'invalid_input' }],
    );
  });

  it('cambia contraseña, revoca otras sesiones emitiendo session.revoked/password_change y mantiene la actual', async () => {
    const email = 'multisesion@ejemplo.test';
    const { userId, sessionId: currentSessionId, sid: currentSid } = await registerAndLogin(
      email,
      PASSWORD_VALIDA,
    );

    const { res: otherLoginRes, sid: otherSid } = await loginUser(email, PASSWORD_VALIDA);
    expect(otherLoginRes.status).toBe(303);
    if (otherSid === undefined) throw new Error('Se esperaba cookie sid para la segunda sesión');

    const sessionsBefore = await readSessions();
    const otherSession = sessionsBefore.find((s) => s.id !== currentSessionId);
    if (!otherSession) throw new Error('Se esperaba la segunda sesión en base');

    const { result: changeRes, events: changeEvents } = await withNewEvents(() =>
      postForm(
        '/cuenta/password',
        { currentPassword: PASSWORD_VALIDA, newPassword: PASSWORD_NUEVA },
        { sid: currentSid },
      ),
    );

    expect(changeRes.status).toBe(303);
    expect(changeRes.get('Location')).toBe('/cuenta?cambiada=1');

    assertHttpEvents(
      changeEvents,
      changeRes,
      { method: 'POST', route: '/cuenta/password' },
      [
        { type: 'auth.password.change.success' },
        { type: 'session.revoked', reason: 'password_change' },
      ],
    );
    expect(changeEvents[0]?.user_id).toBe(userId);
    expect(changeEvents[0]?.session_id).toBe(currentSessionId);
    expect(changeEvents[1]?.user_id).toBe(userId);
    expect(changeEvents[1]?.session_id).toBe(otherSession.id);

    const sessionsAfter = await readSessions();
    const revokedOther = sessionsAfter.find((s) => s.id === otherSession.id);
    const activeCurrent = sessionsAfter.find((s) => s.id === currentSessionId);
    expect(revokedOther?.revoked_at).not.toBeNull();
    expect(revokedOther?.end_reason).toBe('password_change');
    expect(activeCurrent?.revoked_at).toBeNull();

    // La otra sesión ya no sirve; la actual sigue activa.
    const otherCuenta = await getPage('/cuenta', { sid: otherSid });
    expect(otherCuenta.status).toBe(303);
    expect(otherCuenta.get('Location')).toBe('/login');

    const currentCuenta = await getPage('/cuenta', { sid: currentSid });
    expect(currentCuenta.status).toBe(200);

    // La contraseña vieja deja de funcionar y la nueva entra.
    const { result: oldPassOut, events: oldPassEvents } = await withNewEvents(() =>
      loginUser(email, PASSWORD_VALIDA),
    );
    expect(oldPassOut.res.status).toBe(401);
    assertHttpEvents(
      oldPassEvents,
      oldPassOut.res,
      { method: 'POST', route: '/login' },
      [{ type: 'auth.login.failure', reason: 'bad_password' }],
    );

    const { res: newPassRes, sid: newSid } = await loginUser(email, PASSWORD_NUEVA);
    expect(newPassRes.status).toBe(303);
    expect(newPassRes.get('Location')).toBe('/cuenta');
    expect(newSid).toBeDefined();
  });
});
