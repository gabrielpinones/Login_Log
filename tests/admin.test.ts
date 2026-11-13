import request from 'supertest';
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { adminPool, closeAll, resetAuditLog, resetDb } from './helpers.js';
import {
  app,
  assertHttpEvents,
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

const PASSWORD = 'nube-montana-rio-71';

beforeEach(async () => {
  vi.restoreAllMocks();
  await resetDb();
  resetAuditLog();
});

afterAll(async () => {
  await closeAll();
});

// El rol se cambia antes de iniciar sesión: así la sesión nace ya con el rol admin.
async function crearAdmin(email = 'admin@ejemplo.test'): Promise<{ userId: string; sessionId: string; sid: string }> {
  const registro = await registerUser(email, PASSWORD);
  expect(registro.status).toBe(303);
  await adminPool.query("UPDATE users SET role = 'admin' WHERE email = $1", [email]);

  const { res, sid } = await loginUser(email, PASSWORD);
  expect(res.status).toBe(303);
  if (sid === undefined) throw new Error('Se esperaba cookie sid del administrador');

  const user = (await readUsers()).find((u) => u.email === email);
  if (!user) throw new Error('Se esperaba el usuario administrador');
  const session = (await readSessions()).find((s) => s.user_id === user.id);
  if (!session) throw new Error('Se esperaba la sesión del administrador');
  return { userId: user.id, sessionId: session.id, sid };
}

interface Fila {
  seq: number;
  tipo: string;
  resultado: string;
}

function filas(html: string): Fila[] {
  return [...html.matchAll(/<tr data-seq="(\d+)" data-tipo="([^"]+)" data-resultado="([^"]+)">/g)].map((m) => ({
    seq: Number(m[1]),
    tipo: m[2] ?? '',
    resultado: m[3] ?? '',
  }));
}

function enlaceAnterior(html: string): string | null {
  const href = /href="([^"]*antes=[^"]*)"/.exec(html)?.[1];
  return href === undefined ? null : href.replaceAll('&amp;', '&');
}

describe('acceso al visor', () => {
  it('sin sesión redirige 303 a /login y emite authz.denied/no_session', async () => {
    const { result: res, events } = await withNewEvents(() => getPage('/admin/logs'));

    expect(res.status).toBe(303);
    expect(res.get('Location')).toBe('/login');
    assertHttpEvents(events, res, { method: 'GET', route: '/admin/logs' }, [
      { type: 'authz.denied', reason: 'no_session' },
    ]);
  });

  it('un usuario sin rol admin recibe 403 y authz.denied/insufficient_role con su userId', async () => {
    const { userId, sessionId, sid } = await registerAndLogin('normal@ejemplo.test', PASSWORD);

    const { result: res, events } = await withNewEvents(() => getPage('/admin/logs', { sid }));

    expect(res.status).toBe(403);
    expect(res.text).not.toContain('<table');
    assertHttpEvents(events, res, { method: 'GET', route: '/admin/logs' }, [
      { type: 'authz.denied', reason: 'insufficient_role' },
    ]);
    expect(events[0]?.user_id).toBe(userId);
    expect(events[0]?.session_id).toBe(sessionId);
  });
});

describe('listado y auditoría de la consulta', () => {
  it('el admin ve los eventos existentes, el estado de la cadena y deja audit.log.viewed', async () => {
    const { userId, sessionId, sid } = await crearAdmin();
    await postForm('/login', { email: 'noexiste@ejemplo.test', password: PASSWORD });
    const previos = await readAuthEvents();

    const { result: res, events } = await withNewEvents(() => getPage('/admin/logs', { sid }));

    expect(res.status).toBe(200);
    expect(res.get('Cache-Control')).toBe('no-store');
    expect(res.text).toContain('<title>Registro de auditoría - Login Log</title>');
    expect(res.text).toContain('auth.login.failure');
    expect(res.text).toContain('auth.login.success');
    expect(res.text).toMatch(/<time datetime="\d{4}-\d{2}-\d{2}T[\d:.]+Z">/);
    expect(res.text).toContain('<details');
    expect(res.text).toContain(`Cadena íntegra: ${previos.length} eventos verificados.`);
    expect(res.text).not.toContain('role="alert"');
    expect(filas(res.text)).toHaveLength(previos.length);

    assertHttpEvents(events, res, { method: 'GET', route: '/admin/logs' }, [{ type: 'audit.log.viewed' }]);
    expect(events[0]?.user_id).toBe(userId);
    expect(events[0]?.session_id).toBe(sessionId);
    expect(events[0]?.details).toEqual({ result_count: previos.length });
  });

  it('muestra el estado vacío con enlace para limpiar filtros y registra result_count 0', async () => {
    const { sid } = await crearAdmin();

    const { result: res, events } = await withNewEvents(() => getPage('/admin/logs?desde=2999-01-01', { sid }));

    expect(res.status).toBe(200);
    expect(filas(res.text)).toHaveLength(0);
    expect(res.text).not.toContain('<table');
    expect(res.text).toContain('No hay eventos de auditoría para los filtros indicados.');
    expect(res.text).toMatch(/<a href="\/admin\/logs">Limpiar filtros<\/a>/);
    expect(events[0]?.details).toEqual({ desde: '2999-01-01', result_count: 0 });
  });
});

describe('filtros', () => {
  it('filtra por tipo y registra los filtros usados', async () => {
    const { sid } = await crearAdmin();
    await postForm('/login', { email: 'noexiste@ejemplo.test', password: PASSWORD });
    const esperados = (await readAuthEvents()).filter((e) => e.event_type === 'auth.login.failure');
    expect(esperados.length).toBeGreaterThan(0);

    const { result: res, events } = await withNewEvents(() =>
      getPage('/admin/logs?type=auth.login.failure&outcome=failure', { sid }),
    );

    expect(res.status).toBe(200);
    const vistas = filas(res.text);
    expect(vistas).toHaveLength(esperados.length);
    expect(vistas.every((f) => f.tipo === 'auth.login.failure')).toBe(true);
    expect(res.text).toContain(
      'href="/admin/logs?type=auth.login.failure&amp;outcome=failure&amp;verificar=1">Verificar ahora</a>',
    );
    expect(events[0]?.details).toEqual({
      type: 'auth.login.failure',
      outcome: 'failure',
      result_count: esperados.length,
    });
  });

  it('filtra por resultado', async () => {
    const { sid } = await crearAdmin();
    await postForm('/login', { email: 'noexiste@ejemplo.test', password: PASSWORD });
    const todos = await readAuthEvents();

    for (const outcome of ['success', 'failure'] as const) {
      const esperados = todos.filter((e) => e.outcome === outcome);
      expect(esperados.length).toBeGreaterThan(0);
      const res = await getPage(`/admin/logs?outcome=${outcome}`, { sid });
      expect(res.status).toBe(200);
      // audit.log.viewed (éxito) se escribe después de la consulta, así que no entra en su propia respuesta.
      const vistas = filas(res.text);
      expect(vistas).toHaveLength(esperados.length);
      expect(vistas.every((f) => f.resultado === outcome)).toBe(true);
    }
  });

  it('filtra por usuario, por IP y por fechas', async () => {
    const { sid } = await crearAdmin();
    const otro = await registerAndLogin('otro@ejemplo.test', PASSWORD);
    const todos = await readAuthEvents();

    const deOtro = todos.filter((e) => e.user_id === otro.userId);
    const porUsuario = await getPage(`/admin/logs?user=${otro.userId}`, { sid });
    expect(porUsuario.status).toBe(200);
    expect(filas(porUsuario.text)).toHaveLength(deOtro.length);

    const ip = todos[0]?.source_ip;
    if (!ip) throw new Error('Se esperaba una IP registrada');
    // Se relee: la consulta anterior ya dejó su propio audit.log.viewed con la misma IP.
    const deIp = (await readAuthEvents()).filter((e) => e.source_ip === ip);
    const porIp = await getPage(`/admin/logs?ip=${encodeURIComponent(ip)}`, { sid });
    expect(porIp.status).toBe(200);
    expect(filas(porIp.text)).toHaveLength(deIp.length);

    const otraIp = await getPage('/admin/logs?ip=192.0.2.1', { sid });
    expect(otraIp.status).toBe(200);
    expect(filas(otraIp.text)).toHaveLength(0);

    // Una fecha sola en "hasta" incluye el día completo; la fecha y hora usa UTC.
    const hoy = new Date().toISOString().slice(0, 10);
    const delDia = await getPage(`/admin/logs?desde=${hoy}&hasta=${hoy}`, { sid });
    expect(delDia.status).toBe(200);
    expect(filas(delDia.text).length).toBeGreaterThanOrEqual(todos.length);

    const conHora = await getPage('/admin/logs?desde=2000-01-01T00:00&hasta=2000-01-01T23:59', { sid });
    expect(conHora.status).toBe(200);
    expect(filas(conHora.text)).toHaveLength(0);
  });

  it.each([
    'type=no.existe',
    'outcome=quizas',
    'user=abc',
    'ip=999.1.1.1',
    'desde=ayer',
    'hasta=2026-02-31',
    'desde=2026-05-01T10:30%2B02:00',
    'antes=0',
    'antes=-3',
    'antes=1.5',
    'verificar=0',
    'verificar=si',
    'verificar=1&verificar=1',
    'type=auth.logout&type=auth.login.success',
  ])('un filtro inválido (%s) responde 400 con formulario y alerta, sin tabla ni audit.log.viewed', async (query) => {
    const { sid } = await crearAdmin();

    const { result: res, events } = await withNewEvents(() => getPage(`/admin/logs?${query}`, { sid }));

    expect(res.status).toBe(400);
    expect(res.text).toContain('<form');
    expect(res.text).toMatch(/<p class="aviso aviso-error" role="alert">Revisa los filtros: /);
    expect(res.text).not.toContain('<table');
    expect(events).toHaveLength(0);
  });
});

describe('paginación', () => {
  it('con más de 50 eventos ofrece "Eventos anteriores" conservando filtros y la segunda página trae el resto', async () => {
    const { sid } = await crearAdmin();
    for (let i = 0; i < 55; i += 1) {
      await getPage('/cuenta');
    }

    const primera = await getPage('/admin/logs?type=authz.denied', { sid });
    expect(primera.status).toBe(200);
    const filasPrimera = filas(primera.text);
    expect(filasPrimera).toHaveLength(50);
    const seqs = filasPrimera.map((f) => f.seq);
    expect(seqs).toEqual([...seqs].sort((a, b) => b - a));

    const enlace = enlaceAnterior(primera.text);
    if (enlace === null) throw new Error('Se esperaba el enlace a eventos anteriores');
    expect(enlace).toContain('type=authz.denied');
    expect(enlace).toContain('antes=');
    expect(primera.text).toContain('Eventos anteriores');

    const segunda = await getPage(enlace, { sid });
    expect(segunda.status).toBe(200);
    const filasSegunda = filas(segunda.text);
    expect(filasSegunda).toHaveLength(5);
    expect(filasSegunda.every((f) => f.tipo === 'authz.denied' && f.seq < Math.min(...seqs))).toBe(true);
    expect(enlaceAnterior(segunda.text)).toBeNull();
    expect(new Set([...seqs, ...filasSegunda.map((f) => f.seq)]).size).toBe(55);
  });

  it('con 50 eventos o menos no muestra el enlace', async () => {
    const { sid } = await crearAdmin();
    const res = await getPage('/admin/logs', { sid });
    expect(res.status).toBe(200);
    expect(enlaceAnterior(res.text)).toBeNull();
    expect(res.text).not.toContain('Eventos anteriores');
  });
});

describe('seguridad de la salida', () => {
  it('escapa el user agent controlado por el cliente', async () => {
    const { sid } = await crearAdmin();
    const agente = '<script>alert(1)</script>';
    await request(app).get('/cuenta').set('User-Agent', agente);

    const res = await getPage('/admin/logs', { sid });

    expect(res.status).toBe(200);
    expect(res.text).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
    expect(res.text).not.toContain(agente);
  });

  it('avisa de cadena rota con role="alert" cuando se altera un evento', async () => {
    const { sid } = await crearAdmin();

    const cliente = await adminPool.connect();
    try {
      await cliente.query('BEGIN');
      await cliente.query('SET LOCAL session_replication_role = replica');
      const r = await cliente.query('UPDATE auth_events SET http_status = 999 WHERE seq = 2');
      await cliente.query('COMMIT');
      expect(r.rowCount).toBe(1);
    } catch (err) {
      await cliente.query('ROLLBACK');
      throw err;
    } finally {
      cliente.release();
    }

    const res = await getPage('/admin/logs?verificar=1', { sid });

    expect(res.status).toBe(200);
    expect(res.text).toMatch(/<p class="aviso aviso-error" role="alert">Cadena rota en el seq 2: [^<]*\(hash_mismatch\)\.<\/p>/);
    expect(res.text).not.toContain('Cadena íntegra');
    expect(filas(res.text).length).toBeGreaterThan(0);
  });

  it('la segunda carga dentro de la ventana reutiliza el resultado en memoria salvo con verificar=1', async () => {
    const { sid } = await crearAdmin();

    const primera = await getPage('/admin/logs?verificar=1', { sid });
    expect(primera.status).toBe(200);
    expect(primera.text).toContain('Cadena íntegra:');
    expect(primera.text).toContain('href="/admin/logs?verificar=1">Verificar ahora</a>');

    const cliente = await adminPool.connect();
    try {
      await cliente.query('BEGIN');
      await cliente.query('SET LOCAL session_replication_role = replica');
      await cliente.query('UPDATE auth_events SET http_status = 999 WHERE seq = 2');
      await cliente.query('COMMIT');
    } catch (err) {
      await cliente.query('ROLLBACK');
      throw err;
    } finally {
      cliente.release();
    }

    const segunda = await getPage('/admin/logs', { sid });
    expect(segunda.status).toBe(200);
    expect(segunda.text).toContain('Cadena íntegra:');
    expect(segunda.text).not.toContain('role="alert"');

    const forzada = await getPage('/admin/logs?verificar=1', { sid });
    expect(forzada.status).toBe(200);
    expect(forzada.text).toMatch(
      /<p class="aviso aviso-error" role="alert">Cadena rota en el seq 2: [^<]*\(hash_mismatch\)\.<\/p>/,
    );
  });
});

describe('navegación', () => {
  it('la página de cuenta muestra el enlace al visor solo para admin', async () => {
    const { sid: sidAdmin } = await crearAdmin();
    const admin = await getPage('/cuenta', { sid: sidAdmin });
    expect(admin.status).toBe(200);
    expect(admin.text).toContain('href="/admin/logs"');
    expect(admin.text).toContain('action="/logout"');

    const { sid: sidNormal } = await registerAndLogin('normal@ejemplo.test', PASSWORD);
    const normal = await getPage('/cuenta', { sid: sidNormal });
    expect(normal.status).toBe(200);
    expect(normal.text).not.toContain('/admin/logs');
    expect(normal.text).toContain('href="/cuenta"');
    expect(normal.text).toContain('action="/logout"');
  });

  it('sin sesión la cabecera ofrece iniciar sesión y crear cuenta, sin enlaces privados', async () => {
    const res = await getPage('/login');

    expect(res.status).toBe(200);
    expect(res.text).toContain('href="/login"');
    expect(res.text).toContain('href="/registro"');
    expect(res.text).not.toContain('/admin/logs');
    expect(res.text).not.toContain('action="/logout"');
    expect(res.text).toContain('href="#contenido"');
  });
});
