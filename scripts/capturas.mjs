import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const TIMEOUT_MS = 15_000;
// Umbral por defecto definido en src/config.ts (LOCKOUT_THRESHOLD = 5).
const LOCKOUT_THRESHOLD = 5;

const REQUIRED_ENV = ['ADMIN_EMAIL', 'ADMIN_PASSWORD', 'DEMO_PASSWORD', 'DEMO_PASSWORD_2'];
const faltantes = REQUIRED_ENV.filter((k) => !process.env[k] || process.env[k].trim() === '');
if (faltantes.length > 0) {
  process.stderr.write(
    `Error: faltan variables de entorno obligatorias: ${faltantes.join(', ')}\n`,
  );
  process.exit(1);
}

const { ADMIN_EMAIL, ADMIN_PASSWORD, DEMO_PASSWORD, DEMO_PASSWORD_2 } = process.env;
const BASE_URL = (process.env.BASE_URL?.trim() || 'http://localhost:3000').replace(/\/+$/, '');
const CAPTURAS_DIR = path.resolve(import.meta.dirname, '..', 'docs', 'capturas');

function resolverBinarioChromium() {
  const desdeEnv = process.env.CHROME_BIN?.trim();
  if (desdeEnv) {
    if (!fs.existsSync(desdeEnv)) {
      throw new Error(`CHROME_BIN apunta a una ruta que no existe: ${desdeEnv}`);
    }
    return desdeEnv;
  }

  const base = path.join(os.homedir(), '.cache', 'ms-playwright', 'chromium_headless_shell-1248');
  const candidatos = [
    path.join(base, 'chrome-headless-shell-linux64', 'chrome-headless-shell'),
    path.join(base, 'chrome-headless-shell-linux64', 'headless_shell'),
    path.join(base, 'chrome-linux', 'headless_shell'),
    path.join(base, 'chrome-linux', 'chrome'),
    path.join(base, 'chrome-linux', 'chrome-headless-shell'),
  ];

  for (const ruta of candidatos) {
    if (fs.existsSync(ruta)) {
      return ruta;
    }
  }

  throw new Error(
    `No se encontró el ejecutable de Chromium bajo ${base}. Define CHROME_BIN con la ruta al binario.`,
  );
}

function conTimeout(promesa, ms, descripcion) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      reject(new Error(`Tiempo agotado (${ms} ms) esperando: ${descripcion}`));
    }, ms);
  });
  return Promise.race([promesa, timeout]).finally(() => clearTimeout(timer));
}

function lanzarChromium(binario, userDataDir) {
  const args = [
    '--headless',
    '--remote-debugging-port=0',
    `--user-data-dir=${userDataDir}`,
    '--no-first-run',
    '--hide-scrollbars',
  ];

  const proc = spawn(binario, args, {
    stdio: ['ignore', 'ignore', 'pipe'],
  });

  const wsUrlPromise = new Promise((resolve, reject) => {
    let stderrAcumulado = '';

    const onData = (chunk) => {
      stderrAcumulado += chunk.toString('utf8');
      const match = stderrAcumulado.match(/DevTools listening on (ws:\/\/[^\s]+)/);
      if (match) {
        limpiar();
        resolve(match[1]);
      }
    };

    const onError = (err) => {
      limpiar();
      reject(new Error(`No se pudo iniciar Chromium (${binario}): ${err.message}`));
    };

    const onExit = (code, signal) => {
      limpiar();
      reject(
        new Error(
          `Chromium terminó antes de abrir DevTools (código=${code}, señal=${signal}). Stderr:\n${stderrAcumulado}`,
        ),
      );
    };

    function limpiar() {
      proc.stderr.off('data', onData);
      proc.off('error', onError);
      proc.off('exit', onExit);
    }

    proc.stderr.on('data', onData);
    proc.on('error', onError);
    proc.on('exit', onExit);
  });

  return {
    proc,
    wsUrlPromise: conTimeout(wsUrlPromise, TIMEOUT_MS, 'arranque de DevTools en stderr'),
  };
}

class CdpClient {
  constructor(ws) {
    this.ws = ws;
    this.nextId = 1;
    this.pendientes = new Map();
    this.listeners = new Set();

    ws.addEventListener('message', (event) => {
      const texto = typeof event.data === 'string' ? event.data : Buffer.from(event.data).toString('utf8');
      const msg = JSON.parse(texto);

      if (msg.id !== undefined) {
        const entrada = this.pendientes.get(msg.id);
        if (!entrada) return;
        this.pendientes.delete(msg.id);
        if (msg.error) {
          entrada.reject(new Error(`CDP ${entrada.method}: ${msg.error.message}`));
        } else {
          entrada.resolve(msg.result);
        }
        return;
      }

      if (msg.method) {
        for (const listener of [...this.listeners]) {
          listener(msg);
        }
      }
    });

    ws.addEventListener('close', () => {
      for (const [, entrada] of this.pendientes) {
        entrada.reject(new Error(`Conexión WebSocket cerrada durante ${entrada.method}`));
      }
      this.pendientes.clear();
    });
  }

  static async conectar(wsUrl) {
    const ws = new WebSocket(wsUrl);
    await conTimeout(
      new Promise((resolve, reject) => {
        ws.addEventListener('open', () => resolve(), { once: true });
        ws.addEventListener('error', (e) => reject(new Error(`Error de WebSocket CDP: ${e.message ?? 'desconocido'}`)), {
          once: true,
        });
      }),
      TIMEOUT_MS,
      `conexión WebSocket a ${wsUrl}`,
    );
    return new CdpClient(ws);
  }

  send(method, params = {}, sessionId = undefined) {
    const id = this.nextId++;
    const payload = sessionId ? { id, method, params, sessionId } : { id, method, params };
    const promesa = new Promise((resolve, reject) => {
      this.pendientes.set(id, { method, resolve, reject });
      this.ws.send(JSON.stringify(payload));
    });
    return conTimeout(promesa, TIMEOUT_MS, `comando CDP ${method}`);
  }

  onEvent(fn) {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  waitForEvent(method, sessionId, predicate = () => true) {
    const promesa = new Promise((resolve) => {
      const off = this.onEvent((msg) => {
        if (msg.method === method && msg.sessionId === sessionId && predicate(msg.params)) {
          off();
          resolve(msg.params);
        }
      });
    });
    return conTimeout(promesa, TIMEOUT_MS, `evento CDP ${method}`);
  }

   cerrar() {
    try {
      this.ws.close();
    } catch {
      // Ignorar si ya está cerrado.
    }
  }
}

class ActorSession {
  constructor(cdp, browserContextId, targetId, sessionId) {
    this.cdp = cdp;
    this.browserContextId = browserContextId;
    this.targetId = targetId;
    this.sessionId = sessionId;
    this.ultimoEstadoDoc = null;

    this.offNetwork = cdp.onEvent((msg) => {
      if (
        msg.sessionId === sessionId &&
        msg.method === 'Network.responseReceived' &&
        msg.params?.type === 'Document'
      ) {
        this.ultimoEstadoDoc = msg.params.response?.status ?? null;
      }
    });
  }

  static async crear(cdp) {
    const { browserContextId } = await cdp.send('Target.createBrowserContext');
    const { targetId } = await cdp.send('Target.createTarget', {
      url: 'about:blank',
      browserContextId,
    });
    const { sessionId } = await cdp.send('Target.attachToTarget', {
      targetId,
      flatten: true,
    });

    await cdp.send('Page.enable', {}, sessionId);
    await cdp.send('Runtime.enable', {}, sessionId);
    await cdp.send('Network.enable', {}, sessionId);

    const sesion = new ActorSession(cdp, browserContextId, targetId, sessionId);
    await sesion.configurarVista({ width: 1280, height: 800, deviceScaleFactor: 1, scheme: 'light' });
    return sesion;
  }

  async configurarVista({ width = 1280, height = 800, deviceScaleFactor = 1, scheme = 'light' }) {
    await this.cdp.send(
      'Emulation.setEmulatedMedia',
      {
        features: [{ name: 'prefers-color-scheme', value: scheme }],
      },
      this.sessionId,
    );
    await this.cdp.send(
      'Emulation.setDeviceMetricsOverride',
      {
        width,
        height,
        deviceScaleFactor,
        mobile: false,
      },
      this.sessionId,
    );
  }

  async evaluar(expression) {
    const res = await this.cdp.send(
      'Runtime.evaluate',
      {
        expression,
        returnByValue: true,
        awaitPromise: true,
      },
      this.sessionId,
    );
    if (res.exceptionDetails) {
      const detalle =
        res.exceptionDetails.exception?.description ||
        res.exceptionDetails.text ||
        'Excepción al evaluar en la página';
      throw new Error(detalle);
    }
    return res.result?.value;
  }

  async estadoPagina() {
    const info = await this.evaluar(`({
      url: window.location.href,
      pathname: window.location.pathname,
      search: window.location.search,
      h1: document.querySelector('h1')?.textContent?.trim() ?? '',
      avisoError: document.querySelector('.aviso-error')?.textContent?.trim() ?? null,
      avisoOk: document.querySelector('.aviso-ok')?.textContent?.trim() ?? null,
    })`);
    return {
      status: this.ultimoEstadoDoc,
      ...info,
    };
  }

  async navegar(url) {
    this.ultimoEstadoDoc = null;
    const carga = this.cdp.waitForEvent('Page.loadEventFired', this.sessionId);
    const nav = await this.cdp.send('Page.navigate', { url }, this.sessionId);
    if (nav.errorText) {
      throw new Error(`Fallo de navegación a ${url}: ${nav.errorText}`);
    }
    await carga;
    return this.estadoPagina();
  }

  async enviarFormulario(selectorFormulario, campos = {}) {
    this.ultimoEstadoDoc = null;
    const carga = this.cdp.waitForEvent('Page.loadEventFired', this.sessionId);

    // Se desactiva la validación HTML5 en cliente (minlength) y se usa form.submit()
    // para que incluso contraseñas débiles lleguen al servidor y queden auditadas.
    const expr = `(() => {
      const form = document.querySelector(${JSON.stringify(selectorFormulario)});
      if (!form) {
        throw new Error('No se encontró el formulario ' + ${JSON.stringify(selectorFormulario)} + ' en ' + window.location.href);
      }
      const valores = ${JSON.stringify(campos)};
      for (const [nombre, valor] of Object.entries(valores)) {
        const campo = form.querySelector('[name=' + JSON.stringify(nombre) + ']');
        if (!campo) {
          throw new Error('No se encontró el campo "' + nombre + '" dentro de ' + ${JSON.stringify(selectorFormulario)});
        }
        campo.value = valor;
      }
      form.noValidate = true;
      form.submit();
      return true;
    })()`;

    await this.evaluar(expr);
    await carga;
    return this.estadoPagina();
  }

  async capturar(nombreArchivo, { width, height = 800, fullPage = false, deviceScaleFactor = 1, scheme = 'light' }) {
    // Si es captura de página completa, primero se fija una altura base (800) para que
    // scrollHeight refleje la altura real del contenido y no una altura previa inflada.
    await this.configurarVista({
      width,
      height: fullPage ? 800 : height,
      deviceScaleFactor,
      scheme,
    });

    await this.evaluar(
      `new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)))`,
    );

    let altoCaptura = height;
    if (fullPage) {
      altoCaptura = await this.evaluar(`(() => {
        window.scrollTo(0, 0);
        const body = document.body;
        const html = document.documentElement;
        return Math.ceil(Math.max(
          body ? body.scrollHeight : 0,
          body ? body.offsetHeight : 0,
          html ? html.clientHeight : 0,
          html ? html.scrollHeight : 0,
          html ? html.offsetHeight : 0
        ));
      })()`);

      await this.configurarVista({
        width,
        height: altoCaptura,
        deviceScaleFactor,
        scheme,
      });

      await this.evaluar(
        `new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)))`,
      );
    }

    const params = fullPage
      ? {
          format: 'png',
          captureBeyondViewport: true,
          clip: {
            x: 0,
            y: 0,
            width,
            height: altoCaptura,
            scale: 1,
          },
        }
      : { format: 'png' };

    const { data } = await this.cdp.send('Page.captureScreenshot', params, this.sessionId);
    const destino = path.join(CAPTURAS_DIR, nombreArchivo);
    fs.writeFileSync(destino, Buffer.from(data, 'base64'));
    return { destino, width, height: altoCaptura };
  }

  async cerrar() {
    this.offNetwork();
    try {
      await this.cdp.send('Target.closeTarget', { targetId: this.targetId });
    } catch {
      // Ignorar si el navegador ya se está cerrando.
    }
    try {
      await this.cdp.send('Target.disposeBrowserContext', {
        browserContextId: this.browserContextId,
      });
    } catch {
      // Ignorar si ya fue liberado.
    }
  }
}

function verificar(condicion, paso, observado) {
  if (!condicion) {
    throw new Error(`Fallo en paso "${paso}": se observó ${observado}`);
  }
}

function registrarPaso(descripcion, estado) {
  const codigo = estado.status !== null && estado.status !== undefined ? `HTTP ${estado.status}` : 'sin estado HTTP';
  process.stdout.write(`[OK] ${descripcion} -> ${codigo} (${estado.url})\n`);
}

async function cerrarProcesoChromium(proc) {
  if (!proc || proc.exitCode !== null) return;
  proc.kill('SIGTERM');
  await Promise.race([
    new Promise((resolve) => proc.once('exit', resolve)),
    new Promise((resolve) => setTimeout(resolve, 2000)),
  ]);
  if (proc.exitCode === null) {
    proc.kill('SIGKILL');
  }
}

async function ejecutar() {
  fs.mkdirSync(CAPTURAS_DIR, { recursive: true });
  const binario = resolverBinarioChromium();
  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'login-log-cdp-'));

  let proc = null;
  let cdp = null;

  try {
    const lanzado = lanzarChromium(binario, userDataDir);
    proc = lanzado.proc;
    const wsUrl = await lanzado.wsUrlPromise;
    cdp = await CdpClient.conectar(wsUrl);

    const sufijo = Date.now().toString(36);
    const anaEmail = `ana.${sufijo}@example.com`;
    const brunoEmail = `bruno.${sufijo}@example.com`;

    // =========================================================================
    // 1. Ana: registro con contraseña débil, registro correcto y cierre de sesión
    // =========================================================================
    const sesionAna = await ActorSession.crear(cdp);
    try {
      const formReg = await sesionAna.navegar(`${BASE_URL}/registro`);
      verificar(
        formReg.status === 200 && formReg.pathname === '/registro',
        'Ana abre /registro',
        `HTTP ${formReg.status} en ${formReg.url}`,
      );

      const regDebil = await sesionAna.enviarFormulario('form[action="/registro"]', {
        email: anaEmail,
        password: 'corta',
      });
      verificar(
        regDebil.status === 400 && regDebil.pathname === '/registro' && Boolean(regDebil.avisoError),
        'Ana intenta registro con contraseña débil',
        `HTTP ${regDebil.status}, url=${regDebil.url}, avisoError=${JSON.stringify(regDebil.avisoError)}`,
      );
      registrarPaso(`Ana: registro con contraseña débil rechazado (${regDebil.avisoError})`, regDebil);

      const regOk = await sesionAna.enviarFormulario('form[action="/registro"]', {
        email: anaEmail,
        password: DEMO_PASSWORD,
      });
      verificar(
        regOk.status === 200 && regOk.pathname === '/login' && regOk.search === '?registrado=1',
        'Ana completa registro correcto',
        `HTTP ${regOk.status} en ${regOk.url}`,
      );
      registrarPaso(`Ana (${anaEmail}): registro correcto`, regOk);

      // POST /registro redirige a /login?registrado=1 sin iniciar sesión; iniciamos sesión
      // para poder ejecutar el cierre de sesión real mediante POST /logout.
      if (regOk.pathname === '/login') {
        const loginInicialAna = await sesionAna.enviarFormulario('form[action="/login"]', {
          email: anaEmail,
          password: DEMO_PASSWORD,
        });
        verificar(
          loginInicialAna.status === 200 && loginInicialAna.pathname === '/cuenta',
          'Ana inicia sesión tras registrarse para cerrar sesión',
          `HTTP ${loginInicialAna.status} en ${loginInicialAna.url}`,
        );
        registrarPaso('Ana: inicio de sesión previo al cierre de sesión', loginInicialAna);
      }

      const logoutAna = await sesionAna.enviarFormulario('form[action="/logout"]');
      verificar(
        logoutAna.status === 200 && logoutAna.pathname === '/login',
        'Ana cierra sesión',
        `HTTP ${logoutAna.status} en ${logoutAna.url}`,
      );
      registrarPaso('Ana: cierre de sesión', logoutAna);

      // =========================================================================
      // 2. Ana: login con contraseña incorrecta (captura login-error.png) y bloqueo
      // =========================================================================
      const fallo1 = await sesionAna.enviarFormulario('form[action="/login"]', {
        email: anaEmail,
        password: `${DEMO_PASSWORD}-erronea-1`,
      });
      verificar(
        fallo1.status === 401 && fallo1.pathname === '/login' && Boolean(fallo1.avisoError),
        'Ana realiza primer login con contraseña incorrecta',
        `HTTP ${fallo1.status}, url=${fallo1.url}, avisoError=${JSON.stringify(fallo1.avisoError)}`,
      );
      await sesionAna.capturar('login-error.png', {
        width: 1280,
        height: 800,
        fullPage: false,
        scheme: 'light',
      });
      registrarPaso('Ana: login fallido (1/5) y captura login-error.png', fallo1);

      for (let intento = 2; intento <= LOCKOUT_THRESHOLD; intento++) {
        const falloN = await sesionAna.enviarFormulario('form[action="/login"]', {
          email: anaEmail,
          password: `${DEMO_PASSWORD}-erronea-${intento}`,
        });
        verificar(
          falloN.status === 401 && falloN.pathname === '/login' && Boolean(falloN.avisoError),
          `Ana realiza intento fallido ${intento}/${LOCKOUT_THRESHOLD}`,
          `HTTP ${falloN.status}, url=${falloN.url}, avisoError=${JSON.stringify(falloN.avisoError)}`,
        );
        registrarPaso(
          `Ana: login fallido (${intento}/${LOCKOUT_THRESHOLD})${intento === LOCKOUT_THRESHOLD ? ' -> cuenta bloqueada' : ''}`,
          falloN,
        );
      }
    } finally {
      await sesionAna.cerrar();
    }

    // =========================================================================
    // 3. Bruno: registro, cambio de contraseña, POST CSRF, /admin/logs 403 y logout
    // =========================================================================
    const sesionBruno = await ActorSession.crear(cdp);
    try {
      const formRegBruno = await sesionBruno.navegar(`${BASE_URL}/registro`);
      verificar(
        formRegBruno.status === 200 && formRegBruno.pathname === '/registro',
        'Bruno abre /registro',
        `HTTP ${formRegBruno.status} en ${formRegBruno.url}`,
      );

      const regBruno = await sesionBruno.enviarFormulario('form[action="/registro"]', {
        email: brunoEmail,
        password: DEMO_PASSWORD,
      });
      verificar(
        regBruno.status === 200 && regBruno.pathname === '/login' && regBruno.search === '?registrado=1',
        'Bruno completa registro correcto',
        `HTTP ${regBruno.status} en ${regBruno.url}`,
      );
      registrarPaso(`Bruno (${brunoEmail}): registro correcto`, regBruno);

      // Igual que con Ana, tras registrarse en /registro hay que autenticar a Bruno para ir a /cuenta.
      const loginBruno = await sesionBruno.enviarFormulario('form[action="/login"]', {
        email: brunoEmail,
        password: DEMO_PASSWORD,
      });
      verificar(
        loginBruno.status === 200 && loginBruno.pathname === '/cuenta',
        'Bruno inicia sesión tras registrarse',
        `HTTP ${loginBruno.status} en ${loginBruno.url}`,
      );
      registrarPaso('Bruno: inicio de sesión', loginBruno);

      const cambioPass = await sesionBruno.enviarFormulario('form[action="/cuenta/password"]', {
        currentPassword: DEMO_PASSWORD,
        newPassword: DEMO_PASSWORD_2,
      });
      verificar(
        cambioPass.status === 200 &&
          cambioPass.pathname === '/cuenta' &&
          cambioPass.search === '?cambiada=1' &&
          Boolean(cambioPass.avisoOk),
        'Bruno cambia su contraseña',
        `HTTP ${cambioPass.status}, url=${cambioPass.url}, avisoOk=${JSON.stringify(cambioPass.avisoOk)}`,
      );
      registrarPaso('Bruno: cambio de contraseña completado', cambioPass);

      const csrfRes = await conTimeout(
        fetch(`${BASE_URL}/login`, {
          method: 'POST',
          headers: {
            'content-type': 'application/x-www-form-urlencoded',
            origin: 'https://evil.example',
          },
          body: new URLSearchParams({
            email: brunoEmail,
            password: DEMO_PASSWORD_2,
          }).toString(),
          redirect: 'manual',
        }),
        TIMEOUT_MS,
        'POST /login con Origin ajeno (CSRF)',
      );
      verificar(
        csrfRes.status === 403,
        'Petición POST /login con cabecera Origin https://evil.example',
        `HTTP ${csrfRes.status}`,
      );
      registrarPaso('Bruno: petición POST /login con Origin ajeno rechazada por CSRF', {
        status: csrfRes.status,
        url: `${BASE_URL}/login`,
      });

      const denegado = await sesionBruno.navegar(`${BASE_URL}/admin/logs`);
      verificar(
        denegado.status === 403 && denegado.pathname === '/admin/logs' && Boolean(denegado.avisoError),
        'Bruno visita GET /admin/logs con sesión sin rol admin',
        `HTTP ${denegado.status}, url=${denegado.url}, h1=${JSON.stringify(denegado.h1)}`,
      );
      await sesionBruno.capturar('acceso-denegado.png', {
        width: 1280,
        height: 800,
        fullPage: false,
        scheme: 'light',
      });
      registrarPaso('Bruno: acceso denegado en /admin/logs y captura acceso-denegado.png', denegado);

      const logoutBruno = await sesionBruno.enviarFormulario('form[action="/logout"]');
      verificar(
        logoutBruno.status === 200 && logoutBruno.pathname === '/login',
        'Bruno cierra sesión',
        `HTTP ${logoutBruno.status} en ${logoutBruno.url}`,
      );
      registrarPaso('Bruno: cierre de sesión', logoutBruno);
    } finally {
      await sesionBruno.cerrar();
    }

    // =========================================================================
    // 4. Administrador: login y capturas del visor de auditoría
    // =========================================================================
    const sesionAdmin = await ActorSession.crear(cdp);
    try {
      const pagLoginAdmin = await sesionAdmin.navegar(`${BASE_URL}/login`);
      verificar(
        pagLoginAdmin.status === 200 && pagLoginAdmin.pathname === '/login',
        'Administrador abre /login',
        `HTTP ${pagLoginAdmin.status} en ${pagLoginAdmin.url}`,
      );

      const loginAdmin = await sesionAdmin.enviarFormulario('form[action="/login"]', {
        email: ADMIN_EMAIL,
        password: ADMIN_PASSWORD,
      });
      verificar(
        loginAdmin.status === 200 && loginAdmin.pathname === '/cuenta',
        'Administrador inicia sesión',
        `HTTP ${loginAdmin.status}, url=${loginAdmin.url}, avisoError=${JSON.stringify(loginAdmin.avisoError)}`,
      );
      registrarPaso('Administrador: inicio de sesión correcto', loginAdmin);

      // 4.1 visor-general.png: /admin/logs?verificar=1, 1280 ancho, página completa, claro
      const visorGeneral = await sesionAdmin.navegar(`${BASE_URL}/admin/logs?verificar=1`);
      const totalFilasGeneral = await sesionAdmin.evaluar(
        `document.querySelectorAll('table.tabla-eventos tbody tr').length`,
      );
      verificar(
        visorGeneral.status === 200 &&
          visorGeneral.pathname === '/admin/logs' &&
          Boolean(visorGeneral.avisoOk) &&
          totalFilasGeneral > 0,
        'Administrador abre /admin/logs?verificar=1',
        `HTTP ${visorGeneral.status}, url=${visorGeneral.url}, filas=${totalFilasGeneral}, avisoOk=${JSON.stringify(visorGeneral.avisoOk)}`,
      );
      await sesionAdmin.capturar('visor-general.png', {
        width: 1280,
        fullPage: true,
        scheme: 'light',
      });
      registrarPaso(
        `Administrador: captura visor-general.png (${totalFilasGeneral} filas)`,
        visorGeneral,
      );

      // 4.2 visor-filtro-fallos.png: filtrado por outcome=failure, 1280 ancho, página completa, claro
      const visorFallos = await sesionAdmin.enviarFormulario('form.filtros[action="/admin/logs"]', {
        outcome: 'failure',
      });
      const infoFallos = await sesionAdmin.evaluar(`(() => {
        const filas = [...document.querySelectorAll('table.tabla-eventos tbody tr')];
        return {
          total: filas.length,
          todasFallo: filas.length > 0 && filas.every((tr) => tr.dataset.resultado === 'failure'),
        };
      })()`);
      verificar(
        visorFallos.status === 200 &&
          visorFallos.pathname === '/admin/logs' &&
          new URL(visorFallos.url).searchParams.get('outcome') === 'failure' &&
          infoFallos.todasFallo,
        'Administrador filtra el visor por outcome=failure',
        `HTTP ${visorFallos.status}, url=${visorFallos.url}, filas=${infoFallos.total}, todasFallo=${infoFallos.todasFallo}`,
      );
      await sesionAdmin.capturar('visor-filtro-fallos.png', {
        width: 1280,
        fullPage: true,
        scheme: 'light',
      });
      registrarPaso(
        `Administrador: captura visor-filtro-fallos.png (${infoFallos.total} filas de fallo)`,
        visorFallos,
      );

      // 4.3 visor-detalles.png: en /admin/logs?verificar=1 con detalle de fila de fallo expandido, 1280x900, claro
      const visorParaDetalles = await sesionAdmin.navegar(`${BASE_URL}/admin/logs?verificar=1`);
      verificar(
        visorParaDetalles.status === 200 && visorParaDetalles.pathname === '/admin/logs',
        'Administrador vuelve a /admin/logs?verificar=1 para expandir detalles',
        `HTTP ${visorParaDetalles.status} en ${visorParaDetalles.url}`,
      );
      await sesionAdmin.configurarVista({
        width: 1280,
        height: 900,
        deviceScaleFactor: 1,
        scheme: 'light',
      });

      const detalleExpandido = await sesionAdmin.evaluar(`(() => {
        const filaFallo = document.querySelector('table.tabla-eventos tbody tr[data-resultado="failure"]');
        if (!filaFallo) return null;
        const details = filaFallo.querySelector('details.detalle');
        const summary = details?.querySelector('summary');
        if (!details || !summary) return null;
        summary.click();
        const rect = details.getBoundingClientRect();
        if (rect.top < 0 || rect.bottom > window.innerHeight) {
          details.scrollIntoView({ block: 'center', behavior: 'instant' });
        }
        const rectFinal = details.getBoundingClientRect();
        return {
          seq: filaFallo.dataset.seq,
          tipo: filaFallo.dataset.tipo,
          abierto: details.open,
          visible: rectFinal.top >= 0 && rectFinal.bottom <= window.innerHeight,
        };
      })()`);
      verificar(
        Boolean(detalleExpandido) && detalleExpandido.abierto && detalleExpandido.visible,
        'Administrador expande el detalle de una fila de fallo',
        JSON.stringify(detalleExpandido),
      );
      await sesionAdmin.capturar('visor-detalles.png', {
        width: 1280,
        height: 900,
        fullPage: false,
        scheme: 'light',
      });
      registrarPaso(
        `Administrador: captura visor-detalles.png (seq ${detalleExpandido.seq}, ${detalleExpandido.tipo})`,
        visorParaDetalles,
      );

      // Cerramos el desplegable y volvemos al inicio del documento para las capturas del visor general.
      await sesionAdmin.evaluar(`(() => {
        for (const d of document.querySelectorAll('details.detalle[open]')) {
          d.open = false;
        }
        window.scrollTo(0, 0);
      })()`);

      // 4.4 visor-oscuro.png: visor general, 1280x900, prefers-color-scheme dark
      await sesionAdmin.capturar('visor-oscuro.png', {
        width: 1280,
        height: 900,
        fullPage: false,
        scheme: 'dark',
      });
      registrarPaso('Administrador: captura visor-oscuro.png (1280x900, oscuro)', visorParaDetalles);

      // 4.5 visor-movil.png: visor general, 320 ancho, página completa, claro, deviceScaleFactor 2
      await sesionAdmin.capturar('visor-movil.png', {
        width: 320,
        fullPage: true,
        deviceScaleFactor: 2,
        scheme: 'light',
      });
      registrarPaso(
        'Administrador: captura visor-movil.png (320 ancho, página completa, 2x)',
        visorParaDetalles,
      );
    } finally {
      await sesionAdmin.cerrar();
    }
  } finally {
    if (cdp) {
      cdp.cerrar();
    }
    await cerrarProcesoChromium(proc);
    fs.rmSync(userDataDir, { recursive: true, force: true });
  }
}

ejecutar().catch((err) => {
  process.stderr.write(`Error ejecutando capturas: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
