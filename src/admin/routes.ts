import { Router } from 'express';
import { z } from 'zod';
import { pool } from '../db.js';
import { recordEvent } from '../audit/audit.js';
import { auditContextFrom } from '../audit/context.js';
import { EVENT_CATALOG, type AuditDetails, type EventType } from '../audit/events.js';
import { normalizeIp } from '../audit/sanitize.js';
import { getChainStatus, type ChainResult, type ChainStatus } from '../audit/verify.js';
import { requireAdmin } from '../middleware/requireAdmin.js';
import { requireSession } from '../middleware/requireSession.js';

const PAGE_SIZE = 50;

const EVENT_TYPES = Object.keys(EVENT_CATALOG) as [EventType, ...EventType[]];

const FECHA_RE = /^\d{4}-\d{2}-\d{2}$/;
const FECHA_HORA_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,3})?)?Z?$/;

interface FechaUtc {
  instante: Date;
  soloFecha: boolean;
}

// Siempre UTC: sin sufijo "Z" se añade, y los desfases explícitos (+02:00) se rechazan para no ser ambiguos.
function parsearFechaUtc(valor: string): FechaUtc | null {
  const soloFecha = FECHA_RE.test(valor);
  if (!soloFecha && !FECHA_HORA_RE.test(valor)) return null;
  const iso = soloFecha ? `${valor}T00:00:00.000Z` : valor.endsWith('Z') ? valor : `${valor}Z`;
  const instante = new Date(iso);
  if (Number.isNaN(instante.getTime())) return null;
  // Date desborda días inexistentes (2026-02-31 pasa a marzo): la fecha debe sobrevivir a la ida y vuelta.
  if (instante.toISOString().slice(0, 10) !== valor.slice(0, 10)) return null;
  return { instante, soloFecha };
}

const CLAVES_FILTRO = ['type', 'outcome', 'user', 'ip', 'desde', 'hasta', 'antes'] as const;
const CLAVES = [...CLAVES_FILTRO, 'verificar'] as const;
type Clave = (typeof CLAVES)[number];

const filtrosSchema = z.object({
  type: z.enum(EVENT_TYPES).optional(),
  outcome: z.enum(['success', 'failure']).optional(),
  user: z.uuid().optional(),
  ip: z.union([z.ipv4(), z.ipv6()]).optional(),
  desde: z.string().refine((v) => parsearFechaUtc(v) !== null).optional(),
  hasta: z.string().refine((v) => parsearFechaUtc(v) !== null).optional(),
  antes: z.string().regex(/^[1-9]\d{0,14}$/).optional(),
  verificar: z.literal('1').optional(),
});

const ETIQUETAS: Record<Clave, string> = {
  type: 'tipo de evento',
  outcome: 'resultado',
  user: 'usuario (debe ser un UUID)',
  ip: 'IP (IPv4 o IPv6)',
  desde: 'desde (AAAA-MM-DD o AAAA-MM-DDThh:mm, en UTC)',
  hasta: 'hasta (AAAA-MM-DD o AAAA-MM-DDThh:mm, en UTC)',
  antes: 'cursor de paginación (entero positivo)',
  verificar: 'verificación (debe ser 1)',
};

const PROBLEMAS: Record<Extract<ChainResult, { ok: false }>['problem'], string> = {
  seq_gap: 'falta un número de secuencia',
  prev_hash_mismatch: 'el hash anterior no coincide con el del evento previo',
  hash_mismatch: 'el hash del evento no coincide con su contenido',
};

interface FilaEvento {
  seq: number;
  occurred_at: Date;
  event_type: string;
  outcome: 'success' | 'failure';
  reason: string | null;
  user_id: string | null;
  session_id: string | null;
  source_ip: string | null;
  user_agent: string | null;
  http_method: string | null;
  route: string | null;
  http_status: number | null;
  request_id: string | null;
  details: AuditDetails;
  hash: string;
  prev_hash: string;
}

const SELECT_SQL = `SELECT seq, occurred_at, event_type, outcome, reason, user_id, session_id,
       host(source_ip) AS source_ip, user_agent, http_method, route, http_status, request_id,
       details, hash, prev_hash
FROM auth_events`;

/** Texto recortado de lo que escribió el administrador, para devolverlo al formulario escapado. */
function entradaDeQuery(query: Record<string, unknown>): {
  crudo: Record<Clave, string>;
  limpio: Record<string, unknown>;
} {
  const crudo = {} as Record<Clave, string>;
  const limpio: Record<string, unknown> = {};
  for (const clave of CLAVES) {
    const valor = query[clave];
    if (typeof valor === 'string') {
      const recortado = valor.trim();
      crudo[clave] = recortado.slice(0, 200);
      // Un campo vacío del formulario significa "sin filtro", no "filtro inválido".
      limpio[clave] = recortado === '' ? undefined : recortado;
    } else {
      crudo[clave] = '';
      // Un valor repetido (?type=a&type=b) llega como arreglo: zod lo rechaza.
      if (valor !== undefined) limpio[clave] = valor;
    }
  }
  return { crudo, limpio };
}

function describirCadena(
  estado: ChainStatus,
  verificarUrl: string,
): { ok: boolean; texto: string; verificadaEn: string; verificarUrl: string } {
  const { result: resultado, verifiedAt } = estado;
  const verificadaEn = verifiedAt.toISOString();
  if (resultado.ok) {
    const unidad = resultado.count === 1 ? 'evento verificado' : 'eventos verificados';
    return {
      ok: true,
      texto: `Cadena íntegra: ${resultado.count} ${unidad}.`,
      verificadaEn,
      verificarUrl,
    };
  }
  return {
    ok: false,
    texto: `Cadena rota en el seq ${resultado.brokenSeq}: ${PROBLEMAS[resultado.problem]} (${resultado.problem}).`,
    verificadaEn,
    verificarUrl,
  };
}

export function adminRouter(): Router {
  const router = Router();

  router.get('/admin/logs', requireSession, requireAdmin, async (req, res) => {
    const auth = req.auth!;
    const { crudo, limpio } = entradaDeQuery(req.query);

    res.set('Cache-Control', 'no-store');

    const parsed = filtrosSchema.safeParse(limpio);
    if (!parsed.success) {
      const invalidos = new Set<string>();
      for (const issue of parsed.error.issues) invalidos.add(String(issue.path[0]));
      const campos = CLAVES.filter((c) => invalidos.has(c)).map((c) => ETIQUETAS[c]);
      res.status(400).render('admin-logs', {
        pageTitle: 'Filtros no válidos - Registro de auditoría',
        error: `Revisa los filtros: ${campos.join('; ')}.`,
        filtros: crudo,
        tipos: EVENT_TYPES,
        hayFiltros: true,
        cadena: null,
        eventos: null,
        anterior: null,
      });
      return;
    }

    const filtros = parsed.data;
    const desde = filtros.desde === undefined ? null : parsearFechaUtc(filtros.desde);
    const hasta = filtros.hasta === undefined ? null : parsearFechaUtc(filtros.hasta);

    const params: unknown[] = [];
    const condiciones: string[] = [];
    const agregar = (sql: string, valor: unknown): void => {
      params.push(valor);
      condiciones.push(sql.replace('?', `$${params.length}`));
    };

    if (filtros.type !== undefined) agregar('event_type = ?', filtros.type);
    if (filtros.outcome !== undefined) agregar('outcome = ?', filtros.outcome);
    if (filtros.user !== undefined) agregar('user_id = ?::uuid', filtros.user);
    // La columna guarda la IP ya normalizada (sin el prefijo ::ffff:), así que se busca con la misma forma.
    if (filtros.ip !== undefined) agregar('source_ip = ?::inet', normalizeIp(filtros.ip) ?? filtros.ip);
    if (desde !== null) agregar('occurred_at >= ?::timestamptz', desde.instante.toISOString());
    if (hasta !== null) {
      if (hasta.soloFecha) {
        // Una fecha sola incluye el día completo.
        const diaSiguiente = new Date(hasta.instante.getTime() + 24 * 3600 * 1000);
        agregar('occurred_at < ?::timestamptz', diaSiguiente.toISOString());
      } else {
        agregar('occurred_at <= ?::timestamptz', hasta.instante.toISOString());
      }
    }
    if (filtros.antes !== undefined) agregar('seq < ?::bigint', filtros.antes);

    const where = condiciones.length > 0 ? `WHERE ${condiciones.join(' AND ')}` : '';
    // Se pide una fila de más para saber si existe otra página sin contar toda la tabla.
    const consulta = `${SELECT_SQL} ${where} ORDER BY seq DESC LIMIT ${PAGE_SIZE + 1}`;

    const [estadoCadena, filasResultado] = await Promise.all([
      getChainStatus({ force: filtros.verificar === '1' }),
      pool.query<FilaEvento>(consulta, params),
    ]);

    const hayMas = filasResultado.rows.length > PAGE_SIZE;
    const filas = filasResultado.rows.slice(0, PAGE_SIZE);

    const usados: Record<string, string> = {};
    for (const clave of CLAVES_FILTRO) {
      const valor = filtros[clave];
      if (valor !== undefined) usados[clave] = valor;
    }

    // Antes de responder: si el registro de la consulta falla, la página no se entrega.
    await recordEvent(
      {
        type: 'audit.log.viewed',
        userId: auth.userId,
        sessionId: auth.sessionId,
        httpStatus: 200,
        details: { ...usados, result_count: filas.length },
      },
      auditContextFrom(req),
    );

    const enlaceVerificar = new URLSearchParams();
    for (const clave of CLAVES_FILTRO) {
      const valor = filtros[clave];
      if (clave !== 'antes' && valor !== undefined) enlaceVerificar.set(clave, valor);
    }
    enlaceVerificar.set('verificar', '1');
    const verificarUrl = `/admin/logs?${enlaceVerificar.toString()}`;

    let anterior: string | null = null;
    const ultima = filas[filas.length - 1];
    if (hayMas && ultima !== undefined) {
      const enlace = new URLSearchParams();
      for (const clave of CLAVES_FILTRO) {
        const valor = filtros[clave];
        if (clave !== 'antes' && valor !== undefined) enlace.set(clave, valor);
      }
      enlace.set('antes', String(ultima.seq));
      anterior = `/admin/logs?${enlace.toString()}`;
    }

    const eventos = filas.map((fila) => ({
      seq: fila.seq,
      instante: fila.occurred_at.toISOString(),
      tipo: fila.event_type,
      resultado: fila.outcome,
      motivo: fila.reason,
      usuario: fila.user_id,
      ip: fila.source_ip,
      estado: fila.http_status,
      requestId: fila.request_id,
      sessionId: fila.session_id,
      userAgent: fila.user_agent,
      ruta: fila.route,
      metodo: fila.http_method,
      hash: fila.hash,
      hashAnterior: fila.prev_hash,
      detalles: JSON.stringify(fila.details, null, 2),
    }));

    res.status(200).render('admin-logs', {
      pageTitle: 'Registro de auditoría',
      error: null,
      filtros: { ...crudo, antes: '', verificar: '' },
      tipos: EVENT_TYPES,
      hayFiltros: Object.keys(usados).length > 0,
      cadena: describirCadena(estadoCadena, verificarUrl),
      eventos,
      anterior,
    });
  });

  return router;
}
