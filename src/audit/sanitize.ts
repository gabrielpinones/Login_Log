import { createHmac } from 'node:crypto';
import { isIP } from 'node:net';
import { config } from '../config.js';

// Los datos del cliente pueden traer saltos de línea para falsificar entradas de log (log injection).
const CONTROL_CHARS = /[\u0000-\u001F\u007F-\u009F\u2028\u2029]/g;

export function cleanText(value: unknown, max: number): string | null {
  if (typeof value !== 'string') return null;
  const cleaned = value.replace(CONTROL_CHARS, '');
  if (cleaned === '') return null;
  // Se corta por puntos de código y luego se repara cualquier sustituto suelto.
  const truncated = Array.from(cleaned).slice(0, max).join('').toWellFormed();
  return truncated === '' ? null : truncated;
}

export function identifierHash(identifier: string): string {
  return createHmac('sha256', config.auditHmacKey).update(identifier.trim().toLowerCase()).digest('hex');
}

const IPV4_MAPPED = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i;

export function normalizeIp(ip: string | undefined): string | null {
  if (typeof ip !== 'string') return null;
  // La zona IPv6 (fe80::1%eth0) la acepta net.isIP pero la columna inet de PostgreSQL la rechaza.
  const withoutZone = ip.split('%')[0] ?? ip;
  const mapped = IPV4_MAPPED.exec(withoutZone);
  const candidate = mapped?.[1] ?? withoutZone;
  return isIP(candidate) === 0 ? null : candidate;
}
