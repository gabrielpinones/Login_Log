import type { Response } from 'supertest';
import request from 'supertest';
import { expect } from 'vitest';
import { createApp } from '../../src/app.js';
import { config } from '../../src/config.js';
import { adminPool } from '../helpers.js';

export const app = createApp();

export interface AuthEventRow {
  seq: number;
  event_id: string;
  occurred_at: Date;
  event_type: string;
  outcome: 'success' | 'failure';
  reason: string | null;
  severity: 'info' | 'warn' | 'error';
  user_id: string | null;
  identifier_hash: string | null;
  session_id: string | null;
  source_ip: string | null;
  user_agent: string | null;
  http_method: string | null;
  route: string | null;
  http_status: number | null;
  request_id: string | null;
  service: string;
  version: string;
  environment: string;
  hostname: string;
  details: Record<string, unknown>;
  prev_hash: string;
  hash: string;
}

export interface SessionRow {
  id: string;
  token_hash: string;
  user_id: string;
  created_at: Date;
  last_seen_at: Date;
  expires_at: Date;
  revoked_at: Date | null;
  end_reason: string | null;
  source_ip: string | null;
  user_agent: string | null;
}

export interface UserRow {
  id: string;
  email: string;
  password_hash: string;
  role: string;
  failed_attempts: number;
  locked_until: Date | null;
  created_at: Date;
  password_changed_at: Date;
}

export interface ExpectedEvent {
  type: string;
  reason?: string | null;
}

export interface FormRequestOptions {
  origin?: string | null;
  referer?: string;
  sid?: string;
}

export function getPage(route: string, opts: { sid?: string } = {}): Promise<Response> {
  const req = request(app).get(route);
  if (opts.sid !== undefined) {
    req.set('Cookie', [`sid=${opts.sid}`]);
  }
  return req;
}

export function postForm(
  route: string,
  form: Record<string, string>,
  opts: FormRequestOptions = {},
): Promise<Response> {
  const req = request(app).post(route).type('form');
  if (opts.origin !== null) {
    req.set('Origin', opts.origin ?? config.appOrigin);
  }
  if (opts.referer !== undefined) {
    req.set('Referer', opts.referer);
  }
  if (opts.sid !== undefined) {
    req.set('Cookie', [`sid=${opts.sid}`]);
  }
  return req.send(form);
}

export function findSidSetCookie(res: Response): string | undefined {
  const cookies = res.get('Set-Cookie');
  if (!cookies) return undefined;
  return cookies.find((cookie) => cookie.startsWith('sid='));
}

export function extractSid(res: Response): string | undefined {
  const header = findSidSetCookie(res);
  if (!header) return undefined;
  const separator = header.indexOf(';');
  const pair = separator === -1 ? header : header.slice(0, separator);
  const value = pair.slice('sid='.length);
  return value === '' ? undefined : value;
}

export function registerUser(email: string, password: string): Promise<Response> {
  return postForm('/registro', { email, password });
}

export async function loginUser(
  email: string,
  password: string,
): Promise<{ res: Response; sid: string | undefined }> {
  const res = await postForm('/login', { email, password });
  return { res, sid: extractSid(res) };
}

export async function registerAndLogin(
  email: string,
  password: string,
): Promise<{ userId: string; sessionId: string; sid: string; loginRes: Response }> {
  const regRes = await registerUser(email, password);
  expect(regRes.status).toBe(303);

  const { res: loginRes, sid } = await loginUser(email, password);
  expect(loginRes.status).toBe(303);
  if (sid === undefined) {
    throw new Error('Se esperaba cookie sid tras el inicio de sesión');
  }

  const users = await readUsers();
  const normalized = email.trim().toLowerCase();
  const user = users.find((u) => u.email === normalized);
  if (!user) {
    throw new Error(`No se encontró al usuario ${normalized}`);
  }

  const sessions = await readSessions();
  const userSessions = sessions.filter((s) => s.user_id === user.id && s.revoked_at === null);
  const latestSession = userSessions[userSessions.length - 1];
  if (!latestSession) {
    throw new Error(`No se encontró sesión activa para ${normalized}`);
  }

  return { userId: user.id, sessionId: latestSession.id, sid, loginRes };
}

export async function readAuthEvents(): Promise<AuthEventRow[]> {
  const { rows } = await adminPool.query<AuthEventRow>('SELECT * FROM auth_events ORDER BY seq ASC');
  return rows;
}

export async function readAuthEventsAfter(afterSeq: number): Promise<AuthEventRow[]> {
  const { rows } = await adminPool.query<AuthEventRow>(
    'SELECT * FROM auth_events WHERE seq > $1 ORDER BY seq ASC',
    [afterSeq],
  );
  return rows;
}

export async function readSessions(): Promise<SessionRow[]> {
  const { rows } = await adminPool.query<SessionRow>('SELECT * FROM sessions ORDER BY created_at ASC');
  return rows;
}

export async function readUsers(): Promise<UserRow[]> {
  const { rows } = await adminPool.query<UserRow>('SELECT * FROM users ORDER BY created_at ASC');
  return rows;
}

export async function withNewEvents<T>(action: () => Promise<T>): Promise<{ result: T; events: AuthEventRow[] }> {
  const { rows } = await adminPool.query<{ max_seq: number }>('SELECT COALESCE(MAX(seq), 0) AS max_seq FROM auth_events');
  const lastSeq = Number(rows[0]?.max_seq ?? 0);
  const result = await action();
  const events = await readAuthEventsAfter(lastSeq);
  return { result, events };
}

export async function withAuditWriteFailure<T>(fn: () => Promise<T>): Promise<T> {
  await adminPool.query('REVOKE INSERT ON auth_events FROM login_log_app');
  try {
    return await fn();
  } finally {
    await adminPool.query('GRANT INSERT ON auth_events TO login_log_app');
  }
}

export function assertHttpEvents(
  events: AuthEventRow[],
  res: Response,
  reqInfo: { method: string; route: string },
  expected: ExpectedEvent[],
): AuthEventRow[] {
  const actualSummary = events.map((ev) => ({ type: ev.event_type, reason: ev.reason }));
  const expectedSummary = expected.map((ev) => ({ type: ev.type, reason: ev.reason ?? null }));
  expect(actualSummary).toEqual(expectedSummary);

  const requestId = res.get('X-Request-Id');
  expect(requestId).toBeTruthy();

  for (const ev of events) {
    expect(ev.request_id).toBe(requestId);
    expect(ev.source_ip).not.toBeNull();
    expect(ev.http_method).toBe(reqInfo.method);
    expect(ev.route).toBe(reqInfo.route);
    // loadSession emite session.expired antes de que la ruta decida el estado HTTP.
    expect(ev.http_status).toBe(ev.event_type === 'session.expired' ? null : res.status);
  }

  return events;
}
