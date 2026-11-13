import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import type pg from 'pg';
import { config } from '../config.js';
import { pool } from '../db.js';

export type ChainResult =
  | { ok: true; count: number; lastSeq: number | null; lastHash: string | null }
  | {
      ok: false;
      count: number;
      brokenSeq: number;
      problem: 'seq_gap' | 'prev_hash_mismatch' | 'hash_mismatch';
    };

export interface FileCheck {
  linesChecked: number;
  malformedLines: number;
  mismatches: { seq: number; problem: 'hash_differs' | 'missing_in_db' | 'missing_in_file' }[];
}

export interface ChainStatus {
  result: ChainResult;
  verifiedAt: Date;
}

const ZERO_HASH = '0'.repeat(64);
const BATCH_SIZE = 1000;
const CHAIN_CACHE_TTL_MS = 60 * 1000;

let cachedStatus: ChainStatus | null = null;

const BATCH_SQL = `
  SELECT e.seq,
         e.prev_hash,
         e.hash,
         encode(sha256(convert_to(e.prev_hash || auth_event_canonical(e), 'UTF8')), 'hex') AS expected_hash
  FROM auth_events e
  WHERE e.seq > $1
  ORDER BY e.seq ASC
  LIMIT $2
`;

export interface Queryable {
  query<R extends pg.QueryResultRow = pg.QueryResultRow>(
    text: string,
    values?: unknown[],
  ): Promise<{ rows: R[] }>;
}

interface ChainRow {
  seq: number;
  prev_hash: string;
  hash: string;
  expected_hash: string;
}

export async function verifyChain(db: Queryable = pool): Promise<ChainResult> {
  let count = 0;
  let lastSeq: number | null = null;
  let lastHash: string | null = null;
  let expectedSeq = 1;
  let expectedPrevHash = ZERO_HASH;

  while (true) {
    const cursor: number = lastSeq ?? 0;
    const { rows }: { rows: ChainRow[] } = await db.query<ChainRow>(BATCH_SQL, [cursor, BATCH_SIZE]);
    if (rows.length === 0) break;

    for (const row of rows) {
      count += 1;
      if (row.seq !== expectedSeq) {
        return { ok: false, count, brokenSeq: row.seq, problem: 'seq_gap' };
      }
      if (row.prev_hash !== expectedPrevHash) {
        return { ok: false, count, brokenSeq: row.seq, problem: 'prev_hash_mismatch' };
      }
      if (row.hash !== row.expected_hash) {
        return { ok: false, count, brokenSeq: row.seq, problem: 'hash_mismatch' };
      }
      lastSeq = row.seq;
      lastHash = row.hash;
      expectedSeq = row.seq + 1;
      expectedPrevHash = row.hash;
    }

    if (rows.length < BATCH_SIZE) break;
  }

  return { ok: true, count, lastSeq, lastHash };
}

export async function getChainStatus(opts?: { force?: boolean }): Promise<ChainStatus> {
  const now = Date.now();
  if (
    !opts?.force &&
    cachedStatus !== null &&
    now - cachedStatus.verifiedAt.getTime() < CHAIN_CACHE_TTL_MS
  ) {
    return cachedStatus;
  }
  const result = await verifyChain();
  const status: ChainStatus = { result, verifiedAt: new Date() };
  cachedStatus = status;
  return status;
}

interface FileEventEntry {
  seq: number;
  hash: string;
}

type ParsedLine =
  | { kind: 'entry'; entry: FileEventEntry }
  | { kind: 'write_failed' }
  | { kind: 'malformed' };

function parseLine(line: string): ParsedLine {
  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch {
    return { kind: 'malformed' };
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return { kind: 'malformed' };
  }
  const event = (parsed as { event?: unknown }).event;
  if (typeof event !== 'object' || event === null) {
    return { kind: 'malformed' };
  }
  const seq = (event as { sequence?: unknown }).sequence;
  const hash = (event as { hash?: unknown }).hash;
  if (
    typeof seq === 'number' &&
    Number.isInteger(seq) &&
    seq >= 1 &&
    typeof hash === 'string' &&
    hash !== ''
  ) {
    return { kind: 'entry', entry: { seq, hash } };
  }
  const action = (event as { action?: unknown }).action;
  const message = (parsed as { message?: unknown }).message;
  if (action === 'audit.write.failed' || message === 'audit.write.failed') {
    return { kind: 'write_failed' };
  }
  return { kind: 'malformed' };
}

export async function verifyAgainstFiles(
  dir: string = config.logDir,
  db: Queryable = pool,
): Promise<FileCheck> {
  let dirEntries;
  try {
    dirEntries = await readdir(dir, { withFileTypes: true });
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      return { linesChecked: 0, malformedLines: 0, mismatches: [] };
    }
    throw err;
  }

  const files = dirEntries
    .filter((entry) => entry.isFile() && /^auth-events.*\.jsonl$/.test(entry.name))
    .map((entry) => entry.name)
    .sort();

  const entries: FileEventEntry[] = [];
  let malformedLines = 0;
  for (const file of files) {
    const content = await readFile(path.join(dir, file), 'utf8');
    for (const rawLine of content.split('\n')) {
      const trimmed = rawLine.trim();
      if (trimmed === '') continue;
      const parsed = parseLine(trimmed);
      if (parsed.kind === 'entry') {
        entries.push(parsed.entry);
      } else if (parsed.kind === 'malformed') {
        malformedLines += 1;
      }
    }
  }

  if (entries.length === 0) {
    return { linesChecked: 0, malformedLines, mismatches: [] };
  }

  let minSeq = entries[0]!.seq;
  let maxSeq = entries[0]!.seq;
  const fileSeqs = new Set<number>();
  for (const entry of entries) {
    if (entry.seq < minSeq) minSeq = entry.seq;
    if (entry.seq > maxSeq) maxSeq = entry.seq;
    fileSeqs.add(entry.seq);
  }

  const dbHashes = new Map<number, string>();
  let cursor = minSeq - 1;
  while (true) {
    const { rows } = await db.query<{ seq: number; hash: string }>(
      'SELECT seq, hash FROM auth_events WHERE seq > $1 AND seq <= $2 ORDER BY seq ASC LIMIT $3',
      [cursor, maxSeq, BATCH_SIZE],
    );
    if (rows.length === 0) break;
    for (const row of rows) {
      dbHashes.set(row.seq, row.hash);
    }
    cursor = rows[rows.length - 1]!.seq;
    if (rows.length < BATCH_SIZE) break;
  }

  const mismatches: FileCheck['mismatches'] = [];
  for (const entry of entries) {
    const dbHash = dbHashes.get(entry.seq);
    if (dbHash === undefined) {
      mismatches.push({ seq: entry.seq, problem: 'missing_in_db' });
    } else if (dbHash !== entry.hash) {
      mismatches.push({ seq: entry.seq, problem: 'hash_differs' });
    }
  }

  for (const seq of dbHashes.keys()) {
    if (!fileSeqs.has(seq)) {
      mismatches.push({ seq, problem: 'missing_in_file' });
    }
  }

  mismatches.sort((a, b) => a.seq - b.seq);

  return { linesChecked: entries.length, malformedLines, mismatches };
}
