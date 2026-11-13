import { readdir, unlink } from 'node:fs/promises';
import path from 'node:path';
import { config } from '../config.js';
import { appLogger } from './logger.js';

const LOG_FILE_RE = /^(app|auth-events)\.(\d{4}-\d{2}-\d{2})\.\d+\.jsonl$/;

function parseUtcDate(dateStr: string): number | null {
  const ms = Date.parse(`${dateStr}T00:00:00.000Z`);
  if (Number.isNaN(ms)) return null;
  if (new Date(ms).toISOString().slice(0, 10) !== dateStr) return null;
  return ms;
}

export async function purgeOldLogs(opts?: {
  dir?: string;
  days?: number;
  now?: Date;
}): Promise<string[]> {
  const dir = opts?.dir ?? config.logDir;
  const days = opts?.days ?? config.logRetentionDays;
  const now = opts?.now ?? new Date();

  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      return [];
    }
    throw err;
  }

  // Se compara contra la medianoche UTC de (now - days) para que la hora del día no afecte el corte por fecha.
  const cutoff = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - days);
  const candidates = entries
    .filter((entry) => entry.isFile())
    .map((entry) => entry.name)
    .sort();

  const deleted: string[] = [];
  for (const name of candidates) {
    const match = LOG_FILE_RE.exec(name);
    if (!match) continue;
    const datePart = match[2];
    if (datePart === undefined) continue;
    const fileDate = parseUtcDate(datePart);
    if (fileDate === null || fileDate >= cutoff) continue;

    await unlink(path.join(dir, name));
    deleted.push(name);
  }

  if (deleted.length > 0) {
    appLogger.info({ count: deleted.length, files: deleted }, 'log.retention.purged');
  }

  return deleted;
}
