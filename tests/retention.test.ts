import { mkdir, mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { purgeOldLogs } from '../src/logging/retention.js';

describe('purgeOldLogs', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(path.join(os.tmpdir(), 'login-log-retention-'));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it('borra los archivos vencidos de ambos prefijos y conserva recientes, hoy, otros nombres y subdirectorios', async () => {
    const now = new Date('2026-06-15T14:30:00.000Z');
    const days = 30;

    const vencidos = ['app.2026-04-10.1.jsonl', 'auth-events.2026-05-15.3.jsonl'];
    const conservados = [
      'app.2026-05-16.1.jsonl',
      'auth-events.2026-06-01.1.jsonl',
      'app.2026-06-15.1.jsonl',
      'auth-events.2026-06-15.2.jsonl',
      'app.jsonl',
      'auth-events.jsonl',
      'otro.2020-01-01.1.jsonl',
      'notas.txt',
    ];
    const subdirectorios = ['archivo-historico', 'app.2020-01-01.1.jsonl'];

    for (const nombre of [...vencidos, ...conservados]) {
      await writeFile(path.join(tempDir, nombre), '{}\n', 'utf8');
    }
    for (const subdir of subdirectorios) {
      await mkdir(path.join(tempDir, subdir));
    }

    const borrados = await purgeOldLogs({ dir: tempDir, days, now });
    expect(borrados.sort()).toEqual([...vencidos].sort());

    const restantes = (await readdir(tempDir)).sort();
    expect(restantes).toEqual([...conservados, ...subdirectorios].sort());
  });

  it('devuelve [] si el directorio no existe', async () => {
    const inexistente = path.join(tempDir, 'no-existe');
    const borrados = await purgeOldLogs({ dir: inexistente, days: 30, now: new Date() });
    expect(borrados).toEqual([]);
  });
});
