import pg from 'pg';
import { config } from './config.js';

// int8 llega como string por defecto. Los valores de este esquema (seq, conteos) están
// lejos de 2^53, así que Number es seguro y evita comparar strings con números.
pg.types.setTypeParser(pg.types.builtins.INT8, (valor) => Number(valor));

export const pool = new pg.Pool({ connectionString: config.databaseUrl });

// Sin este manejador, un error en una conexión inactiva (por ejemplo, reinicio del servidor)
// se emite como 'error' sin escucha y tumba el proceso.
pool.on('error', (err) => {
  process.stderr.write(`Error en conexión inactiva de PostgreSQL: ${err.message}\n`);
});

let cerrado = false;

export async function closePool(): Promise<void> {
  // pool.end() lanza si se llama dos veces, y tanto los tests como el servidor pueden cerrarlo.
  if (cerrado) return;
  cerrado = true;
  await pool.end();
}
