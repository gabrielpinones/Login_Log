import { verifyAgainstFiles, verifyChain } from '../src/audit/verify.js';
import { closePool } from '../src/db.js';

const incluirArchivos = process.argv.slice(2).includes('--files');

try {
  const resultado = await verifyChain();
  if (resultado.ok) {
    console.log(
      `Cadena íntegra: ${resultado.count} eventos (último seq=${resultado.lastSeq ?? 'ninguno'}, último hash=${resultado.lastHash ?? 'ninguno'})`,
    );
  } else {
    console.error(
      `Cadena rota en seq=${resultado.brokenSeq}: ${resultado.problem} (${resultado.count} filas revisadas)`,
    );
    process.exitCode = 1;
  }

  if (incluirArchivos) {
    const archivos = await verifyAgainstFiles();
    if (archivos.mismatches.length === 0 && archivos.malformedLines === 0) {
      console.log(
        `Archivos verificados: ${archivos.linesChecked} líneas comprobadas, 0 líneas malformadas, sin diferencias`,
      );
    } else {
      if (archivos.mismatches.length > 0) {
        const detalle = archivos.mismatches.map((m) => `seq=${m.seq}:${m.problem}`).join(', ');
        console.error(
          `Diferencias con archivos (${archivos.mismatches.length} en ${archivos.linesChecked} líneas): ${detalle}`,
        );
      }
      if (archivos.malformedLines > 0) {
        console.error(
          `Líneas malformadas en archivos (${archivos.malformedLines}, ${archivos.linesChecked} líneas válidas comprobadas)`,
        );
      }
      process.exitCode = 1;
    }
  }
} catch (err) {
  const msg = err instanceof Error ? err.message : String(err);
  console.error(`Error al verificar la cadena: ${msg}`);
  process.exitCode = 1;
} finally {
  await closePool();
}
