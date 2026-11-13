import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    environment: 'node',
    // Todos los archivos comparten la misma base de pruebas y la vacían entre casos.
    fileParallelism: false,
    globalSetup: ['tests/setup/global.ts'],
    env: {
      HTTP_RATE_LIMIT_MAX: '100000',
    },
  },
});
