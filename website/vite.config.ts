import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'

const rootDirectory = dirname(fileURLToPath(import.meta.url))

export default defineConfig({
  base: process.env.WEBSITE_BASE_PATH || '/',
  plugins: [react()],
  build: {
    rollupOptions: {
      input: {
        en: resolve(rootDirectory, 'index.html'),
        ckb: resolve(rootDirectory, 'ckb/index.html'),
        kmr: resolve(rootDirectory, 'kmr/index.html'),
      },
    },
  },
  test: {
    environment: 'jsdom',
    setupFiles: './src/test/setup.ts',
    include: ['src/**/*.{test,spec}.{ts,tsx}'],
  },
})
