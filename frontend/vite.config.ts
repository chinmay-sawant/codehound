import path from 'node:path'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// Project Pages URL: https://chinmay-sawant.github.io/codehound/
// Dev server keeps base `/` so local paths work without a prefix.
const isProd = process.env.NODE_ENV === 'production'

// https://vite.dev/config/
export default defineConfig({
  base: isProd ? '/codehound/' : '/',
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  build: {
    // Emit into repo-root docs/ (GitHub Pages source folder).
    outDir: path.resolve(__dirname, '../docs'),
    // Wipe previous assets/html so only the latest build remains.
    emptyOutDir: true,
  },
})