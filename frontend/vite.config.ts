import path from 'node:path'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
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