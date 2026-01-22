import { defineConfig, Plugin } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

const stripCrossorigin = (): Plugin => ({
  name: 'strip-crossorigin',
  transformIndexHtml(html) {
    return html.replace(/\s+crossorigin(=("[^"]*"|'[^']*'|[^\s>]+))?/gi, '')
  },
})

export default defineConfig({
  plugins: [stripCrossorigin(), react({ babel: { plugins: ['babel-plugin-react-compiler'] } })],
  base: './',
  server: {
    port: 5173,
    strictPort: true,
    open: false
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, '../src'),
      'lucide-react$': 'lucide-react/dist/esm/icons/index.js',
    },
  },
  build: {
    sourcemap: true,
    outDir: 'dist',
    emptyOutDir: true,
    chunkSizeWarningLimit: 1000,
    rollupOptions: {
      output: {
        manualChunks: (id) => {
          if (id.includes('node_modules')) {
            return 'vendor'
          }
          return undefined
        },
        chunkFileNames: (chunkInfo) => {
          const facadeModuleId = chunkInfo.facadeModuleId
            ? chunkInfo.facadeModuleId.split('/').pop()?.replace(/\.(js|ts|tsx)$/, '')
            : chunkInfo.name || 'chunk'
          return `assets/${facadeModuleId}-[hash].js`
        },
        entryFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash].[ext]'
      }
    },
  },
  define: {
    global: 'globalThis',
  },

})

