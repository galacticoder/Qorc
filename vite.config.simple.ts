import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig({
  plugins: [react()],
  base: './',
  server: {
    port: 5173,
    strictPort: true,
    open: false
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
      // Avoid lucide-react's namespace re-export causing "Export 'index' is not defined in module"
      'lucide-react$': 'lucide-react/dist/esm/icons/index.js',
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    chunkSizeWarningLimit: 1000, // Increase limit to 1MB to reduce warnings while we optimize
    rollupOptions: {
      output: {
        manualChunks: (id) => {
          // Collapse all third-party dependencies into a single vendor chunk to avoid
          // cross-chunk circular imports that can break in Electron.
          if (id.includes('node_modules')) {
            return 'vendor';
          }
          // Keep app code in main chunk (let Rollup decide further splitting if needed)
          return undefined;
        },
        
        // Optimize chunk file names for caching
        chunkFileNames: (chunkInfo) => {
          const facadeModuleId = chunkInfo.facadeModuleId 
            ? chunkInfo.facadeModuleId.split('/').pop()?.replace(/\.(js|ts|tsx)$/, '') 
            : chunkInfo.name || 'chunk';
          return `assets/${facadeModuleId}-[hash].js`;
        },
        
        // Optimize entry file names
        entryFileNames: 'assets/[name]-[hash].js',
        
        // Optimize asset file names
        assetFileNames: 'assets/[name]-[hash].[ext]'
      }
    },
    
    // Enable more aggressive minification
    minify: 'terser',
    terserOptions: {
      compress: {
        drop_console: true, // Remove console logs in production
        drop_debugger: true,
        pure_funcs: ['console.log', 'console.info', 'console.debug', 'console.warn']
      },
      mangle: {
        safari10: true
      }
    }
  },
  define: {
    global: 'globalThis',
  },
  optimizeDeps: {
    exclude: ['electron']
  }
})
