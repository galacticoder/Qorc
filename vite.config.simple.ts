import { defineConfig, Plugin } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

const stripCrossorigin = (): Plugin => ({
  name: 'strip-crossorigin',
  transformIndexHtml(html) {
    return html.replace(/\s+crossorigin(=("[^"]*"|'[^']*'|[^\s>]+))?/gi, '')
  },
})

const moveScriptsToBody = (): Plugin => ({
  name: 'move-scripts-to-body',
  enforce: 'post',
  transformIndexHtml(html) {
    const scriptRegex = /<script[^>]*>[\s\S]*?<\/script>|<script[^>]*\/>/gi;
    const linkPreloadRegex = /<link[^>]*rel=["']modulepreload["'][^>]*>/gi;
    
    const scripts: string[] = [];
    let cleanedHtml = html;
    
    cleanedHtml = cleanedHtml.replace(linkPreloadRegex, (match) => {
      scripts.push(match);
      return '';
    });
    
    cleanedHtml = cleanedHtml.replace(scriptRegex, (match) => {
      scripts.push(match);
      return '';
    });
    
    const bodyEndIndex = cleanedHtml.lastIndexOf('</body>');
    if (bodyEndIndex !== -1 && scripts.length > 0) {
      cleanedHtml = cleanedHtml.slice(0, bodyEndIndex) + scripts.join('\n  ') + '\n' + cleanedHtml.slice(bodyEndIndex);
    }
    
    return cleanedHtml;
  },
})

export default defineConfig({
  plugins: [stripCrossorigin(), react({ babel: { plugins: ['babel-plugin-react-compiler'] } }), moveScriptsToBody()],
  base: './',
  worker: {
    format: 'es',
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
      'lucide-react$': 'lucide-react/dist/esm/icons/index.js',
    },
  },
  build: {
    sourcemap: false,
    outDir: 'dist',
    emptyOutDir: true,
    chunkSizeWarningLimit: 1000,
    rollupOptions: {
      output: {
        manualChunks: (id) => {
          const normalizedId = id.replaceAll('\\', '/');
          if (!normalizedId.includes('/node_modules/')) {
            if (normalizedId.includes('/src/lib/cryptography/') || normalizedId.includes('/src/lib/crypto/')) {
              return 'crypto-core';
            }
            if (normalizedId.includes('/src/lib/transport/') || normalizedId.includes('/src/lib/websocket/')) {
              return 'transport-core';
            }
            return undefined;
          }
          if (/\/node_modules\/(react|react-dom|scheduler|react-compiler-runtime)\//.test(normalizedId)) {
            return 'react-vendor';
          }
          if (/\/node_modules\/@noble\//.test(normalizedId)) {
            return 'noble-vendor';
          }
          return 'vendor';
        },
        chunkFileNames: (chunkInfo) => {
          const facadeModuleId = chunkInfo.facadeModuleId 
            ? chunkInfo.facadeModuleId.split('/').pop()?.replace(/\.(js|ts|tsx)$/, '') 
            : chunkInfo.name || 'chunk';
          return `assets/${facadeModuleId}-[hash].js`;
        },
        entryFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash].[ext]'
      }
    },
    minify: 'terser',
    terserOptions: {
      compress: {
        drop_console: false,
        drop_debugger: false,
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
  }
})
