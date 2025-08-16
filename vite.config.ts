import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";
import wasm from "vite-plugin-wasm";

export default defineConfig({
  plugins: [
    react(),
    wasm(),
  ],
  server: {
    port: 5173,
  },
  resolve: {
    alias: {
      "@": "/src",
    },
  },
  optimizeDeps: {
    exclude: ['mlkem']
  }
});
