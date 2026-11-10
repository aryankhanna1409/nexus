/// <reference types="vitest" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// In development, /api is proxied to the backend (default http://127.0.0.1:8000).
export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      output: { manualChunks: { react: ["react", "react-dom", "react-router-dom"], charts: ["recharts"] } },
    },
  },
  server: {
    proxy: { "/api": process.env.AEGIS_API_URL ?? "http://127.0.0.1:8000" },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
  },
});
