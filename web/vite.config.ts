import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": "http://localhost:3000",
      "/oauth2": "http://localhost:3000",
      "/access": "http://localhost:3000",
      "/.well-known": "http://localhost:3000",
    },
  },
});
