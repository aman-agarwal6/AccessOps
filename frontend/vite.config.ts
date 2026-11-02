import { loadEnv, type Plugin } from "vite";
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import { withCsp } from "./src/csp.ts";

// Static simulation builds carry their CSP in a meta tag; the connected build
// gets it from Caddy, and the dev server needs inline HMR scripts.
const simulationCspMeta = (): Plugin => ({
  name: "accessops-simulation-csp",
  apply: "build",
  transformIndexHtml: { order: "pre", handler: (html) => withCsp(html) },
});

export default defineConfig(({ mode }) => {
  const connected =
    loadEnv(mode, process.cwd(), "VITE_").VITE_ACCESSOPS_MODE === "connected";
  return {
    plugins: [react(), ...(connected ? [] : [simulationCspMeta()])],
    base: "./",
    server: { host: "127.0.0.1", port: 4173, strictPort: true },
    preview: { host: "127.0.0.1", port: 4173, strictPort: true },
    test: { include: ["src/**/*.test.ts"], environment: "node" },
  };
});
