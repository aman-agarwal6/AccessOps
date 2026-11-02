import type { Plugin } from "vite";
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import { withCsp } from "./src/csp.ts";

// Static simulation builds carry their CSP in a meta tag; the connected build
// gets it from Caddy, and the dev server needs inline HMR scripts. The mode is
// read from Vite's resolved env, the same values the app's import.meta.env sees.
const simulationCspMeta = (): Plugin => {
  let connected = false;
  return {
    name: "accessops-simulation-csp",
    apply: "build",
    configResolved: (config) => {
      connected = config.env.VITE_ACCESSOPS_MODE === "connected";
    },
    transformIndexHtml: {
      order: "pre",
      handler: (html) => (connected ? html : withCsp(html)),
    },
  };
};

export default defineConfig({
  plugins: [react(), simulationCspMeta()],
  base: "./",
  server: { host: "127.0.0.1", port: 4173, strictPort: true },
  preview: { host: "127.0.0.1", port: 4173, strictPort: true },
  test: { include: ["src/**/*.test.ts"], environment: "node" },
});
