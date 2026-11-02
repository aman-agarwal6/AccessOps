import { fileURLToPath } from "node:url";
import { build, type Rolldown } from "vite";
import { afterEach, describe, expect, it } from "vitest";
import { simulationCsp } from "./csp";

const root = fileURLToPath(new URL("..", import.meta.url));
const savedMode = process.env.VITE_ACCESSOPS_MODE;

// Runs the real production build in memory, so the check covers the plugin
// wiring and the tags Vite injects into <head>, not just the source HTML.
async function buildFiles(mode: string) {
  process.env.VITE_ACCESSOPS_MODE = mode;
  const result = await build({
    root,
    configFile: `${root}/vite.config.ts`,
    logLevel: "silent",
    build: { write: false, emptyOutDir: false },
  });
  const outputs = (
    Array.isArray(result) ? result : [result]
  ) as Rolldown.RolldownOutput[];
  const files = new Map<string, string>();
  for (const { output } of outputs)
    for (const file of output)
      files.set(
        file.fileName,
        file.type === "chunk"
          ? file.code
          : typeof file.source === "string"
            ? file.source
            : new TextDecoder().decode(file.source),
      );
  return files;
}

afterEach(() => {
  if (savedMode === undefined) delete process.env.VITE_ACCESSOPS_MODE;
  else process.env.VITE_ACCESSOPS_MODE = savedMode;
});

describe("built index.html", () => {
  it("puts the CSP ahead of every script and stylesheet in the Pages build", async () => {
    const files = await buildFiles("simulation");
    const html = files.get("index.html") ?? "";
    const meta = html.indexOf(
      `<meta http-equiv="Content-Security-Policy" content="${simulationCsp}" />`,
    );
    expect(meta).toBeGreaterThan(html.indexOf("<meta charset"));
    expect(meta).toBeLessThan(html.indexOf("<script"));
    expect(meta).toBeLessThan(html.indexOf("<link"));
    expect(html).toContain('<meta name="referrer" content="no-referrer" />');
    // script-src 'self' blocks inline scripts and font-src 'self' blocks
    // fonts Vite inlines as data: URIs.
    expect(html).not.toMatch(/<script(?![^>]*\ssrc=)[^>]*>/);
    for (const [name, text] of files)
      expect(text, name).not.toMatch(/data:(font\/|application\/(x-)?font)/);
  }, 120_000);

  it("leaves the CSP to Caddy in the connected build", async () => {
    const html = (await buildFiles("connected")).get("index.html") ?? "";
    expect(html).toContain("<script");
    expect(html).not.toContain("Content-Security-Policy");
    expect(html).toContain('<meta name="referrer" content="no-referrer" />');
  }, 120_000);
});
