import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { simulationCsp, withCsp } from "./csp";

const indexHtml = readFileSync(
  new URL("../index.html", import.meta.url),
  "utf8",
);
const directives = new Map(
  simulationCsp.split("; ").map((d) => {
    const [name, ...sources] = d.split(" ");
    return [name, sources] as const;
  }),
);

describe("static simulation CSP", () => {
  it("never allows inline or evaluated scripts", () => {
    expect(directives.get("script-src")).toEqual(["'self'"]);
    expect(simulationCsp).not.toMatch(/unsafe-eval|unsafe-hashes|\*/);
    expect(directives.get("object-src")).toEqual(["'none'"]);
    expect(directives.get("base-uri")).toEqual(["'self'"]);
  });
  it("keeps every fetch on the page's own origin", () => {
    for (const name of ["default-src", "connect-src", "font-src"])
      expect(directives.get(name)).toEqual(["'self'"]);
  });
  it("leaves out directives that a meta tag ignores", () => {
    for (const name of ["frame-ancestors", "report-uri", "sandbox"])
      expect(directives.has(name)).toBe(false);
  });
  it("lands ahead of every script and stylesheet in index.html", () => {
    const html = withCsp(indexHtml);
    const meta = html.indexOf('http-equiv="Content-Security-Policy"');
    expect(meta).toBeGreaterThan(html.indexOf("<meta charset"));
    expect(meta).toBeLessThan(html.indexOf("<script"));
    expect(meta).toBeLessThan(html.indexOf("<link"));
    expect(html).toContain(`content="${simulationCsp}"`);
  });
  it("refuses to build when the anchor is missing", () => {
    expect(() => withCsp("<html><head></head></html>")).toThrow(/charset/);
  });
  it("sends no referrer from the page", () => {
    expect(indexHtml).toContain(
      '<meta name="referrer" content="no-referrer" />',
    );
  });
});
