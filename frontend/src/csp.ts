/**
 * Content-Security-Policy for the static simulation published to GitHub
 * Pages, which cannot set response headers. It follows the self-hosted policy
 * in infra/Caddyfile minus the directives a meta tag ignores (frame-ancestors,
 * report-uri, sandbox). Styles keep 'unsafe-inline' for the <style> elements
 * the dialog's scroll lock injects; scripts never do.
 */
export const simulationCsp = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "object-src 'none'",
  "form-action 'self'",
  "base-uri 'self'",
].join("; ");

const CHARSET = '<meta charset="UTF-8" />';

/** Puts the policy right after the charset, ahead of every script and style. */
export function withCsp(html: string, policy = simulationCsp): string {
  if (!html.includes(CHARSET))
    throw new Error("index.html has no charset meta to anchor the CSP");
  return html.replace(
    CHARSET,
    `${CHARSET}\n    <meta http-equiv="Content-Security-Policy" content="${policy}" />`,
  );
}
