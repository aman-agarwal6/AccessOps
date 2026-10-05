import { defineConfig, devices } from "@playwright/test";

// Real-browser journey through the authenticated local lab. Runs only inside the
// opt-in `browser-tests` compose service (infra/compose.browser.yml), which joins
// the lab network and trusts the lab CA with full certificate verification.
const reports = process.env.ACCESSOPS_LIVE_REPORTS ?? "../output/connected";

export default defineConfig({
  testDir: "./e2e-live",
  outputDir: "/tmp/accessops-live-results",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 240000,
  expect: { timeout: 15000 },
  reporter: [
    ["list"],
    ["junit", { outputFile: `${reports}/console-live.xml` }],
  ],
  use: {
    baseURL: "https://accessops.test:8443",
    trace: "retain-on-failure",
    acceptDownloads: true,
  },
  projects: [
    {
      name: "firefox",
      use: {
        ...devices["Desktop Firefox"],
        viewport: { width: 1440, height: 1000 },
      },
    },
  ],
});
