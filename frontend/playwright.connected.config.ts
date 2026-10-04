import { defineConfig, devices } from "@playwright/test";

// Renders a sanitized snapshot recorded from the real lab through the connected
// build. Transport is intercepted: this checks DTO compatibility and display,
// not authentication or provider behavior. Opt in with ACCESSOPS_CONNECTED_SNAPSHOT.
export default defineConfig({
  testDir: "./e2e-connected",
  fullyParallel: false,
  workers: 1,
  timeout: 30000,
  expect: { timeout: 5000 },
  reporter: [
    ["list"],
    ["junit", { outputFile: "../output/connected-renderer-tests.xml" }],
  ],
  use: {
    baseURL: "http://127.0.0.1:4175",
    channel: process.env.CI ? undefined : "chrome",
    trace: "retain-on-failure",
  },
  webServer: {
    command: "npx vite --port 4175 --strictPort",
    url: "http://127.0.0.1:4175",
    reuseExistingServer: false,
    timeout: 30000,
    env: { VITE_ACCESSOPS_MODE: "connected" },
  },
  projects: [
    {
      name: "desktop",
      use: {
        ...devices["Desktop Chrome"],
        viewport: { width: 1440, height: 1000 },
      },
    },
  ],
});
