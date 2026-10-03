// Checks only the authorized public, synthetic AccessOps simulation.
import {
  chromium,
  expect,
} from "../frontend/node_modules/@playwright/test/index.mjs";
import { mkdir, writeFile } from "node:fs/promises";

const base = "https://aman-agarwal6.github.io/AccessOps/";
const startedAt = new Date().toISOString();
const checks = [];
const browser = await chromium.launch({
  channel: process.env.CI ? undefined : "chrome",
});
const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
page.setDefaultTimeout(15000);
page.setDefaultNavigationTimeout(20000);
const requests = [];
const pageErrors = [];
const badResponses = [];
page.on("request", (request) => requests.push(new URL(request.url())));
page.on("pageerror", () => pageErrors.push("browser exception"));
page.on("response", (response) => {
  if (response.status() >= 400) badResponses.push(response.status());
});

async function check(name, action) {
  try {
    await action();
    checks.push({ name, status: "passed" });
  } catch {
    checks.push({ name, status: "failed" });
    throw new Error(`Published check failed: ${name}`);
  }
}

try {
  await check("HTTPS page and simulation boundary", async () => {
    const response = await page.goto(base);
    expect(response.status()).toBe(200);
    await expect(
      page.getByText("Browser simulation", { exact: true }),
    ).toBeVisible();
    await expect(page.getByText(/\d+ recorded local runs/)).toBeVisible();
    await mkdir("output/screenshots", { recursive: true });
    await page.screenshot({
      path: "output/screenshots/published-overview-desktop.png",
      fullPage: true,
    });
  });
  for (const [route, title] of [
    ["overview", "Access operations"],
    ["requests", "Requests"],
    ["identities", "Identities"],
    ["reviews", "Access reviews"],
    ["policies", "Policies & resources"],
    ["runs", "Runs & evidence"],
  ]) {
    await check(`Published route: ${route}`, async () => {
      await page.goto(`${base}#/${route}`);
      await expect(
        page.getByRole("heading", { name: title, exact: true }),
      ).toBeVisible();
    });
  }
  await check("Actual published records load", async () => {
    const response = await page.request.get(`${base}evidence/index.json`);
    expect(response.status()).toBe(200);
    const records = (await response.json()).runs;
    expect(records.length).toBeGreaterThan(0);
    expect(records.every((record) => record.origin === "recorded")).toBe(true);
    expect(records.some((record) => record.status === "failed")).toBe(true);
    await expect(
      page.getByRole("heading", { name: "Recorded local runs", exact: true }),
    ).toBeVisible();
  });
  await check("Published guided containment denies both reads", async () => {
    await page.goto(base);
    await page
      .getByRole("button", { name: "Start guided scenario", exact: true })
      .click();
    const coach = page.getByRole("region", { name: "Guided scenario" });
    for (const name of [
      "Check existing access",
      "Confirm affected scope",
      "Apply containment",
      "Check simulated provider",
      "Retry both reads",
      "Inspect the evidence",
    ]) {
      await coach.getByRole("button", { name, exact: true }).click();
    }
    await expect(
      page
        .locator(".simulation-evidence")
        .getByText("Identity is not active.", { exact: true }),
    ).toHaveCount(2);
    await expect(page.getByText(/0 simulated resource effects/)).toHaveCount(2);
  });
  await check("Source link points to the published repository", async () => {
    await page.goto(base);
    await page
      .getByRole("button", { name: "Run the connected lab", exact: true })
      .click();
    await expect(
      page.getByRole("link", { name: "Open source & setup instructions" }),
    ).toHaveAttribute("href", "https://github.com/aman-agarwal6/AccessOps");
    await page.keyboard.press("Escape");
  });
  await check("Mobile overview fits its viewport", async () => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto(base);
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBe(true);
    await page.screenshot({
      path: "output/screenshots/published-overview-mobile.png",
      fullPage: true,
    });
  });
  await check(
    "No protected APIs, third-party requests or browser errors",
    async () => {
      expect(
        requests.every(
          (url) =>
            url.origin === new URL(base).origin &&
            !/\/(api|auth)\//.test(url.pathname),
        ),
      ).toBe(true);
      expect(pageErrors).toEqual([]);
      expect(badResponses).toEqual([]);
    },
  );
} finally {
  await browser.close();
  await mkdir("output", { recursive: true });
  await writeFile(
    "output/published-demo-checks.json",
    JSON.stringify(
      {
        origin: "published-browser-check",
        url: base,
        startedAt,
        finishedAt: new Date().toISOString(),
        checks,
        limitations: [
          "Public synthetic simulation only; no connected-provider or full accessibility claim.",
        ],
      },
      null,
      2,
    ),
  );
  console.log(
    JSON.stringify({
      passed: checks.filter((check) => check.status === "passed").length,
      failed: checks.filter((check) => check.status === "failed").length,
    }),
  );
}
