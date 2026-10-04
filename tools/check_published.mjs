// Checks only the authorized public, synthetic AccessOps simulation.
// ACCESSOPS_CHECK_URL may point at a loopback preview build for a dry run.
import {
  chromium,
  expect,
} from "../frontend/node_modules/@playwright/test/index.mjs";
import { mkdir, readFile, writeFile } from "node:fs/promises";

const published = "https://aman-agarwal6.github.io/AccessOps/";
const base = process.env.ACCESSOPS_CHECK_URL ?? published;
if (
  base !== published &&
  !/^http:\/\/(127\.0\.0\.1|localhost):\d+\/$/.test(base)
)
  throw new Error("Only the published demo or a loopback preview is allowed.");
const report =
  base === published
    ? "output/published-demo-checks.json"
    : "output/published-demo-dry-run.json";
const shots = base === published ? "published" : "preview";
const startedAt = new Date().toISOString();
const checks = [];
const browser = await chromium.launch({
  channel: process.env.CI ? undefined : "chrome",
});
const context = await browser.newContext({
  viewport: { width: 1440, height: 1000 },
  acceptDownloads: true,
});
const page = await context.newPage();
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
const nextStep = () =>
  page
    .getByRole("region", { name: /./ })
    .filter({ has: page.locator("#next-step-title") });

async function check(name, action) {
  try {
    await action();
    checks.push({ name, status: "passed" });
  } catch (error) {
    checks.push({ name, status: "failed" });
    throw new Error(`Published check failed: ${name}`, { cause: error });
  }
}

try {
  await mkdir("output/screenshots", { recursive: true });
  await check("HTTPS page, simulation boundary and dark default", async () => {
    const response = await page.goto(base);
    expect(response.status()).toBe(200);
    if (base === published) expect(new URL(page.url()).protocol).toBe("https:");
    await expect(
      page.getByText("Browser simulation", { exact: true }),
    ).toBeVisible();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
    await page.screenshot({
      path: `output/screenshots/${shots}-overview-desktop.png`,
    });
  });
  for (const [route, title] of [
    ["overview", "Overview"],
    ["cases", "Offboarding cases"],
    ["requests", "Requests"],
    ["identities", "Identities"],
    ["reviews", "Access reviews"],
    ["policies", "Policies & resources"],
    ["runs", "Runs & evidence"],
  ]) {
    await check(`Route: ${route}`, async () => {
      await page.goto(`${base}#/${route}`);
      await expect(
        page.getByRole("heading", { level: 1, name: title, exact: true }),
      ).toBeVisible();
    });
  }
  await check(
    "Recorded records load with failures retained and are labeled unsigned",
    async () => {
      const response = await page.request.get(`${base}evidence/index.json`);
      expect(response.status()).toBe(200);
      const records = (await response.json()).runs;
      expect(records.length).toBeGreaterThan(0);
      expect(records.every((record) => record.origin === "recorded")).toBe(
        true,
      );
      expect(records.some((record) => record.status === "failed")).toBe(true);
      await page.goto(`${base}#/runs`);
      await expect(page.locator(".run-row")).toHaveCount(records.length);
      await expect(
        page.getByText("Local hashes are not signatures.", { exact: false }),
      ).toBeVisible();
    },
  );
  await check("Containment walkthrough denies both reads", async () => {
    await page.goto(base);
    await page
      .getByRole("button", { name: "Containment walkthrough", exact: true })
      .click();
    const coach = page.getByRole("region", { name: "Guided scenario" });
    for (const name of [
      "Check existing access",
      "Confirm affected scope",
      "Apply containment",
      "Check simulated provider",
      "Retry both reads",
      "Inspect the evidence",
    ])
      await coach.getByRole("button", { name, exact: true }).click();
    await expect(
      page
        .locator(".simulation-evidence")
        .getByText("Identity is not active.", { exact: true }),
    ).toHaveCount(2);
    await expect(page.getByText(/0 simulated resource effects/)).toHaveCount(2);
  });
  await check("Source link points to the published repository", async () => {
    await page.goto(base);
    await page.getByRole("button", { name: "Run it locally" }).click();
    await expect(
      page.getByRole("link", { name: /Setup guide on GitHub/ }),
    ).toHaveAttribute(
      "href",
      "https://github.com/aman-agarwal6/AccessOps#readme",
    );
    await page.keyboard.press("Escape");
  });
  await check("Departure case explains blocked roles and closure", async () => {
    await page
      .getByRole("button", { name: "Reset the browser simulation" })
      .click();
    await page
      .getByRole("button", { name: "Reset simulation", exact: true })
      .click();
    await page.goto(`${base}#/cases?case=case-hr-1084`);
    await expect(
      page.getByRole("button", { name: "Review & close case" }),
    ).toHaveCount(0);
    await page
      .getByLabel("Acting as (simulated operator)")
      .selectOption("nina");
    await expect(nextStep()).toContainText("Requires the operator role.");
    await page
      .getByLabel("Acting as (simulated operator)")
      .selectOption("op-jules");
  });
  await check(
    "Containment, imported snapshot and unknown GitHub stay distinct",
    async () => {
      await nextStep()
        .getByRole("button", { name: "Apply local containment" })
        .click();
      await expect(
        page.locator(".task .prov-simulated", {
          hasText: "Simulated observation",
        }),
      ).toHaveCount(2);
      await nextStep()
        .getByRole("button", { name: "Import platform report" })
        .click();
      const dialog = page.getByRole("dialog", {
        name: "Import platform report",
      });
      await dialog
        .getByRole("button", { name: "Load after-departure fixture" })
        .click();
      const fixture = JSON.parse(
        await dialog.getByLabel("Canonical report JSON").inputValue(),
      );
      expect(fixture.collectionMethod).toBe("synthetic_fixture");
      expect(
        fixture.observations
          .filter((o) => o.provider === "github")
          .every((o) => o.status === "unknown"),
      ).toBe(true);
      await dialog
        .getByRole("button", { name: "Assess & import report" })
        .click();
      await expect(page.locator(".task .prov-imported")).toHaveCount(1);
      await expect(nextStep().getByRole("heading")).toHaveText(
        "Record owner evidence · 6 remaining",
      );
      await page.screenshot({
        path: `output/screenshots/${shots}-offboarding-desktop.png`,
      });
    },
  );
  await check(
    "Independent review closes the case and exports a labeled packet",
    async () => {
      for (let i = 0; i < 6; i++) {
        await nextStep()
          .getByRole("button", { name: "Record next statement" })
          .click();
        const dialog = page.getByRole("dialog", {
          name: "Record owner evidence",
        });
        await dialog
          .getByLabel("Evidence reference")
          .fill(`SYNTHETIC-OWNER-${i + 1}`);
        await dialog
          .getByLabel("Owner evidence summary")
          .fill(
            "Synthetic owner records scoped handover for this fictional case. Existing sessions, copied data and unsupported credentials remain within the stated limits.",
          );
        await dialog
          .getByRole("button", { name: "Save owner attestation" })
          .click();
        await expect(page.getByRole("dialog")).toHaveCount(0);
      }
      await expect(
        nextStep().getByRole("button", { name: "Review & close case" }),
      ).toBeDisabled();
      await nextStep()
        .getByRole("button", { name: "Act as Avery Chen" })
        .click();
      await nextStep()
        .getByRole("button", { name: "Review & close case" })
        .click();
      await page
        .getByRole("dialog", { name: "Review administrative closure" })
        .getByRole("button", { name: "Accept evidence & close case" })
        .click();
      await expect(page.getByTestId("case-status")).toHaveText("Closed");
      const download = page.waitForEvent("download");
      await page
        .getByRole("button", { name: "Export closure packet" })
        .first()
        .click();
      const packet = JSON.parse(
        await readFile(await (await download).path(), "utf8"),
      );
      expect(packet.mode).toBe("browser_simulation");
      expect(packet.outcome).toBe("administrative_closure");
      expect(packet.case.closedById).toBe("op-avery");
      expect(packet.limitations.join(" ")).toContain(
        "no external platforms were contacted",
      );
    },
  );
  await check("Light theme applies and persists", async () => {
    await page.getByRole("button", { name: "Switch to light theme" }).click();
    await page.reload();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
    await page.getByRole("button", { name: "Switch to dark theme" }).click();
  });
  await check("Mobile layouts fit their viewport", async () => {
    await page.setViewportSize({ width: 390, height: 844 });
    for (const route of ["overview", "cases?case=case-hr-1079", "runs"]) {
      await page.goto(`${base}#/${route}`);
      await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
      expect(
        await page.evaluate(
          () => document.documentElement.scrollWidth <= innerWidth,
        ),
      ).toBe(true);
    }
    await page.screenshot({
      path: `output/screenshots/${shots}-runs-mobile.png`,
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
    report,
    JSON.stringify(
      {
        origin:
          base === published ? "published-browser-check" : "preview-dry-run",
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
      passed: checks.filter((entry) => entry.status === "passed").length,
      failed: checks.filter((entry) => entry.status === "failed").length,
    }),
  );
}
