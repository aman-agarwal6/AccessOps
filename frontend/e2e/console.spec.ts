import { test, expect, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { mkdir } from "node:fs/promises";

const wcag = ["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"];
async function axe(page: Page) {
  const result = await new AxeBuilder({ page }).withTags(wcag).analyze();
  expect(result.violations).toEqual([]);
}
async function useTheme(page: Page, theme: "dark" | "light") {
  await page.addInitScript((value) => {
    localStorage.setItem("accessops-theme", value);
  }, theme);
}

test("public simulation completes the employee and agent containment walkthrough", async ({
  page,
}) => {
  const requests: string[] = [];
  page.on("request", (r) => {
    if (r.url().includes("/api/") || r.url().includes("/auth/"))
      requests.push(r.url());
  });
  await page.goto("/");
  await expect(
    page.getByText("Browser simulation", { exact: true }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Containment walkthrough", exact: true })
    .first()
    .click();
  const coach = page.getByRole("region", { name: "Guided scenario" });
  for (const label of [
    "Check existing access",
    "Confirm affected scope",
    "Apply containment",
    "Check simulated provider",
    "Retry both reads",
    "Inspect the evidence",
  ])
    await coach.getByRole("button", { name: label, exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Runs & evidence", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Recorded local runs", exact: true }),
  ).toBeVisible();
  await expect(
    page
      .locator(".simulation-evidence")
      .getByText("Identity is not active.", { exact: true }),
  ).toHaveCount(2);
  await expect(page.getByText(/0 simulated resource effects/)).toHaveCount(2);
  expect(requests).toEqual([]);
});

test("request path blocks self approval then applies an independently approved grant", async ({
  page,
}) => {
  await page.goto("/#/requests");
  await page.getByRole("button", { name: "Open request RQ-1043" }).click();
  const drawer = page.getByRole("dialog");
  await drawer
    .getByRole("button", { name: "Approve exact change", exact: true })
    .click();
  await expect(drawer.getByRole("alert")).toContainText(
    "cannot approve their own",
  );
  await drawer
    .getByRole("button", { name: "Switch to Avery, reviewer" })
    .click();
  await drawer
    .getByRole("button", { name: "Approve exact change", exact: true })
    .click();
  await expect(
    drawer.getByRole("heading", { name: "Approved, ready to apply" }),
  ).toBeVisible();
  await drawer.getByRole("button", { name: "Apply approved change" }).click();
  await expect(
    drawer.getByRole("heading", { name: "Applied, awaiting observation" }),
  ).toBeVisible();
  await drawer
    .getByRole("button", { name: "Check simulated provider" })
    .click();
  await expect(
    drawer.getByRole("heading", { name: "Verification recorded" }),
  ).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
});

test("review drafts do not approve untrusted text; drift does not create access", async ({
  page,
}) => {
  await page.goto("/#/reviews");
  await page.getByRole("button", { name: "Run bounded review" }).click();
  await expect(
    page.getByRole("heading", { name: "Instruction-bearing record excluded" }),
  ).toBeVisible();
  await expect(page.getByText("Excluded from the approval path")).toBeVisible();
  await page.getByRole("button", { name: "Inject synthetic drift" }).click();
  await page.getByRole("button", { name: "Reconcile access" }).click();
  await expect(
    page.getByRole("heading", {
      name: "Provider membership has no active grant",
    }),
  ).toBeVisible();
  await page.getByRole("link", { name: "Identities", exact: true }).click();
  await page
    .getByRole("combobox", { name: "Identity", exact: true })
    .selectOption("leo");
  await page
    .getByRole("combobox", { name: "Resource", exact: true })
    .selectOption("export");
  await page.getByRole("button", { name: "Try simulated read" }).click();
  await expect(
    page.getByText("Denied before effect · Leo Brooks"),
  ).toBeVisible();
});

test("identity registration clearly preserves pending credential binding", async ({
  page,
}) => {
  await page.goto("/#/identities");
  await page
    .getByRole("button", { name: "Register identity", exact: true })
    .click();
  await page
    .getByRole("combobox", { name: "Identity type", exact: true })
    .selectOption("agent");
  await page.getByLabel("Name", { exact: true }).fill("Atlas change assistant");
  await page.getByLabel("Synthetic email").fill("changes@example.test");
  await page.getByRole("button", { name: "Register agent" }).click();
  const drawer = page.getByRole("dialog");
  await expect(drawer).toContainText("credential binding pending");
  await expect(drawer).toContainText("Suspended");
  await expect(drawer).toContainText("No grants are assigned");
});

test("sponsor acceptance survives the reviewed transfer and leaves the agent suspended", async ({
  page,
}) => {
  await page.goto("/#/requests");
  await page.getByRole("button", { name: "New request", exact: true }).click();
  const form = page.getByRole("dialog", { name: "New access request" });
  await form
    .getByRole("combobox", { name: "Identity", exact: true })
    .selectOption("atlas-agent");
  await form
    .getByRole("combobox", { name: "Change", exact: true })
    .selectOption("transfer");
  await form
    .getByRole("combobox", { name: "New accountable sponsor", exact: true })
    .selectOption("nina");
  await form
    .getByLabel("Business reason")
    .fill("Transfer responsibility before the Atlas project handover");
  await form
    .getByRole("button", { name: "Submit request", exact: true })
    .click();
  const drawer = page.getByRole("dialog");
  await expect(drawer).toContainText("Awaiting the named successor");
  await drawer
    .getByRole("button", { name: "Switch to Nina, successor" })
    .click();
  await drawer
    .getByRole("button", { name: "Accept sponsorship", exact: true })
    .click();
  await expect(drawer).toContainText("Accepted by Nina Okafor");
  await expect(
    drawer.getByRole("button", { name: "Accept sponsorship", exact: true }),
  ).toHaveCount(0);
  await drawer
    .getByRole("button", { name: "Switch to Avery, reviewer" })
    .click();
  await drawer
    .getByRole("button", { name: "Approve exact change", exact: true })
    .click();
  await drawer
    .getByRole("button", { name: "Apply approved change", exact: true })
    .click();
  await page.keyboard.press("Escape");
  await page.getByRole("link", { name: "Identities", exact: true }).click();
  await page
    .getByRole("button", {
      name: "Atlas digest Agent · Read-only project assistant",
    })
    .click();
  const identity = page.getByRole("dialog");
  await expect(identity).toContainText("Nina Okafor");
  await expect(identity).toContainText("Suspended");
  await expect(identity).toContainText("Agent credential binding");
  await expect(identity).toContainText("Revoked");
});

test("recorded evidence viewer preserves the supplied record scope", async ({
  page,
}) => {
  await page.route("**/evidence/index.json", async (route) => {
    await route.fulfill({
      json: {
        runs: [
          {
            id: "viewer-fixture-only",
            name: "Evidence viewer contract fixture",
            scenario: "viewer-contract",
            origin: "recorded",
            status: "passed",
            startedAt: "2026-10-03T12:00:00Z",
            finishedAt: "2026-10-03T12:00:01Z",
            summary: "Viewer contract test fixture; no live provider claim.",
            checks: [
              {
                name: "Fixture display",
                status: "passed",
                detail: "Supplied record fields are displayed.",
              },
            ],
            manifest: {
              limitations: [
                "This synthetic browser test exercises rendering only.",
              ],
            },
          },
        ],
      },
    });
  });
  await page.goto("/#/runs");
  await page
    .getByRole("button", { name: /Evidence viewer contract fixture/ })
    .click();
  const dialog = page.getByRole("dialog", {
    name: "Evidence viewer contract fixture",
  });
  await expect(dialog).toContainText("Recorded local execution");
  await expect(dialog).toContainText("Scope and limitations");
  await expect(dialog).toContainText(
    "This synthetic browser test exercises rendering only.",
  );
  await dialog
    .getByText("Inspect the serialized record", { exact: true })
    .click();
  await expect(dialog.locator("pre")).toContainText("viewer-fixture-only");
  await axe(page);
});

test("evidence loading failures are explicit and recoverable", async ({
  page,
}) => {
  let fail = true;
  await page.route("**/evidence/index.json", async (route) => {
    if (fail) await route.fulfill({ status: 503, body: "unavailable" });
    else await route.fulfill({ json: { runs: [] } });
  });
  await page.goto("/#/runs");
  await expect(page.getByRole("alert")).toContainText("No results are assumed");
  fail = false;
  await page.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "No recorded runs published" }),
  ).toBeVisible();
});

test("published evidence retains limitations and readable raw records", async ({
  page,
}) => {
  const response = await page.request.get("/evidence/index.json");
  const index = await response.json();
  test.skip(
    !index.runs.length,
    "No actual recordings are published in this checkout.",
  );
  await page.goto("/#/runs");
  await expect(page.locator(".run-row")).toHaveCount(index.runs.length);
  for (const status of ["passed", "failed"]) {
    const run = index.runs.find(
      (record: { status: string }) => record.status === status,
    );
    if (!run) continue;
    await page.locator(".run-row").filter({ hasText: run.id }).click();
    const dialog = page.getByRole("dialog", { name: run.name, exact: true });
    await expect(dialog).toContainText("Recorded local execution");
    await expect(dialog).toContainText(run.summary);
    if (run.manifest?.limitations?.length)
      await expect(dialog).toContainText("Scope and limitations");
    await dialog
      .getByText("Inspect the serialized record", { exact: true })
      .click();
    await expect(dialog.locator("pre")).toContainText(run.id);
    await axe(page);
    await page.keyboard.press("Escape");
  }
});

for (const theme of ["dark", "light"] as const)
  for (const route of [
    "overview",
    "cases",
    "cases?case=case-hr-1084",
    "requests",
    "identities",
    "reviews",
    "policies",
    "runs",
  ]) {
    test(`${route} has no WCAG A/AA violations in the ${theme} theme`, async ({
      page,
    }) => {
      await useTheme(page, theme);
      await page.goto(`/#/${route}`);
      await expect(page.locator("html")).toHaveAttribute("data-theme", theme);
      await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
      await axe(page);
    });
  }

test("theme choice is applied, announced and remembered", async ({ page }) => {
  await page.goto("/");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await page.getByRole("button", { name: "Switch to light theme" }).click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await page.reload();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await expect(
    page.getByRole("button", { name: "Switch to dark theme" }),
  ).toBeVisible();
});

test("keyboard opens and closes a focus-managed dialog", async ({ page }) => {
  await page.goto("/");
  const button = page.getByRole("button", { name: "New request", exact: true });
  await button.focus();
  await page.keyboard.press("Enter");
  await expect(
    page.getByRole("dialog", { name: "New access request" }),
  ).toBeVisible();
  await axe(page);
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(button).toBeFocused();
});

test("skip link and navigation move focus to the page content", async ({
  page,
}) => {
  await page.goto("/");
  await page.keyboard.press("Tab");
  await expect(
    page.getByRole("link", { name: "Skip to main content" }),
  ).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.locator("#main-content")).toBeFocused();
  await page.getByRole("link", { name: /^Requests/ }).click();
  await expect(page.locator("#main-content")).toBeFocused();
  await expect(page).toHaveTitle("Requests · AccessOps");
});

test("desktop and mobile layouts are readable without page overflow", async ({
  page,
}) => {
  await mkdir("../output/screenshots", { recursive: true });
  for (const theme of ["dark", "light"] as const) {
    await useTheme(page, theme);
    await page.goto("/");
    await page.screenshot({
      path: `../output/screenshots/accessops-overview-desktop-${theme}.png`,
      fullPage: true,
    });
  }
  await useTheme(page, "dark");
  await page.goto("/#/identities");
  await page.screenshot({
    path: "../output/screenshots/accessops-identities-desktop.png",
    fullPage: true,
  });
  await page.setViewportSize({ width: 390, height: 844 });
  for (const route of ["overview", "cases", "requests", "identities", "runs"]) {
    await page.goto(`/#/${route}`);
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBe(true);
  }
  await page.goto("/");
  await page.screenshot({
    path: "../output/screenshots/accessops-overview-mobile.png",
    fullPage: true,
  });
  const menu = page.getByRole("button", { name: "Open navigation" });
  await expect(
    page.getByRole("link", { name: "Overview", exact: true }),
  ).toBeHidden();
  await menu.click();
  await expect(
    page.getByRole("link", { name: "Overview", exact: true }),
  ).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(menu).toBeFocused();
  await expect(menu).toHaveAttribute("aria-expanded", "false");
  await menu.click();
  await page
    .getByRole("link", { name: "Policies & resources", exact: true })
    .click();
  await expect(
    page.getByRole("heading", { name: "Policies & resources", exact: true }),
  ).toBeVisible();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  await axe(page);
});
