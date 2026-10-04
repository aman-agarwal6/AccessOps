import { test, expect, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { readFile } from "node:fs/promises";

const snapshotPath = process.env.ACCESSOPS_CONNECTED_SNAPSHOT;
type Case = {
  id: string;
  status: string;
  hrEventId: string;
  adBinding?: unknown;
  ownerId: string;
  tasks: { id: string; evidenceKind: string }[];
};

test.skip(
  !snapshotPath,
  "Set ACCESSOPS_CONNECTED_SNAPSHOT to a sanitized lab snapshot.",
);

let snapshot: { offboardingCases: Case[] } & Record<string, unknown>;
const blocked: string[] = [];

test.beforeAll(async () => {
  snapshot = JSON.parse(await readFile(snapshotPath!, "utf8"));
});
async function connect(page: Page) {
  const owner = snapshot.offboardingCases[0]?.ownerId ?? "renderer-only";
  await page.route("**/api/v1/session", (route) =>
    route.fulfill({
      json: {
        authenticated: true,
        mode: "connected",
        // Renderer-only principal: no live session or credential exists here.
        principal: { id: owner, name: "Renderer check", roles: ["operator"] },
      },
    }),
  );
  await page.route("**/api/v1/snapshot", (route) =>
    route.fulfill({ json: snapshot }),
  );
  for (const pattern of ["**/api/**", "**/auth/**"])
    await page.route(pattern, (route) => {
      const url = route.request().url();
      if (url.endsWith("/api/v1/session") || url.endsWith("/api/v1/snapshot"))
        return route.fallback();
      blocked.push(`${route.request().method()} ${url}`);
      return route.abort();
    });
}
async function axe(page: Page) {
  const result = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"])
    .analyze();
  expect(result.violations).toEqual([]);
}

for (const route of [
  "overview",
  "cases",
  "requests",
  "identities",
  "reviews",
  "policies",
  "runs",
])
  test(`connected ${route} renders the recorded lab snapshot`, async ({
    page,
  }) => {
    await connect(page);
    await page.goto(`/#/${route}`);
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    await expect(
      page.getByText("Connected lab", { exact: true }),
    ).toBeVisible();
    await expect(
      page.getByText("Browser simulation", { exact: true }),
    ).toHaveCount(0);
    await axe(page);
    await page.setViewportSize({ width: 390, height: 844 });
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBe(true);
  });

test("a closed directory-enrolled case shows provider observations, never simulation", async ({
  page,
}) => {
  const item = snapshot.offboardingCases.find(
    (entry) => entry.status === "closed" && entry.adBinding,
  );
  test.skip(!item, "Snapshot has no closed directory-enrolled case.");
  await connect(page);
  await page.goto(`/#/cases?case=${encodeURIComponent(item!.id)}`);
  await expect(page.getByTestId("case-status")).toHaveText("Closed");
  const observed = item!.tasks.filter(
    (task) => task.evidenceKind === "provider_observation",
  ).length;
  await expect(page.locator(".task .prov-observed")).toHaveCount(observed);
  await expect(page.locator(".task .prov-simulated")).toHaveCount(0);
  await expect(page.getByText("Samba AD lab (server-enrolled)")).toBeAttached();
  await expect(page.locator("input[name*='Guid' i]")).toHaveCount(0);
  await axe(page);
});

test("connected rendering made no calls beyond the two read endpoints", () => {
  expect(blocked).toEqual([]);
});
