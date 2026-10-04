import { test, expect, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { mkdir, readFile } from "node:fs/promises";

const wcag = ["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"];
async function axe(page: Page) {
  const result = await new AxeBuilder({ page }).withTags(wcag).analyze();
  expect(result.violations).toEqual([]);
}
const nextStep = (page: Page) =>
  page.getByRole("region", { name: /./ }).filter({
    has: page.locator("#next-step-title"),
  });
const actingAs = (page: Page) =>
  page.getByLabel("Acting as (simulated operator)");

test("a departure stays open until owner evidence and an independent reviewer close it", async ({
  page,
}) => {
  await page.goto("/#/cases");
  await page
    .getByRole("button", { name: /^Mara Patel, employee departure/ })
    .click();
  const step = nextStep(page);
  await expect(step.getByRole("heading")).toHaveText("Contain local access");
  await expect(
    page.getByRole("button", { name: "Review & close case" }),
  ).toHaveCount(0);
  await expect(page.getByText(/blockers keep this case open/)).toBeVisible();

  await step.getByRole("button", { name: "Apply local containment" }).click();
  await expect(page.getByRole("status").first()).toContainText(
    "Local access contained",
  );
  await expect(
    page.locator(".task .prov-simulated", { hasText: "Simulated observation" }),
  ).toHaveCount(2);
  await expect(step.getByRole("heading")).toHaveText(
    "Import an after-departure platform report",
  );

  await step.getByRole("button", { name: "Import platform report" }).click();
  const importer = page.getByRole("dialog", { name: "Import platform report" });
  await importer
    .getByRole("button", { name: "Load after-departure fixture" })
    .click();
  const report = JSON.parse(
    await importer.getByLabel("Canonical report JSON").inputValue(),
  );
  expect(report.collectionMethod).toBe("synthetic_fixture");
  expect(
    report.observations
      .filter((entry: { provider: string }) => entry.provider === "github")
      .every((entry: { status: string }) => entry.status === "unknown"),
  ).toBe(true);
  await importer
    .getByRole("button", { name: "Assess & import report" })
    .click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(page.locator(".task .prov-imported")).toHaveCount(1);
  await expect(step.getByRole("heading")).toHaveText(
    "Record owner evidence · 6 remaining",
  );

  for (let index = 0; index < 6; index++) {
    await step.getByRole("button", { name: "Record next statement" }).click();
    const dialog = page.getByRole("dialog", { name: "Record owner evidence" });
    await dialog
      .getByLabel("Evidence reference")
      .fill(`CHG-1084-OWNER-${index + 1}`);
    await dialog
      .getByLabel("Owner evidence summary")
      .fill(
        "Synthetic owner records the completed scoped action and handover. Sessions, copied data and unsupported credentials remain within the stated limits.",
      );
    await dialog
      .getByRole("button", { name: "Save owner attestation" })
      .click();
    await expect(page.getByRole("dialog")).toHaveCount(0);
  }

  await expect(step.getByRole("heading")).toHaveText(
    "Ready for independent review",
  );
  await expect(step).toContainText("Closure needs an independent reviewer");
  await expect(
    step.getByRole("button", { name: "Review & close case" }),
  ).toBeDisabled();
  await step.getByRole("button", { name: "Act as Avery Chen" }).click();
  await expect(actingAs(page)).toHaveValue("op-avery");
  await step.getByRole("button", { name: "Review & close case" }).click();
  const review = page.getByRole("dialog", {
    name: "Review administrative closure",
  });
  await expect(review).toContainText("All 9 actions are accounted for");
  await expect(review).toContainText("6 × owner attestation");
  await review
    .getByRole("button", { name: "Accept evidence & close case" })
    .click();
  await expect(page.getByTestId("case-status")).toHaveText("Closed");
  await expect(step.getByRole("heading")).toHaveText(
    "Closed on reviewed evidence",
  );
  await expect(
    page.getByRole("button", { name: "Import platform report" }),
  ).toBeDisabled();
  await expect(page.locator(".task .prov-attested")).toHaveCount(6);

  const download = page.waitForEvent("download");
  await page
    .getByRole("button", { name: "Export closure packet" })
    .first()
    .click();
  const packet = JSON.parse(
    await readFile((await (await download).path())!, "utf8"),
  );
  expect(packet).toMatchObject({
    mode: "browser_simulation",
    outcome: "administrative_closure",
    case: { closureBasis: "reviewed_evidence", closedById: "op-avery" },
  });
  expect(packet.limitations.join(" ")).toContain(
    "no external platforms were contacted",
  );
  await axe(page);
});

test("role boundaries are explained, never silently bypassed", async ({
  page,
}) => {
  await page.goto("/#/cases?case=case-hr-1084");
  await actingAs(page).selectOption("nina");
  const step = nextStep(page);
  await expect(step).toContainText("Requires the operator role.");
  await expect(
    step.getByRole("button", { name: "Apply local containment" }),
  ).toBeDisabled();
  await expect(
    page.getByRole("button", { name: "Record owner evidence" }),
  ).toHaveCount(0);
  await step.getByRole("button", { name: "Act as Jules Morgan" }).click();
  await expect(
    step.getByRole("button", { name: "Apply local containment" }),
  ).toBeEnabled();
});

test("the queue separates overdue, scheduled and closed departures", async ({
  page,
}) => {
  await page.goto("/#/cases");
  const filters = page.getByRole("group", { name: "Filter departures" });
  await filters.getByRole("button", { name: /^Overdue/ }).click();
  await expect(page.getByRole("button", { name: /^Leo Brooks/ })).toContainText(
    "Overdue",
  );
  await expect(page.getByRole("button", { name: /^Mara Patel/ })).toHaveCount(
    0,
  );
  await filters.getByRole("button", { name: /^Scheduled/ }).click();
  await page.getByRole("button", { name: /^Sam Rivera/ }).click();
  await expect(nextStep(page).getByRole("heading")).toHaveText(
    "Waiting for the departure date",
  );
  await expect(
    page.getByRole("button", { name: "Record owner evidence" }),
  ).toHaveCount(0);
  await page.getByRole("link", { name: "All departure cases" }).click();
  await filters.getByRole("button", { name: /^Closed/ }).click();
  await page.getByRole("button", { name: /^Priya Nair/ }).click();
  await expect(page.getByTestId("case-status")).toHaveText("Closed");
  await expect(page.locator(".task .prov-attested")).toHaveCount(6);
  await expect(page.locator(".task .prov-imported")).toHaveCount(1);
  await axe(page);
});

test("public import rejects malformed and cross-bound reports with accessible errors", async ({
  page,
}) => {
  await page.goto("/#/cases?case=case-hr-1084");
  await page
    .getByRole("button", { name: "Import platform report" })
    .first()
    .click();
  const dialog = page.getByRole("dialog", { name: "Import platform report" });
  await dialog.getByLabel("Canonical report JSON").fill("{malformed");
  await dialog.getByRole("button", { name: "Assess & import report" }).click();
  await expect(dialog.getByRole("alert")).toContainText("not valid JSON");
  await dialog
    .getByRole("button", { name: "Load after-departure fixture" })
    .click();
  const report = JSON.parse(
    await dialog.getByLabel("Canonical report JSON").inputValue(),
  );
  report.observations[0].subjectId = "33333333-3333-4333-8333-333333333333";
  await dialog.getByLabel("Canonical report JSON").fill(JSON.stringify(report));
  await dialog.getByRole("button", { name: "Assess & import report" }).click();
  await expect(dialog.getByRole("alert")).toHaveText(
    "The report does not match this case’s explicitly bound tenant and account.",
  );
  await axe(page);
});

test("case detail works on desktop and mobile without overflow", async ({
  page,
}) => {
  await mkdir("../output/screenshots", { recursive: true });
  await page.goto("/#/cases");
  await page.screenshot({
    path: "../output/screenshots/accessops-queue-desktop.png",
    fullPage: true,
  });
  await page.goto("/#/cases?case=case-hr-1084");
  await expect(
    nextStep(page).getByRole("button", { name: "Apply local containment" }),
  ).toBeVisible();
  await page.screenshot({
    path: "../output/screenshots/accessops-offboarding-desktop.png",
    fullPage: true,
  });
  await page.setViewportSize({ width: 390, height: 844 });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  await page.screenshot({
    path: "../output/screenshots/accessops-offboarding-mobile.png",
    fullPage: true,
  });
  await page
    .getByRole("button", { name: "Import platform report" })
    .first()
    .click();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  await axe(page);
});
