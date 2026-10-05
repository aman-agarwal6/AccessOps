import { test, expect, type Browser, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { createHmac } from "node:crypto";
import { readFile, rename, writeFile } from "node:fs/promises";

const loginsPath = process.env.ACCESSOPS_LIVE_LOGINS;
const reports = process.env.ACCESSOPS_LIVE_REPORTS ?? "/tmp";
test.skip(!loginsPath, "Run inside the browser-tests compose service.");

type Snapshot = {
  identities: {
    id: string;
    name: string;
    status: string;
    providerSubject?: string;
  }[];
  offboardingCases: {
    id: string;
    hrEventId: string;
    status: string;
    tasks: { id: string; status: string; evidenceKind: string }[];
  }[];
};

let passwords: Record<string, string>;
let authenticators: Record<string, string>;
test.beforeAll(async () => {
  // Generated lab operator passwords and authenticator secrets; never logged or reported.
  const logins = JSON.parse(await readFile(loginsPath!, "utf8"));
  passwords = logins.passwords;
  authenticators = logins.totp;
});

// RFC 6238 code (HMAC-SHA1, six digits) for one 30-second step.
function totp(secret: string, step: number) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const digest = createHmac("sha1", Buffer.from(secret, "utf8"))
    .update(counter)
    .digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const value = (digest.readUInt32BE(offset) & 0x7fffffff) % 1_000_000;
  return value.toString().padStart(6, "0");
}

// Keycloak refuses a reused code, so each step is used once per operator. The
// step file is shared with the Python suites through the report folder.
async function oneTimeCode(person: string) {
  const path = `${reports}/otp-steps.json`;
  let steps: Record<string, number> = {};
  try {
    steps = JSON.parse(await readFile(path, "utf8"));
  } catch {
    steps = {};
  }
  const now = () => Math.floor(Date.now() / 30_000);
  const step = Math.max(now(), (steps[person] ?? -1) + 1);
  while (step > now() + 1) {
    await new Promise((done) =>
      setTimeout(done, Math.max(0, (step - 1) * 30_000 - Date.now() + 200)),
    );
  }
  steps[person] = step;
  await writeFile(`${path}.tmp`, JSON.stringify(steps));
  await rename(`${path}.tmp`, path);
  return totp(authenticators[person], step);
}

// Each operator gets a separate browser profile, as two different people would.
async function operator(browser: Browser, person: "alice" | "bob") {
  const context = await browser.newContext({
    baseURL: "https://accessops.test:8443",
    viewport: { width: 1440, height: 1000 },
    acceptDownloads: true,
  });
  const page = await context.newPage();
  await page.goto("/");
  await page
    .getByRole("link", { name: "Sign in with the lab identity provider" })
    .click();
  await expect(page).toHaveURL(
    /id\.accessops\.test:8443\/realms\/accessops-operators\//,
  );
  await page.locator("#username").fill(person);
  await page.locator("#password").fill(passwords[person]);
  await page.locator("#kc-login").click();
  await page.locator("#otp").fill(await oneTimeCode(person));
  await page.locator("#kc-login").click();
  await expect(page.getByText("Connected lab", { exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
  return page;
}
async function signOut(page: Page) {
  await page
    .getByRole("button", { name: "Sign out of the lab" })
    .first()
    .click();
  await expect(
    page.getByRole("link", { name: "Sign in with the lab identity provider" }),
  ).toBeVisible();
}
// Read through the page's own same-origin fetch: Firefox verifies TLS against the
// lab CA, and failures never echo session or CSRF headers into test reports.
async function snapshot(page: Page): Promise<Snapshot> {
  return page.evaluate(async () => {
    const response = await fetch("/api/v1/snapshot", { cache: "no-store" });
    if (!response.ok)
      throw new Error(`Snapshot read failed: ${response.status}`);
    return response.json();
  });
}
// Contain synthetic workers this test registered but never finished with (an
// interrupted earlier run, or a failure below), as the API suites do.
const WORKER = "UI Worker ";
async function containWorkers(page: Page, only?: string) {
  const open = (await snapshot(page)).identities.filter(
    (item) =>
      item.status === "active" &&
      (only ? item.name === only : item.name.startsWith(WORKER)),
  );
  for (const item of open)
    await page.evaluate(async (identityId) => {
      const token = decodeURIComponent(
        document.cookie
          .split("; ")
          .find((cookie) => cookie.startsWith("csrftoken="))
          ?.slice("csrftoken=".length) ?? "",
      );
      const post = async (path: string, body: object) => {
        const response = await fetch(path, {
          method: "POST",
          cache: "no-store",
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
            "X-CSRFToken": token,
            "Idempotency-Key": crypto.randomUUID(),
          },
          body: JSON.stringify(body),
        });
        if (!response.ok)
          throw new Error(`Fixture containment failed: ${response.status}`);
        return response.json();
      };
      const created = await post("/api/v1/requests", {
        identityId,
        action: "offboard",
        reason: "Contain an interrupted synthetic UI test worker",
      });
      await post(
        `/api/v1/requests/${encodeURIComponent(created.result.id)}/execute`,
        {},
      );
    }, item.id);
  return open.length;
}
async function waitFor<T>(
  read: () => Promise<T | undefined>,
  label: string,
  seconds = 120,
): Promise<T> {
  for (let i = 0; i < seconds; i++) {
    const value = await read();
    if (value !== undefined) return value;
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  throw new Error(`Timed out waiting for ${label}`);
}
const nextStep = (page: Page) => page.locator("section.next-step");
async function axe(page: Page) {
  const result = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"])
    .analyze();
  expect(result.violations).toEqual([]);
}

test("operators close a real departure case through the redesigned console", async ({
  browser,
}) => {
  const suffix = Date.now().toString(36);
  const name = `UI Worker ${suffix}`;

  const page = await operator(browser, "alice");
  const swept = await containWorkers(page);
  test.info().annotations.push({
    type: "fixture-sweep",
    description: `${swept} interrupted UI test worker(s) contained before this run`,
  });
  await axe(page);
  let contained = false;
  try {
    // Register a fresh synthetic employee and wait for real Keycloak provisioning.
    await page.goto("/#/identities");
    await page
      .getByRole("button", { name: "Register identity", exact: true })
      .click();
    const form = page.getByRole("dialog", { name: "Register an identity" });
    await form.getByLabel("Name", { exact: true }).fill(name);
    await form.getByLabel("Synthetic email").fill(`ui-${suffix}@example.test`);
    await form.getByRole("button", { name: "Register employee" }).click();
    await expect(form).toHaveCount(0);
    const person = await waitFor(async () => {
      const found = (await snapshot(page)).identities.find(
        (item) => item.name === name,
      );
      return found &&
        found.providerSubject &&
        !found.providerSubject.startsWith("pending:")
        ? found
        : undefined;
    }, "workforce provisioning");

    // Open the departure case from the queue.
    await page.goto("/#/cases");
    await page.reload();
    await page.getByRole("button", { name: "New departure case" }).click();
    const create = page.getByRole("dialog", { name: "New departure case" });
    await create.getByLabel("Departing person").selectOption(person.id);
    await create.getByLabel("HR event ID").fill(`UI-LIVE-${suffix}`);
    await create.getByLabel("HR source").fill("HR service desk (synthetic)");
    await create
      .getByLabel("Reason")
      .fill("Synthetic departure exercised through the redesigned console.");
    await create.getByRole("button", { name: "Create departure case" }).click();
    await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();

    // Contain, then wait for the real worker's provider readings.
    await nextStep(page)
      .getByRole("button", { name: "Apply local containment" })
      .click();
    await expect(page.getByText(/^Local access contained/)).toBeVisible();
    const caseId = await waitFor(async () => {
      const item = (await snapshot(page)).offboardingCases.find(
        (entry) => entry.hrEventId === `UI-LIVE-${suffix}`,
      );
      const native = item?.tasks.filter((task) =>
        ["local-containment", "keycloak-directory"].includes(task.id),
      );
      return native?.length === 2 &&
        native.every(
          (task) =>
            task.status === "observed" &&
            task.evidenceKind === "provider_observation",
        )
        ? item!.id
        : undefined;
    }, "containment and Keycloak observation");
    contained = true;
    await page.goto(`/#/cases?case=${encodeURIComponent(caseId)}`);
    await page.reload();
    await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
    await expect(page.locator(".task .prov-observed")).toHaveCount(2);
    await expect(page.locator(".task .prov-simulated")).toHaveCount(0);

    // The owner records statements for the external work, one at a time.
    for (let index = 0; index < 12; index++) {
      const record = nextStep(page).getByRole("button", {
        name: "Record next statement",
      });
      if (!(await record.isVisible())) break;
      await record.click();
      const dialog = page.getByRole("dialog", {
        name: "Record owner evidence",
      });
      await dialog
        .getByLabel("Evidence reference")
        .fill(`UI-LIVE-${suffix}-${index + 1}`);
      await dialog
        .getByLabel("Owner evidence summary")
        .fill(
          "Synthetic scope exclusion for a fictional case: no tenant was contacted and no revocation was measured.",
        );
      await dialog
        .getByRole("button", { name: "Save owner attestation" })
        .click();
      await expect(dialog).toHaveCount(0);
    }
    await expect(nextStep(page).getByRole("heading")).toHaveText(
      "Ready for independent review",
    );
    await expect(nextStep(page)).toContainText(
      "Closure needs an independent reviewer",
    );
    await page.screenshot({ path: `${reports}/console-live-case.png` });
    await axe(page);

    // The owner cannot close their own case; the button stays disabled.
    await expect(
      nextStep(page).getByRole("button", { name: "Review & close case" }),
    ).toBeDisabled();
    await signOut(page);

    // An independent reviewer, in their own session, closes the exact packet.
    const reviewer = await operator(browser, "bob");
    await reviewer.goto(`/#/cases?case=${encodeURIComponent(caseId)}`);
    await expect(
      reviewer.getByRole("heading", { level: 1, name }),
    ).toBeVisible();
    await nextStep(reviewer)
      .getByRole("button", { name: "Review & close case" })
      .click();
    await reviewer
      .getByRole("dialog", { name: "Review administrative closure" })
      .getByRole("button", { name: "Accept evidence & close case" })
      .click();
    await expect(reviewer.getByTestId("case-status")).toHaveText("Closed");
    await expect(reviewer.locator(".task .prov-observed")).toHaveCount(2);
    await expect(reviewer.locator(".task .prov-simulated")).toHaveCount(0);
    // Every other action is the owner's written statement, labeled as such.
    const tasks = await reviewer.locator(".task").count();
    await expect(reviewer.locator(".task .prov-attested")).toHaveCount(
      tasks - 2,
    );
    expect(tasks - 2).toBe(7);
    await axe(reviewer);

    const download = reviewer.waitForEvent("download");
    await nextStep(reviewer)
      .getByRole("button", { name: "Export closure packet" })
      .click();
    const packet = JSON.parse(
      await readFile((await (await download).path())!, "utf8"),
    );
    expect(packet.origin).toBe("connected_case");
    expect(packet.case.status).toBe("closed");
    expect(packet.case.closureBasis).toBe("reviewed_evidence");
    expect(packet.limitations.length).toBeGreaterThan(0);
    await reviewer.screenshot({ path: `${reports}/console-live-closed.png` });
    await signOut(reviewer);
  } finally {
    if (!contained && !page.isClosed()) await containWorkers(page, name);
  }
});
