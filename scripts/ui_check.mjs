// Headless browser check of every dashboard page against a running stack.
// Usage (inside mcr.microsoft.com/playwright): node ui_check.mjs <base-url> <token> <screenshot-dir>
import { chromium } from "playwright";

const [base, token, shots] = process.argv.slice(2);
const PAGES = [
  ["/", "health-score"], ["/network", "timeseries-chart"], ["/calls", "cell-drop-chart"],
  ["/anomalies", null], ["/incidents", null], ["/incidents/INC-2026-001", "incident-timeline"],
  ["/rca", "rca-panel"], ["/reports", null], ["/agent", null], ["/security", null], ["/audit", null],
];
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
const failures = [];
page.on("pageerror", (err) => failures.push(`page error: ${err.message}`));
page.on("response", (r) => { if (r.url().includes("/api/") && r.status() >= 500) failures.push(`${r.status()} ${r.url()}`); });

await page.goto(base);
await page.getByLabel("API token").fill(token);
await page.getByRole("button", { name: "Sign in" }).click();
await page.getByText("Is the network healthy?").waitFor();
for (const [path, testId] of PAGES) {
  await page.goto(base + path);
  await page.waitForLoadState("networkidle");
  if (testId) await page.getByTestId(testId).first().waitFor({ timeout: 15000 });
  const alerts = await page.getByRole("alert").allTextContents();
  if (alerts.length) failures.push(`${path}: ${alerts.join(" | ")}`);
  const text = await page.locator("main").innerText();
  console.log(`${path.padEnd(28)} ${text.length} chars  ${text.replace(/\s+/g, " ").slice(0, 90)}`);
  await page.screenshot({ path: `${shots}/${path === "/" ? "dashboard" : path.slice(1).replace(/\//g, "_")}.png`, fullPage: true });
}
await browser.close();
if (failures.length) { console.error("UI CHECK FAILED\n" + failures.join("\n")); process.exit(1); }
console.log("UI CHECK PASSED");
