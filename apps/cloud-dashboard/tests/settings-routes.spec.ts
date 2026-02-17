import { expect, test } from "@playwright/test";

test("settings SIEM route renders SIEM section", async ({ page }) => {
  await page.goto("/settings/siem");

  await expect(page.getByRole("heading", { name: "Settings" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "SIEM Export" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Save SIEM Config" })).toBeVisible();
});

test("settings Webhooks route renders Webhooks section", async ({ page }) => {
  await page.goto("/settings/webhooks");

  await expect(page.getByRole("heading", { name: "Settings" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Webhooks" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Save Webhook Config" })).toBeVisible();
});
