import { expect, test } from "@playwright/test";

test("settings SIEM section renders when opened from desktop", async ({ page }) => {
  await page.goto("/");

  await page.getByRole("button", { name: "Settings" }).first().dblclick();
  await expect(page.getByRole("heading", { name: "Connection" })).toBeVisible();

  // Click the SIEM tab
  await page.getByRole("button", { name: /SIEM Export/i }).first().click();

  await expect(page.getByRole("heading", { name: "SIEM Export" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Save SIEM Config" })).toBeVisible();
});

test("settings Webhooks section renders when opened from desktop", async ({ page }) => {
  await page.goto("/");

  await page.getByRole("button", { name: "Settings" }).first().dblclick();
  await expect(page.getByRole("heading", { name: "Connection" })).toBeVisible();

  // Click the Webhooks tab
  await page.getByRole("button", { name: /Webhooks/i }).first().click();

  await expect(page.getByRole("heading", { name: "Webhooks" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Save Webhook Config" })).toBeVisible();
});
