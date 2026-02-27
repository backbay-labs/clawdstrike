import { expect, test } from "@playwright/test";

test("settings SIEM section renders when opened from desktop", async ({ page }) => {
  await page.goto("/");

  // Open Settings via desktop icon double-click
  await page.getByText("Settings").dblclick();

  await expect(page.getByRole("heading", { name: "Settings" })).toBeVisible();

  // Click the SIEM tab
  await page.getByText("SIEM Export", { exact: false }).first().click();

  await expect(page.getByRole("heading", { name: "SIEM Export" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Save SIEM Config" })).toBeVisible();
});

test("settings Webhooks section renders when opened from desktop", async ({ page }) => {
  await page.goto("/");

  // Open Settings via desktop icon double-click
  await page.getByText("Settings").dblclick();

  await expect(page.getByRole("heading", { name: "Settings" })).toBeVisible();

  // Click the Webhooks tab
  await page.getByText("Webhooks", { exact: false }).first().click();

  await expect(page.getByRole("heading", { name: "Webhooks" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Save Webhook Config" })).toBeVisible();
});
