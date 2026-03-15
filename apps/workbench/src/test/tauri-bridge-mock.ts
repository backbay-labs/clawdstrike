/**
 * Mock for @/lib/tauri-bridge used across desktop component tests.
 *
 * By default isDesktop returns false. Tests that need desktop mode
 * should override the mock via vi.mocked(isDesktop).mockReturnValue(true).
 */
import { vi } from "vitest";

export const isDesktop = vi.fn(() => false);
export const isMacOS = vi.fn(() => false);
export const minimizeWindow = vi.fn(() => Promise.resolve());
export const maximizeWindow = vi.fn(() => Promise.resolve());
export const closeWindow = vi.fn(() => Promise.resolve());
export const openDetectionFile = vi.fn(() => Promise.resolve(null));
export const readDetectionFileByPath = vi.fn(() => Promise.resolve(null));
export const openPolicyFile = vi.fn(() => Promise.resolve(null));
export const readPolicyFileByPath = vi.fn(() => Promise.resolve(null));
export const pickSavePath = vi.fn(() => Promise.resolve(null));
export const saveDetectionFile = vi.fn(() => Promise.resolve(null));
export const savePolicyFile = vi.fn(() => Promise.resolve(null));
