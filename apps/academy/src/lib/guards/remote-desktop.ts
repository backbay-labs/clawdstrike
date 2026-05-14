/**
 * Remote Desktop Side-Channel Guard Simulation
 *
 * Controls channel enable/disable flags for remote desktop sessions.
 * Config has `block_channels: string[]` (e.g., ['clipboard', 'file_transfer', 'audio']).
 * Denies if action references a blocked channel.
 */
import type { GuardAction, GuardResult } from './types';

const DEFAULT_BLOCKED_CHANNELS: string[] = [];

export function evaluateRemoteDesktop(
  config: Record<string, unknown>,
  action: GuardAction,
): GuardResult {
  // Only evaluate custom actions with action_type 'remote_desktop'
  if (action.type !== 'custom' || action.action_type !== 'remote_desktop') {
    return {
      allowed: true,
      guard: 'remote_desktop_side_channel',
      severity: 'info',
      message: 'Action type not evaluated by remote_desktop guard',
    };
  }

  const blockedChannels =
    (config.block_channels as string[] | undefined) ?? DEFAULT_BLOCKED_CHANNELS;

  const channel = action.data?.channel as string | undefined;
  if (channel && blockedChannels.includes(channel)) {
    return {
      allowed: false,
      guard: 'remote_desktop_side_channel',
      severity: 'error',
      message: `Remote desktop channel blocked: ${channel}`,
      details: { channel },
    };
  }

  return {
    allowed: true,
    guard: 'remote_desktop_side_channel',
    severity: 'info',
    message: 'Remote desktop channel allowed',
    details: { channel },
  };
}
