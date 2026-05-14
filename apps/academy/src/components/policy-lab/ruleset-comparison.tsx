'use client';

import { useState } from 'react';
import { rulesets, RULESET_NAMES } from '@/lib/ruleset-data';
import { Badge } from '@/components/ui/badge';

// ---------------------------------------------------------------------------
// Guard config keys (all 13 built-in guards + custom)
// ---------------------------------------------------------------------------

const GUARD_KEYS = [
  'forbidden_path',
  'path_allowlist',
  'egress_allowlist',
  'secret_leak',
  'patch_integrity',
  'shell_command',
  'mcp_tool',
  'prompt_injection',
  'jailbreak',
  'computer_use',
  'remote_desktop_side_channel',
  'input_injection_capability',
  'spider_sense',
] as const;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type GuardConfig = Record<string, unknown>;

function getGuards(ruleset: object): GuardConfig | undefined {
  return (ruleset as Record<string, unknown>).guards as GuardConfig | undefined;
}

function getSettings(ruleset: object): Record<string, unknown> | undefined {
  return (ruleset as Record<string, unknown>).settings as
    | Record<string, unknown>
    | undefined;
}

/**
 * Extract a human-readable summary of key threshold / config values for a guard.
 */
function guardSummary(guardKey: string, config: unknown): string {
  if (!config || typeof config !== 'object') return '';

  const c = config as Record<string, unknown>;
  const parts: string[] = [];

  if ('threshold' in c) parts.push(`threshold: ${c.threshold}`);
  if ('max_additions' in c) parts.push(`max_add: ${c.max_additions}`);
  if ('max_deletions' in c) parts.push(`max_del: ${c.max_deletions}`);
  if ('default_action' in c) parts.push(`default: ${c.default_action}`);
  if ('mode' in c) parts.push(`mode: ${c.mode}`);
  if ('enabled' in c && c.enabled === false) parts.push('disabled');
  if ('max_scan_bytes' in c) parts.push(`max_bytes: ${c.max_scan_bytes}`);
  if ('require_postcondition_probe' in c)
    parts.push(`probe: ${c.require_postcondition_probe}`);

  // For guards with patterns/allow/block lists, show count
  if (guardKey === 'forbidden_path' && Array.isArray(c.patterns))
    parts.push(`${c.patterns.length} patterns`);
  if (Array.isArray(c.allow)) parts.push(`${c.allow.length} allowed`);
  if (Array.isArray(c.block) && (c.block as unknown[]).length > 0)
    parts.push(`${(c.block as unknown[]).length} blocked`);

  return parts.join(', ');
}

/**
 * Check if a cell value differs from the default ruleset for difference highlighting.
 */
function differsFromDefault(
  guardKey: string,
  rulesetName: string,
): boolean {
  if (rulesetName === 'default') return false;

  const defaultGuards = getGuards(rulesets['default']);
  const currentGuards = getGuards(rulesets[rulesetName]);

  const inDefault = defaultGuards ? guardKey in defaultGuards : false;
  const inCurrent = currentGuards ? guardKey in currentGuards : false;

  return inDefault !== inCurrent;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function RulesetComparison() {
  const [selectedRulesets, setSelectedRulesets] = useState<string[]>([
    'default',
    'strict',
    'permissive',
  ]);

  const toggleRuleset = (name: string) => {
    setSelectedRulesets((prev) =>
      prev.includes(name)
        ? prev.filter((n) => n !== name)
        : [...prev, name],
    );
  };

  return (
    <div className="my-6 space-y-4">
      {/* Ruleset toggle bar */}
      <div className="flex flex-wrap gap-2">
        {RULESET_NAMES.map((name) => {
          const active = selectedRulesets.includes(name);
          return (
            <button
              key={name}
              type="button"
              onClick={() => toggleRuleset(name)}
              className="focus:outline-none"
            >
              <Badge
                variant={active ? 'default' : 'outline'}
                className={`cursor-pointer text-xs ${active ? '' : 'opacity-60 hover:opacity-100'}`}
              >
                {name}
              </Badge>
            </button>
          );
        })}
      </div>

      {/* Comparison table */}
      <div className="overflow-x-auto border rounded-lg">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b bg-muted/50">
              <th className="text-left py-2 px-3 font-medium sticky left-0 bg-muted/50 z-10">
                Guard
              </th>
              {selectedRulesets.map((name) => (
                <th
                  key={name}
                  className="text-center py-2 px-3 font-medium min-w-[140px]"
                >
                  <code className="text-xs">{name}</code>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {GUARD_KEYS.map((guardKey) => (
              <tr key={guardKey} className="border-b last:border-b-0">
                <td className="py-2 px-3 font-mono text-xs sticky left-0 bg-background z-10">
                  {guardKey}
                </td>
                {selectedRulesets.map((rulesetName) => {
                  const guards = getGuards(rulesets[rulesetName]);
                  const configured = guards ? guardKey in guards : false;
                  const summary = configured
                    ? guardSummary(guardKey, guards![guardKey])
                    : '';
                  const differs = differsFromDefault(guardKey, rulesetName);

                  return (
                    <td
                      key={rulesetName}
                      className={`py-2 px-3 text-center ${differs ? 'bg-yellow-500/10' : ''}`}
                    >
                      {configured ? (
                        <div className="flex flex-col items-center gap-1">
                          <Badge
                            variant="default"
                            className="bg-green-600 hover:bg-green-700 text-[10px] px-1.5 py-0"
                          >
                            Enabled
                          </Badge>
                          {summary && (
                            <span className="text-[10px] text-muted-foreground leading-tight">
                              {summary}
                            </span>
                          )}
                        </div>
                      ) : (
                        <span className="text-muted-foreground text-xs">
                          ---
                        </span>
                      )}
                    </td>
                  );
                })}
              </tr>
            ))}

            {/* Settings row */}
            <tr className="border-t-2">
              <td className="py-2 px-3 font-mono text-xs font-semibold sticky left-0 bg-background z-10">
                settings
              </td>
              {selectedRulesets.map((rulesetName) => {
                const settings = getSettings(rulesets[rulesetName]);
                if (!settings) {
                  return (
                    <td
                      key={rulesetName}
                      className="py-2 px-3 text-center text-muted-foreground text-xs"
                    >
                      ---
                    </td>
                  );
                }

                return (
                  <td key={rulesetName} className="py-2 px-3 text-center">
                    <div className="flex flex-col items-center gap-0.5 text-[10px] text-muted-foreground">
                      {'fail_fast' in settings && (
                        <span>fail_fast: {String(settings.fail_fast)}</span>
                      )}
                      {'verbose_logging' in settings && (
                        <span>
                          verbose: {String(settings.verbose_logging)}
                        </span>
                      )}
                      {'session_timeout_secs' in settings && (
                        <span>
                          timeout: {String(settings.session_timeout_secs)}s
                        </span>
                      )}
                    </div>
                  </td>
                );
              })}
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  );
}
