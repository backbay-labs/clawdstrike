'use client';

import { useState, useEffect, useCallback } from 'react';
import { Target, CheckCircle2, XCircle, Lightbulb, Trophy } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { cn } from '@/lib/utils';
import { evaluateGuard } from '@/lib/guards/types';
import type { GuardName, GuardAction, GuardResult } from '@/lib/guards/types';
import { useProgressStore } from '@/lib/stores/progress';

interface BypassChallengeProps {
  /** Guard name (e.g., 'forbidden_path') */
  guard: string;
  /** What verdict counts as success */
  expectedVerdict: 'allow' | 'deny';
  /** Challenge description shown to user */
  description: string;
  /** Optional hint text */
  hint?: string;
  /** Unique ID for progress tracking */
  challengeId: string;
  /** Guard config override (defaults to empty object) */
  config?: Record<string, unknown>;
  /** Action type for this guard (e.g., 'file_access', 'shell_command') */
  actionType: string;
  /** For actionType="custom": the fixed action_type to send (e.g., 'computer_use', 'remote_desktop') */
  customActionType?: string;
  /** Input placeholder text */
  placeholder?: string;
}

type ChallengeStatus = 'idle' | 'evaluating' | 'success' | 'failure';

/**
 * Build a GuardAction from the action type and user input value.
 */
function buildAction(actionType: string, inputValue: string, customActionType?: string): GuardAction {
  switch (actionType) {
    case 'file_access':
      return { type: 'file_access', path: inputValue };
    case 'file_write':
      return { type: 'file_write', path: '/tmp/test', content: inputValue };
    case 'shell_command':
      return { type: 'shell_command', command: inputValue };
    case 'network_egress':
      return { type: 'network_egress', host: inputValue, port: 443 };
    case 'mcp_tool':
      return { type: 'mcp_tool', tool: inputValue };
    case 'patch':
      return { type: 'patch', path: '/tmp/test', diff: inputValue };
    case 'text':
      return { type: 'text', text: inputValue };
    default:
      return { type: 'custom', action_type: customActionType ?? actionType, data: { value: inputValue, action: inputValue, channel: inputValue } };
  }
}

export function BypassChallenge({
  guard,
  expectedVerdict,
  description,
  hint,
  challengeId,
  config,
  actionType,
  customActionType,
  placeholder,
}: BypassChallengeProps) {
  const [inputValue, setInputValue] = useState('');
  const [lastResult, setLastResult] = useState<GuardResult | null>(null);
  const [status, setStatus] = useState<ChallengeStatus>('idle');
  const [showHint, setShowHint] = useState(false);

  const markChallengeComplete = useProgressStore((s) => s.markChallengeComplete);
  const isChallengeComplete = useProgressStore((s) => s.isChallengeComplete);

  // Hydration guard
  const [hydrated, setHydrated] = useState(false);
  useEffect(() => {
    setHydrated(true);
  }, []);

  const alreadyCompleted = hydrated && isChallengeComplete(challengeId);

  const handleEvaluate = useCallback(async () => {
    if (!inputValue.trim() || status === 'evaluating') return;

    setStatus('evaluating');
    setLastResult(null);
    setShowHint(false);

    try {
      const action = buildAction(actionType, inputValue, customActionType);
      const result = await evaluateGuard(guard as GuardName, config ?? {}, action);
      setLastResult(result);

      // Determine if the result matches the expected verdict
      const isSuccess =
        (expectedVerdict === 'allow' && result.allowed) ||
        (expectedVerdict === 'deny' && !result.allowed);

      if (isSuccess) {
        setStatus('success');
        markChallengeComplete(challengeId);
      } else {
        setStatus('failure');
      }
    } catch {
      setLastResult({
        allowed: false,
        guard,
        severity: 'critical',
        message: 'Evaluation failed. Please try again.',
      });
      setStatus('failure');
    }
  }, [inputValue, status, actionType, guard, config, expectedVerdict, challengeId, markChallengeComplete]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleEvaluate();
    }
  };

  return (
    <Card
      className={cn(
        'my-6 border-2 transition-colors',
        status === 'success' && 'border-green-500 dark:border-green-400',
        status === 'failure' && 'border-red-300 dark:border-red-700',
        status === 'idle' && 'border-border',
        status === 'evaluating' && 'border-border',
      )}
    >
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2 text-base">
            <Target className="h-5 w-5 text-orange-500" />
            <span>Bypass Challenge</span>
          </CardTitle>
          {alreadyCompleted && (
            <Badge variant="secondary" className="gap-1 text-green-600 dark:text-green-400">
              <Trophy className="h-3 w-3" />
              Completed
            </Badge>
          )}
        </div>
        <p className="text-sm text-muted-foreground mt-1">{description}</p>
      </CardHeader>

      <CardContent className="space-y-4">
        {/* Input area */}
        <div className="space-y-2">
          <textarea
            value={inputValue}
            onChange={(e) => setInputValue(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder={placeholder ?? `Enter your ${actionType} payload...`}
            rows={3}
            className="w-full rounded-md border bg-background px-3 py-2 text-sm font-mono placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring resize-y"
          />
        </div>

        {/* Submit button */}
        <Button
          onClick={handleEvaluate}
          disabled={status === 'evaluating' || !inputValue.trim()}
          className="w-full"
          variant={status === 'success' ? 'outline' : 'default'}
        >
          {status === 'evaluating' ? 'Evaluating...' : 'Try Payload'}
        </Button>

        {/* Result banner */}
        {status === 'success' && (
          <div className="rounded-md bg-green-50 dark:bg-green-950/50 border border-green-200 dark:border-green-800 p-4">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="h-5 w-5 text-green-600 dark:text-green-400 shrink-0" />
              <p className="text-sm font-medium text-green-800 dark:text-green-200">
                You bypassed the guard!
              </p>
            </div>
          </div>
        )}

        {status === 'failure' && (
          <div className="rounded-md bg-red-50 dark:bg-red-950/50 border border-red-200 dark:border-red-800 p-4">
            <div className="flex items-center gap-2">
              <XCircle className="h-5 w-5 text-red-600 dark:text-red-400 shrink-0" />
              <p className="text-sm font-medium text-red-800 dark:text-red-200">
                Guard still blocked you. Try again.
              </p>
            </div>
          </div>
        )}

        {/* Verdict details */}
        {lastResult && (
          <div className="rounded-md border bg-muted/30 p-3 space-y-1">
            <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
              Guard Verdict
            </p>
            <div className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-sm">
              <span className="text-muted-foreground">Guard:</span>
              <span className="font-mono">{lastResult.guard}</span>
              <span className="text-muted-foreground">Verdict:</span>
              <span className={lastResult.allowed ? 'text-green-600 dark:text-green-400' : 'text-red-600 dark:text-red-400'}>
                {lastResult.allowed ? 'ALLOW' : 'DENY'}
              </span>
              <span className="text-muted-foreground">Severity:</span>
              <span>{lastResult.severity}</span>
              <span className="text-muted-foreground">Message:</span>
              <span>{lastResult.message}</span>
            </div>
            {lastResult.details && Object.keys(lastResult.details).length > 0 && (
              <pre className="mt-2 text-xs bg-muted rounded p-2 overflow-x-auto">
                {JSON.stringify(lastResult.details, null, 2)}
              </pre>
            )}
          </div>
        )}

        {/* Hint toggle */}
        {hint && status === 'failure' && (
          <div>
            <button
              onClick={() => setShowHint((v) => !v)}
              className="flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors"
            >
              <Lightbulb className="h-4 w-4" />
              {showHint ? 'Hide Hint' : 'Show Hint'}
            </button>
            {showHint && (
              <p className="mt-2 text-sm text-amber-700 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/30 rounded-md border border-amber-200 dark:border-amber-800 p-3">
                {hint}
              </p>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
