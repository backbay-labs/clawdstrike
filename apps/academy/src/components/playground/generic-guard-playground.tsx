'use client';

import { useState, useCallback } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { VerdictDisplay } from './verdict-display';
import {
  evaluateGuard,
  guardResultToVerdict,
  type GuardName,
  type GuardAction,
  type VerdictData,
} from '@/lib/guards/types';

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

export interface GenericGuardPlaygroundProps {
  guard: GuardName;
  actionType:
    | 'file_access'
    | 'file_write'
    | 'network_egress'
    | 'shell_command'
    | 'mcp_tool'
    | 'patch'
    | 'text'
    | 'custom';
  placeholder: string;
  defaultInput?: string;
  config?: Record<string, unknown>;
  examples?: { label: string; value: string }[];
  customActionType?: string;
}

// ---------------------------------------------------------------------------
// Action Builder
// ---------------------------------------------------------------------------

function buildAction(
  actionType: GenericGuardPlaygroundProps['actionType'],
  input: string,
  customActionType?: string,
): GuardAction {
  switch (actionType) {
    case 'file_access':
      return { type: 'file_access', path: input };
    case 'file_write':
      return { type: 'file_write', path: '/tmp/test', content: input };
    case 'network_egress':
      return { type: 'network_egress', host: input, port: 443 };
    case 'shell_command':
      return { type: 'shell_command', command: input };
    case 'mcp_tool':
      return { type: 'mcp_tool', tool: input };
    case 'patch':
      return { type: 'patch', path: '/tmp/test', diff: input };
    case 'text':
      return { type: 'text', text: input };
    case 'custom':
      return {
        type: 'custom',
        action_type: customActionType ?? 'unknown',
        data: { value: input, action: input, channel: input },
      };
  }
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function GenericGuardPlayground({
  guard,
  actionType,
  placeholder,
  defaultInput = '',
  config,
  examples,
  customActionType,
}: GenericGuardPlaygroundProps) {
  const [input, setInput] = useState(defaultInput);
  const [result, setResult] = useState<VerdictData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleEvaluate = useCallback(async () => {
    if (!input.trim()) {
      setError('Please enter a value to evaluate');
      setResult(null);
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const action = buildAction(actionType, input, customActionType);
      const guardResult = await evaluateGuard(guard, config ?? {}, action);
      setResult(guardResultToVerdict(guardResult));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [input, guard, actionType, config, customActionType]);

  return (
    <Card className="my-6">
      <CardContent className="p-0">
        {/* Example pills */}
        {examples && examples.length > 0 && (
          <div className="flex flex-wrap gap-2 p-3 border-b">
            <span className="text-xs text-muted-foreground self-center mr-1">
              Examples:
            </span>
            {examples.map((example, i) => (
              <button
                key={i}
                onClick={() => setInput(example.value)}
                className="text-xs px-2.5 py-1 rounded-full border bg-muted/50 hover:bg-muted transition-colors truncate max-w-[280px]"
              >
                {example.label}
              </button>
            ))}
          </div>
        )}

        {/* Input area */}
        <div className="p-4 space-y-3">
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder={placeholder}
            rows={5}
            className="w-full rounded-md border bg-background px-3 py-2 text-sm font-mono placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring resize-y"
          />

          <Button
            onClick={handleEvaluate}
            disabled={loading}
            className="w-full"
          >
            {loading ? 'Evaluating...' : 'Evaluate'}
          </Button>
        </div>

        {/* Verdict display */}
        <div className="p-4 pt-0">
          <VerdictDisplay result={result} error={error} loading={loading} />
        </div>
      </CardContent>
    </Card>
  );
}
