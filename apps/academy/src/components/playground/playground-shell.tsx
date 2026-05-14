'use client';

import { useEffect, useState, useCallback } from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { getWasm, resetWasmError, type WasmModule } from '@/lib/wasm';

interface PlaygroundShellProps {
  children: (wasm: WasmModule) => React.ReactNode;
}

export function PlaygroundShell({ children }: PlaygroundShellProps) {
  const [wasm, setWasm] = useState<WasmModule | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [loading, setLoading] = useState(true);

  const loadWasm = useCallback(async () => {
    setLoading(true);
    setError(null);
    resetWasmError();
    try {
      const mod = await getWasm();
      setWasm(mod);
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadWasm();
  }, [loadWasm]);

  if (loading) {
    return (
      <Card className="my-6">
        <CardContent className="flex items-center justify-center py-16">
          <div className="flex flex-col items-center gap-4">
            <div className="h-10 w-10 animate-spin rounded-full border-4 border-muted border-t-primary" />
            <p className="text-sm text-muted-foreground">Loading ClawdStrike security engine...</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card className="my-6 border-red-500/50">
        <CardContent className="flex flex-col items-center gap-4 py-16">
          <div className="text-center">
            <p className="text-sm font-medium text-red-600 dark:text-red-400 mb-2">
              Failed to load security engine
            </p>
            <p className="text-xs text-muted-foreground max-w-md">
              {error.message}
            </p>
          </div>
          <Button variant="outline" size="sm" onClick={loadWasm}>
            Retry
          </Button>
        </CardContent>
      </Card>
    );
  }

  if (!wasm) {
    return null;
  }

  return <>{children(wasm)}</>;
}
