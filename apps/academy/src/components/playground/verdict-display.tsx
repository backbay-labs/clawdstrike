'use client';

import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { cn } from '@/lib/utils';

export interface VerdictData {
  level: string;
  score: number;
  indicators: string[];
  guardName: string;
}

interface VerdictDisplayProps {
  result: VerdictData | null;
  error: string | null;
  loading: boolean;
}

const severityColors: Record<string, string> = {
  safe: 'text-green-600 dark:text-green-400',
  low: 'text-yellow-600 dark:text-yellow-400',
  medium: 'text-orange-600 dark:text-orange-400',
  high: 'text-red-600 dark:text-red-400',
  critical: 'text-red-700 dark:text-red-300 font-bold',
};

export function VerdictDisplay({ result, error, loading }: VerdictDisplayProps) {
  if (loading) {
    return (
      <Card className="h-full">
        <CardContent className="flex items-center justify-center h-full p-6">
          <div className="flex flex-col items-center gap-3">
            <div className="h-8 w-8 animate-spin rounded-full border-4 border-muted border-t-primary" />
            <p className="text-sm text-muted-foreground animate-pulse">Evaluating...</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card className="h-full border-red-500/50">
        <CardHeader>
          <CardTitle className="text-sm text-red-600 dark:text-red-400">Evaluation Error</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
        </CardContent>
      </Card>
    );
  }

  if (!result) {
    return (
      <Card className="h-full">
        <CardContent className="flex items-center justify-center h-full p-6">
          <p className="text-sm text-muted-foreground">Enter a payload and click Evaluate</p>
        </CardContent>
      </Card>
    );
  }

  const isAllowed = result.level === 'safe';

  return (
    <Card className="h-full">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm font-medium">Verdict</CardTitle>
          <Badge variant={isAllowed ? 'default' : 'destructive'}>
            {isAllowed ? 'ALLOW' : 'DENY'}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-2 gap-3 text-sm">
          <div>
            <p className="text-muted-foreground text-xs mb-1">Guard</p>
            <p className="font-medium">{result.guardName}</p>
          </div>
          <div>
            <p className="text-muted-foreground text-xs mb-1">Severity</p>
            <p className={cn('font-medium capitalize', severityColors[result.level] ?? 'text-foreground')}>
              {result.level}
            </p>
          </div>
          <div>
            <p className="text-muted-foreground text-xs mb-1">Score</p>
            <p className="font-mono font-medium">{result.score.toFixed(2)}</p>
          </div>
        </div>

        {result.indicators.length > 0 && (
          <div>
            <p className="text-muted-foreground text-xs mb-2">Evidence</p>
            <ul className="space-y-1">
              {result.indicators.map((indicator, i) => (
                <li key={i} className="text-sm flex items-start gap-2">
                  <span className="text-red-500 mt-0.5 shrink-0">&#x2022;</span>
                  <span>{indicator}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
