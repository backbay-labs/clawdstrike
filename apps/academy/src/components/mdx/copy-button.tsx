'use client';

import * as React from 'react';
import { Copy, Check } from 'lucide-react';
import { Button } from '@/components/ui/button';

export function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = React.useState(false);

  const handleCopy = React.useCallback(async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard API not available
    }
  }, [text]);

  return (
    <Button
      variant="ghost"
      size="icon"
      className="absolute right-2 top-2 h-8 w-8 opacity-0 group-hover:opacity-100 transition-opacity"
      onClick={handleCopy}
      aria-label="Copy code"
    >
      {copied ? (
        <Check className="h-4 w-4 text-green-500" />
      ) : (
        <Copy className="h-4 w-4" />
      )}
    </Button>
  );
}
