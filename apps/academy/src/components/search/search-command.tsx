'use client';

import { Command } from 'cmdk';
import { useRouter } from 'next/navigation';
import { useState, useEffect, useCallback } from 'react';
import { Dialog, DialogContent, DialogTitle } from '@/components/ui/dialog';
import { Search } from 'lucide-react';
import { VisuallyHidden } from '@radix-ui/react-visually-hidden';

// ---------------------------------------------------------------------------
// Pagefind type declarations
// ---------------------------------------------------------------------------

interface SearchResult {
  url: string;
  excerpt: string;
  meta: { title: string };
}

interface PagefindInstance {
  search: (query: string) => Promise<{
    results: Array<{ data: () => Promise<SearchResult> }>;
  }>;
}

declare global {
  interface Window {
    __pagefind?: PagefindInstance;
  }
}

// ---------------------------------------------------------------------------
// SearchCommand
// ---------------------------------------------------------------------------

export function SearchCommand() {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<SearchResult[]>([]);

  // Global Cmd+K / Ctrl+K listener
  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setOpen((prev) => !prev);
      }
    }
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, []);

  // Search callback: lazy-loads Pagefind client and queries index
  const search = useCallback(async (value: string) => {
    setQuery(value);

    if (!value.trim()) {
      setResults([]);
      return;
    }

    // Lazy-load Pagefind on first search
    if (!window.__pagefind) {
      try {
        window.__pagefind = await import(
          // @ts-expect-error -- Pagefind JS is generated at postbuild into public/pagefind/
          /* webpackIgnore: true */ '/pagefind/pagefind.js'
        );
      } catch {
        // Pagefind index not available (e.g., dev mode before build)
        window.__pagefind = {
          search: async () => ({ results: [] }),
        };
      }
    }

    const pagefind = window.__pagefind;
    if (!pagefind) return;

    const response = await pagefind.search(value);
    const top8 = response.results.slice(0, 8);
    const loaded = await Promise.all(top8.map((r) => r.data()));
    setResults(loaded);
  }, []);

  function onSelect(url: string) {
    router.push(url);
    setOpen(false);
    setQuery('');
    setResults([]);
  }

  return (
    <>
      {/* Floating Cmd+K hint button */}
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="fixed bottom-4 right-4 z-30 flex items-center gap-2 rounded-lg border bg-background/95 px-3 py-2 text-sm text-muted-foreground shadow-md backdrop-blur transition-colors hover:bg-accent hover:text-accent-foreground md:bottom-auto md:top-3 md:right-16 md:fixed md:shadow-none md:border-border/50"
      >
        <Search className="h-4 w-4" />
        <span className="hidden sm:inline">Search</span>
        <kbd className="pointer-events-none ml-1 hidden h-5 select-none items-center gap-1 rounded border bg-muted px-1.5 font-mono text-[10px] font-medium opacity-100 sm:flex">
          <span className="text-xs">&#8984;</span>K
        </kbd>
      </button>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-w-lg p-0 overflow-hidden">
          <VisuallyHidden>
            <DialogTitle>Search lessons</DialogTitle>
          </VisuallyHidden>
          <Command className="[&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:font-medium [&_[cmdk-group-heading]]:text-muted-foreground">
            <div className="flex items-center border-b px-3">
              <Search className="mr-2 h-4 w-4 shrink-0 opacity-50" />
              <Command.Input
                value={query}
                onValueChange={search}
                placeholder="Search lessons..."
                className="flex h-11 w-full rounded-md bg-transparent py-3 text-sm outline-none placeholder:text-muted-foreground disabled:cursor-not-allowed disabled:opacity-50"
              />
            </div>
            <Command.List className="max-h-[300px] overflow-y-auto p-2">
              <Command.Empty className="py-6 text-center text-sm text-muted-foreground">
                No results found.
              </Command.Empty>
              {results.map((result) => (
                <Command.Item
                  key={result.url}
                  value={result.meta.title}
                  onSelect={() => onSelect(result.url)}
                  className="relative flex cursor-default select-none flex-col gap-1 rounded-sm px-3 py-2 text-sm outline-none data-[selected=true]:bg-accent data-[selected=true]:text-accent-foreground"
                >
                  <span className="font-medium">{result.meta.title}</span>
                  {result.excerpt && (
                    <span
                      className="text-xs text-muted-foreground line-clamp-2 [&_mark]:bg-primary/20 [&_mark]:text-foreground [&_mark]:rounded-sm"
                      dangerouslySetInnerHTML={{ __html: result.excerpt }}
                    />
                  )}
                </Command.Item>
              ))}
            </Command.List>
          </Command>
        </DialogContent>
      </Dialog>
    </>
  );
}
