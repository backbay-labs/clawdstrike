'use client';

import { SearchCommand } from '@/components/search/search-command';
import { useKeyboardNav } from '@/hooks/use-keyboard-nav';
import type { TrackMeta } from '@/lib/content';

/**
 * Client component shell that wraps client-side features needing
 * browser APIs (keyboard listeners, Pagefind lazy-load).
 *
 * Rendered by the server-side tracks layout, receiving the serializable
 * tracks array that the Sidebar already uses.
 */
export function ClientShell({ tracks }: { tracks: TrackMeta[] }) {
  useKeyboardNav(tracks);
  return <SearchCommand />;
}
