import { useState, useCallback } from "react";

interface Bookmark {
  note: string;
  pinned: boolean;
  ts: string;
}

type BookmarkMap = Record<string, Bookmark>;

const STORAGE_KEY = "cs_bookmarks";

function loadBookmarks(): BookmarkMap {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : {};
  } catch {
    return {};
  }
}

function saveBookmarks(bookmarks: BookmarkMap) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(bookmarks));
}

export function useBookmarks() {
  const [bookmarks, setBookmarks] = useState<BookmarkMap>(loadBookmarks);

  const toggleBookmark = useCallback((id: string) => {
    setBookmarks((prev) => {
      const next = { ...prev };
      if (next[id]) {
        delete next[id];
      } else {
        next[id] = { note: "", pinned: true, ts: new Date().toISOString() };
      }
      saveBookmarks(next);
      return next;
    });
  }, []);

  const setNote = useCallback((id: string, note: string) => {
    setBookmarks((prev) => {
      if (!prev[id]) return prev;
      const next = { ...prev, [id]: { ...prev[id], note } };
      saveBookmarks(next);
      return next;
    });
  }, []);

  const isBookmarked = useCallback((id: string) => !!bookmarks[id], [bookmarks]);

  const getBookmark = useCallback((id: string) => bookmarks[id] ?? null, [bookmarks]);

  return { bookmarks, toggleBookmark, setNote, isBookmarked, getBookmark };
}
