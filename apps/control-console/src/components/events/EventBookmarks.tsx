import { useState } from "react";
import { useBookmarks } from "../../hooks/useBookmarks";

export function EventBookmarks({ eventId }: { eventId: string }) {
  const { isBookmarked, toggleBookmark, setNote, getBookmark } = useBookmarks();
  const [showPopover, setShowPopover] = useState(false);
  const [noteValue, setNoteValue] = useState("");
  const bookmarked = isBookmarked(eventId);

  const handleStarClick = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (bookmarked) {
      setShowPopover((v) => !v);
      const bm = getBookmark(eventId);
      if (bm) setNoteValue(bm.note);
    } else {
      toggleBookmark(eventId);
    }
  };

  return (
    <span style={{ position: "relative", display: "inline-flex" }}>
      <button
        type="button"
        onClick={handleStarClick}
        style={{
          background: "none",
          border: "none",
          cursor: "pointer",
          padding: 2,
          fontSize: 14,
          color: bookmarked ? "var(--gold)" : "rgba(154,167,181,0.3)",
          transition: "color 0.15s ease",
        }}
      >
        {bookmarked ? "\u2605" : "\u2606"}
      </button>
      {showPopover && bookmarked && (
        <div
          className="glass-panel"
          onClick={(e) => e.stopPropagation()}
          style={{
            position: "absolute",
            top: "100%",
            left: 0,
            zIndex: 60,
            padding: 8,
            width: 200,
            display: "flex",
            flexDirection: "column",
            gap: 6,
          }}
        >
          <input
            type="text"
            value={noteValue}
            onChange={(e) => setNoteValue(e.target.value)}
            placeholder="Add a note..."
            className="glass-input font-mono rounded px-2 py-1 text-xs"
            style={{ color: "var(--text)" }}
          />
          <div style={{ display: "flex", gap: 4 }}>
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                setNote(eventId, noteValue);
                setShowPopover(false);
              }}
              className="font-mono"
              style={{
                background: "var(--gold-bloom)",
                border: "1px solid var(--gold-edge)",
                borderRadius: 4,
                color: "var(--gold)",
                fontSize: 10,
                padding: "2px 8px",
                cursor: "pointer",
              }}
            >
              Save
            </button>
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                toggleBookmark(eventId);
                setShowPopover(false);
              }}
              className="font-mono"
              style={{
                background: "rgba(194,59,59,0.08)",
                border: "1px solid rgba(194,59,59,0.25)",
                borderRadius: 4,
                color: "var(--crimson)",
                fontSize: 10,
                padding: "2px 8px",
                cursor: "pointer",
              }}
            >
              Remove
            </button>
          </div>
        </div>
      )}
    </span>
  );
}
