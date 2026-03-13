import { useState, type KeyboardEvent } from "react";
import { IconX } from "@tabler/icons-react";

interface TagListProps {
  items: string[];
  onChange: (items: string[]) => void;
  placeholder?: string;
}

export function TagList({ items, onChange, placeholder = "Add item..." }: TagListProps) {
  const [input, setInput] = useState("");

  const addItem = () => {
    const trimmed = input.trim();
    if (trimmed && !items.includes(trimmed)) {
      onChange([...items, trimmed]);
      setInput("");
    }
  };

  const removeItem = (index: number) => {
    onChange(items.filter((_, i) => i !== index));
  };

  const handleKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter") {
      e.preventDefault();
      addItem();
    }
  };

  return (
    <div className="flex flex-col gap-2">
      {items.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {items.map((item, index) => (
            <span
              key={`${item}-${index}`}
              className="inline-flex items-center gap-1 px-2 py-0.5 bg-[#131721] border border-[#2d3240] text-[#ece7dc] font-mono text-xs rounded-md"
            >
              {item}
              <button
                type="button"
                onClick={() => removeItem(index)}
                className="text-[#6f7f9a] hover:text-[#c45c5c] transition-colors"
              >
                <IconX size={12} stroke={1.5} />
              </button>
            </span>
          ))}
        </div>
      )}
      <input
        type="text"
        value={input}
        onChange={(e) => setInput(e.target.value)}
        onKeyDown={handleKeyDown}
        placeholder={placeholder}
        className="h-8 w-full rounded-md border border-[#2d3240] bg-[#131721] px-2.5 py-1 text-xs font-mono text-[#ece7dc] placeholder:text-[#6f7f9a]/50 outline-none focus:border-[#d4a84b]/50 transition-colors"
      />
    </div>
  );
}
