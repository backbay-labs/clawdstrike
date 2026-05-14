import { useState, useRef, useEffect } from "react";
import { cn } from "@/lib/utils";

interface InlineNameInputProps {
  /** Pre-filled value (e.g. for rename). */
  defaultValue?: string;
  /** Called when the user presses Enter with a non-empty value. */
  onSubmit: (name: string) => void;
  /** Called when the user presses Escape or blurs the input. */
  onCancel: () => void;
  placeholder?: string;
  className?: string;
}

export function InlineNameInput({
  defaultValue = "",
  onSubmit,
  onCancel,
  placeholder = "filename.yaml",
  className,
}: InlineNameInputProps) {
  const [value, setValue] = useState(defaultValue);
  const inputRef = useRef<HTMLInputElement>(null);
  const submittedRef = useRef(false);

  useEffect(() => {
    const el = inputRef.current;
    if (!el) return;
    el.focus();
    el.select();
  }, []);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter") {
      e.preventDefault();
      const trimmed = value.trim();
      if (trimmed) {
        submittedRef.current = true;
        onSubmit(trimmed);
      }
    } else if (e.key === "Escape") {
      e.preventDefault();
      onCancel();
    }
  };

  const handleBlur = () => {
    if (!submittedRef.current) {
      onCancel();
    }
  };

  return (
    <input
      ref={inputRef}
      type="text"
      value={value}
      onChange={(e) => setValue(e.target.value)}
      onKeyDown={handleKeyDown}
      onBlur={handleBlur}
      placeholder={placeholder}
      className={cn(
        "text-[11px] font-mono bg-[#0b0d13] border border-[#d4a84b]/40 text-[#ece7dc] rounded px-1 py-[2px] outline-none w-[120px]",
        className,
      )}
    />
  );
}
