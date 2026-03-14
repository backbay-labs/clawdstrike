import { cn } from "@/lib/utils";


interface FrameworkSelectorProps {
  frameworks: Array<{ id: string; name: string; score: number }>;
  selected: string;
  onSelect: (id: string) => void;
}


function MiniScoreRing({ score, size = 32 }: { score: number; size?: number }) {
  const color = score > 80 ? "#3dbf84" : score >= 50 ? "#d4a84b" : "#c45c5c";
  const strokeWidth = 3;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  return (
    <div className="relative shrink-0" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="#2d3240"
          strokeWidth={strokeWidth}
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          className="transition-all duration-500"
        />
      </svg>
      <div className="absolute inset-0 flex items-center justify-center">
        <span
          className="text-[8px] font-mono font-bold"
          style={{ color }}
        >
          {score}
        </span>
      </div>
    </div>
  );
}


function FrameworkPill({
  framework,
  isSelected,
  onSelect,
}: {
  framework: { id: string; name: string; score: number };
  isSelected: boolean;
  onSelect: () => void;
}) {
  const scoreColor = framework.score > 80 ? "#3dbf84" : framework.score >= 50 ? "#d4a84b" : "#c45c5c";

  return (
    <button
      onClick={onSelect}
      className={cn(
        "flex items-center gap-2 px-3 py-2 rounded-lg border transition-all duration-150 text-left shrink-0",
        isSelected
          ? "border-[#d4a84b]/40 bg-[#d4a84b]/5"
          : "border-[#2d3240] bg-[#0b0d13] hover:border-[#2d3240] hover:bg-[#131721]/60",
      )}
    >
      <MiniScoreRing score={framework.score} />
      <div className="min-w-0">
        <span
          className={cn(
            "text-[11px] font-medium block truncate",
            isSelected ? "text-[#ece7dc]" : "text-[#6f7f9a]",
          )}
        >
          {framework.name}
        </span>
        <span
          className="text-[9px] font-mono"
          style={{ color: scoreColor }}
        >
          {framework.score}%
        </span>
      </div>
    </button>
  );
}


export function FrameworkSelector({
  frameworks,
  selected,
  onSelect,
}: FrameworkSelectorProps) {
  if (frameworks.length === 0) return null;

  return (
    <div className="flex items-center gap-2 overflow-x-auto pb-1 scrollbar-thin">
      {frameworks.map((fw) => (
        <FrameworkPill
          key={fw.id}
          framework={fw}
          isSelected={selected === fw.id}
          onSelect={() => onSelect(fw.id)}
        />
      ))}
    </div>
  );
}
