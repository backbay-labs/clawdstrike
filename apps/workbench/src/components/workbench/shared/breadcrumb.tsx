import { Link } from "react-router-dom";
import { IconChevronRight } from "@tabler/icons-react";

interface BreadcrumbItem {
  label: string;
  href?: string;
}

export function Breadcrumb({ items }: { items: BreadcrumbItem[] }) {
  return (
    <nav className="flex items-center gap-1 px-6 py-2 text-[10px] font-mono text-[#6f7f9a]/60 bg-[#0b0d13]/40 border-b border-[#2d3240]/20 shrink-0">
      {items.map((item, i) => (
        <span key={i} className="flex items-center gap-1">
          {i > 0 && <IconChevronRight size={10} stroke={1.5} className="text-[#2d3240]" />}
          {item.href ? (
            <Link to={item.href} className="hover:text-[#ece7dc]/70 transition-colors">{item.label}</Link>
          ) : (
            <span className="text-[#ece7dc]/50">{item.label}</span>
          )}
        </span>
      ))}
    </nav>
  );
}
