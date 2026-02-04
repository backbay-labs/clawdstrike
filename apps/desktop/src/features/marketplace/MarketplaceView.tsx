/**
 * MarketplaceView - Discover and share community policies
 */
import { useState, useMemo } from "react";
import { clsx } from "clsx";

type PolicyCategory = "all" | "compliance" | "ai-safety" | "enterprise" | "minimal" | "custom";

interface MarketplacePolicy {
  id: string;
  name: string;
  description: string;
  author: string;
  authorVerified: boolean;
  version: string;
  category: PolicyCategory;
  rating: number;
  reviewCount: number;
  installCount: number;
  tags: string[];
  createdAt: string;
  updatedAt: string;
}

// Mock data for initial implementation
const MOCK_POLICIES: MarketplacePolicy[] = [
  {
    id: "soc2-compliance",
    name: "SOC 2 Compliance",
    description: "Policy template aligned with SOC 2 Type II requirements. Includes audit logging, access controls, and data protection guards.",
    author: "ClawdStrike",
    authorVerified: true,
    version: "1.0.0",
    category: "compliance",
    rating: 4.8,
    reviewCount: 124,
    installCount: 2340,
    tags: ["soc2", "compliance", "audit"],
    createdAt: "2025-01-15",
    updatedAt: "2025-02-01",
  },
  {
    id: "ai-agent-strict",
    name: "Strict AI Agent",
    description: "High-security policy for AI agents with restricted file access, network egress, and MCP tool usage. Includes jailbreak detection.",
    author: "SecurityFirst",
    authorVerified: true,
    version: "2.1.0",
    category: "ai-safety",
    rating: 4.6,
    reviewCount: 89,
    installCount: 1567,
    tags: ["ai", "strict", "jailbreak"],
    createdAt: "2025-01-20",
    updatedAt: "2025-01-28",
  },
  {
    id: "developer-friendly",
    name: "Developer Friendly",
    description: "Balanced policy for development environments. Allows common dev tools while protecting sensitive paths and secrets.",
    author: "DevSecOps",
    authorVerified: false,
    version: "1.2.3",
    category: "minimal",
    rating: 4.2,
    reviewCount: 56,
    installCount: 890,
    tags: ["dev", "minimal", "flexible"],
    createdAt: "2025-01-10",
    updatedAt: "2025-01-25",
  },
  {
    id: "enterprise-standard",
    name: "Enterprise Standard",
    description: "Comprehensive enterprise policy with RBAC integration, audit trails, and compliance-ready configurations.",
    author: "EnterpriseSec",
    authorVerified: true,
    version: "3.0.0",
    category: "enterprise",
    rating: 4.9,
    reviewCount: 201,
    installCount: 4521,
    tags: ["enterprise", "rbac", "compliance"],
    createdAt: "2024-12-01",
    updatedAt: "2025-02-01",
  },
];

const CATEGORIES: { id: PolicyCategory; label: string }[] = [
  { id: "all", label: "All" },
  { id: "compliance", label: "Compliance" },
  { id: "ai-safety", label: "AI Safety" },
  { id: "enterprise", label: "Enterprise" },
  { id: "minimal", label: "Minimal" },
  { id: "custom", label: "Custom" },
];

export function MarketplaceView() {
  const [category, setCategory] = useState<PolicyCategory>("all");
  const [search, setSearch] = useState("");
  const [selectedPolicy, setSelectedPolicy] = useState<MarketplacePolicy | null>(null);

  const filteredPolicies = useMemo(() => {
    return MOCK_POLICIES.filter((policy) => {
      if (category !== "all" && policy.category !== category) return false;
      if (search) {
        const searchLower = search.toLowerCase();
        return (
          policy.name.toLowerCase().includes(searchLower) ||
          policy.description.toLowerCase().includes(searchLower) ||
          policy.tags.some((t) => t.toLowerCase().includes(searchLower))
        );
      }
      return true;
    });
  }, [category, search]);

  return (
    <div className="flex h-full">
      {/* Main content */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Header */}
        <div className="px-4 py-3 border-b border-sdr-border bg-sdr-bg-secondary">
          <h1 className="text-lg font-semibold text-sdr-text-primary">Policy Marketplace</h1>
          <p className="text-sm text-sdr-text-muted mt-0.5">
            Discover and install community policies
          </p>
        </div>

        {/* Search and filters */}
        <div className="px-4 py-3 border-b border-sdr-border bg-sdr-bg-secondary/50">
          <div className="flex items-center gap-4">
            {/* Search */}
            <div className="relative flex-1 max-w-md">
              <SearchIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-sdr-text-muted" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search policies..."
                className="w-full pl-9 pr-3 py-2 bg-sdr-bg-tertiary text-sdr-text-primary placeholder:text-sdr-text-muted rounded-md border border-sdr-border focus:outline-none focus:border-sdr-accent-blue"
              />
            </div>

            {/* Category tabs */}
            <div className="flex items-center gap-1">
              {CATEGORIES.map((cat) => (
                <button
                  key={cat.id}
                  onClick={() => setCategory(cat.id)}
                  className={clsx(
                    "px-3 py-1.5 text-sm font-medium rounded-md transition-colors",
                    category === cat.id
                      ? "bg-sdr-accent-blue/20 text-sdr-accent-blue"
                      : "text-sdr-text-secondary hover:text-sdr-text-primary hover:bg-sdr-bg-tertiary"
                  )}
                >
                  {cat.label}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Policy grid */}
        <div className="flex-1 overflow-y-auto p-4">
          {filteredPolicies.length === 0 ? (
            <div className="flex items-center justify-center h-full text-sdr-text-muted">
              No policies found
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {filteredPolicies.map((policy) => (
                <PolicyCard
                  key={policy.id}
                  policy={policy}
                  onClick={() => setSelectedPolicy(policy)}
                />
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Detail panel */}
      {selectedPolicy && (
        <PolicyDetailPanel
          policy={selectedPolicy}
          onClose={() => setSelectedPolicy(null)}
        />
      )}
    </div>
  );
}

interface PolicyCardProps {
  policy: MarketplacePolicy;
  onClick: () => void;
}

function PolicyCard({ policy, onClick }: PolicyCardProps) {
  return (
    <button
      onClick={onClick}
      className="text-left p-4 bg-sdr-bg-secondary rounded-lg border border-sdr-border hover:border-sdr-accent-blue/50 transition-colors"
    >
      <div className="flex items-start justify-between mb-2">
        <div>
          <h3 className="font-medium text-sdr-text-primary">{policy.name}</h3>
          <div className="flex items-center gap-1 text-xs text-sdr-text-muted mt-0.5">
            <span>{policy.author}</span>
            {policy.authorVerified && <VerifiedBadge />}
          </div>
        </div>
        <span className="text-xs text-sdr-text-muted">v{policy.version}</span>
      </div>

      <p className="text-sm text-sdr-text-secondary line-clamp-2 mb-3">
        {policy.description}
      </p>

      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1">
          <StarRating rating={policy.rating} />
          <span className="text-xs text-sdr-text-muted">({policy.reviewCount})</span>
        </div>
        <span className="text-xs text-sdr-text-muted">{formatInstalls(policy.installCount)}</span>
      </div>

      <div className="flex flex-wrap gap-1 mt-3">
        {policy.tags.slice(0, 3).map((tag) => (
          <span
            key={tag}
            className="px-2 py-0.5 text-xs bg-sdr-bg-tertiary text-sdr-text-muted rounded"
          >
            {tag}
          </span>
        ))}
      </div>
    </button>
  );
}

interface PolicyDetailPanelProps {
  policy: MarketplacePolicy;
  onClose: () => void;
}

function PolicyDetailPanel({ policy, onClose }: PolicyDetailPanelProps) {
  const [isInstalling, setIsInstalling] = useState(false);

  const handleInstall = async () => {
    setIsInstalling(true);
    // Simulate install
    await new Promise((resolve) => setTimeout(resolve, 1000));
    setIsInstalling(false);
  };

  return (
    <div className="w-96 border-l border-sdr-border bg-sdr-bg-secondary flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-sdr-border">
        <h2 className="font-medium text-sdr-text-primary">{policy.name}</h2>
        <button
          onClick={onClose}
          className="p-1 text-sdr-text-muted hover:text-sdr-text-primary rounded"
        >
          <CloseIcon />
        </button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {/* Author */}
        <div className="flex items-center gap-2">
          <div className="w-10 h-10 rounded-full bg-sdr-bg-tertiary flex items-center justify-center text-sdr-text-muted">
            {policy.author[0]}
          </div>
          <div>
            <div className="flex items-center gap-1">
              <span className="text-sm font-medium text-sdr-text-primary">{policy.author}</span>
              {policy.authorVerified && <VerifiedBadge />}
            </div>
            <span className="text-xs text-sdr-text-muted">v{policy.version}</span>
          </div>
        </div>

        {/* Stats */}
        <div className="flex items-center gap-4 text-sm">
          <div className="flex items-center gap-1">
            <StarRating rating={policy.rating} />
            <span className="text-sdr-text-secondary">{policy.rating}</span>
            <span className="text-sdr-text-muted">({policy.reviewCount})</span>
          </div>
          <span className="text-sdr-text-muted">{formatInstalls(policy.installCount)} installs</span>
        </div>

        {/* Description */}
        <div>
          <h3 className="text-xs font-medium text-sdr-text-muted uppercase tracking-wide mb-2">
            Description
          </h3>
          <p className="text-sm text-sdr-text-secondary">{policy.description}</p>
        </div>

        {/* Tags */}
        <div>
          <h3 className="text-xs font-medium text-sdr-text-muted uppercase tracking-wide mb-2">
            Tags
          </h3>
          <div className="flex flex-wrap gap-1">
            {policy.tags.map((tag) => (
              <span
                key={tag}
                className="px-2 py-0.5 text-xs bg-sdr-bg-tertiary text-sdr-text-secondary rounded"
              >
                {tag}
              </span>
            ))}
          </div>
        </div>

        {/* Dates */}
        <div>
          <h3 className="text-xs font-medium text-sdr-text-muted uppercase tracking-wide mb-2">
            Version History
          </h3>
          <div className="text-sm text-sdr-text-secondary">
            <p>Created: {new Date(policy.createdAt).toLocaleDateString()}</p>
            <p>Updated: {new Date(policy.updatedAt).toLocaleDateString()}</p>
          </div>
        </div>
      </div>

      {/* Actions */}
      <div className="p-4 border-t border-sdr-border">
        <button
          onClick={handleInstall}
          disabled={isInstalling}
          className="w-full px-4 py-2.5 bg-sdr-accent-blue text-white font-medium rounded-md hover:bg-sdr-accent-blue/90 disabled:opacity-50 transition-colors"
        >
          {isInstalling ? "Installing..." : "Install Policy"}
        </button>
      </div>
    </div>
  );
}

function StarRating({ rating }: { rating: number }) {
  return (
    <div className="flex items-center">
      {[1, 2, 3, 4, 5].map((star) => (
        <svg
          key={star}
          className={clsx(
            "w-3.5 h-3.5",
            star <= rating ? "text-sdr-accent-amber" : "text-sdr-text-muted"
          )}
          fill="currentColor"
          viewBox="0 0 20 20"
        >
          <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 00-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 00.951-.69l1.07-3.292z" />
        </svg>
      ))}
    </div>
  );
}

function VerifiedBadge() {
  return (
    <svg className="w-3.5 h-3.5 text-sdr-accent-blue" viewBox="0 0 20 20" fill="currentColor">
      <path
        fillRule="evenodd"
        d="M6.267 3.455a3.066 3.066 0 001.745-.723 3.066 3.066 0 013.976 0 3.066 3.066 0 001.745.723 3.066 3.066 0 012.812 2.812c.051.643.304 1.254.723 1.745a3.066 3.066 0 010 3.976 3.066 3.066 0 00-.723 1.745 3.066 3.066 0 01-2.812 2.812 3.066 3.066 0 00-1.745.723 3.066 3.066 0 01-3.976 0 3.066 3.066 0 00-1.745-.723 3.066 3.066 0 01-2.812-2.812 3.066 3.066 0 00-.723-1.745 3.066 3.066 0 010-3.976 3.066 3.066 0 00.723-1.745 3.066 3.066 0 012.812-2.812zm7.44 5.252a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z"
        clipRule="evenodd"
      />
    </svg>
  );
}

function formatInstalls(count: number): string {
  if (count >= 1000) {
    return `${(count / 1000).toFixed(1)}k`;
  }
  return String(count);
}

function SearchIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <circle cx="11" cy="11" r="8" />
      <path d="M21 21l-4.35-4.35" />
    </svg>
  );
}

function CloseIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M18 6L6 18M6 6l12 12" />
    </svg>
  );
}
