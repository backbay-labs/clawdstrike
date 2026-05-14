'use client';

import { useState } from 'react';
import { ChevronRight, ChevronDown } from 'lucide-react';
import { rulesetIndex, rulesets } from '@/lib/ruleset-data';
import type { RulesetIndexEntry } from '@/lib/ruleset-data';
import { Badge } from '@/components/ui/badge';

// ---------------------------------------------------------------------------
// Tree data types
// ---------------------------------------------------------------------------

export interface TreeNode {
  id: string;
  name: string;
  children: TreeNode[];
  overrides: string[];
  description: string;
}

// ---------------------------------------------------------------------------
// Pure tree-building logic (exported for testing)
// ---------------------------------------------------------------------------

/**
 * Build a tree of ruleset inheritance from the index and parsed data.
 *
 * Roots are entries with no `extends` field. Children are entries whose
 * `extends` matches a parent id (with optional `clawdstrike:` prefix stripped).
 *
 * For each child node, `overrides` lists the guard config keys from the child
 * that also appear in the parent's guards object (i.e., keys the child overrides).
 */
export function buildInheritanceTree(
  index: Record<string, RulesetIndexEntry>,
  data: Record<string, object>,
): TreeNode[] {
  /**
   * Normalise the extends value: strip the `clawdstrike:` prefix if present.
   */
  function normaliseExtends(raw?: string): string | undefined {
    if (!raw) return undefined;
    return raw.replace(/^clawdstrike:/, '');
  }

  /**
   * Compute override/addition keys: all guard config keys the child explicitly
   * configures. These are either overrides of parent keys or new additions.
   */
  function computeOverrides(
    childId: string,
    _parentId: string,
  ): string[] {
    const childGuards = (data[childId] as Record<string, unknown>)?.guards as
      | Record<string, unknown>
      | undefined;

    if (!childGuards) return [];

    return Object.keys(childGuards).sort();
  }

  /**
   * Recursively build child nodes for a given parent id.
   */
  function buildChildren(parentId: string): TreeNode[] {
    const children: TreeNode[] = [];

    for (const [id, entry] of Object.entries(index)) {
      const norm = normaliseExtends(entry.extends);
      if (norm === parentId) {
        children.push({
          id,
          name: entry.name,
          description: entry.description,
          overrides: computeOverrides(id, parentId),
          children: buildChildren(id),
        });
      }
    }

    // Sort children alphabetically for stable output
    children.sort((a, b) => a.id.localeCompare(b.id));
    return children;
  }

  // Find root entries: no `extends` or extends normalises to undefined
  const roots: TreeNode[] = [];

  for (const [id, entry] of Object.entries(index)) {
    const norm = normaliseExtends(entry.extends);
    if (!norm) {
      roots.push({
        id,
        name: entry.name,
        description: entry.description,
        overrides: [],
        children: buildChildren(id),
      });
    }
  }

  roots.sort((a, b) => a.id.localeCompare(b.id));
  return roots;
}

// ---------------------------------------------------------------------------
// Tree node renderer
// ---------------------------------------------------------------------------

function TreeNodeComponent({
  node,
  depth,
  highlight,
}: {
  node: TreeNode;
  depth: number;
  highlight?: string;
}) {
  const [expanded, setExpanded] = useState(depth < 2);
  const hasChildren = node.children.length > 0;
  const isHighlighted = highlight === node.id;

  return (
    <div className={depth > 0 ? 'ml-6 border-l-2 border-muted pl-4' : ''}>
      <div
        className={`flex items-start gap-2 py-1.5 ${isHighlighted ? 'bg-primary/10 rounded px-2 -mx-2' : ''}`}
      >
        {hasChildren ? (
          <button
            type="button"
            onClick={() => setExpanded(!expanded)}
            className="mt-0.5 text-muted-foreground hover:text-foreground transition-colors shrink-0"
            aria-label={expanded ? 'Collapse' : 'Expand'}
          >
            {expanded ? (
              <ChevronDown className="h-4 w-4" />
            ) : (
              <ChevronRight className="h-4 w-4" />
            )}
          </button>
        ) : (
          <span className="w-4 shrink-0" />
        )}

        <div className="flex flex-col gap-0.5 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-semibold text-sm">{node.name}</span>
            <code className="text-xs text-muted-foreground font-mono">
              {node.id}
            </code>
            {node.overrides.length > 0 && (
              <Badge variant="secondary" className="text-[10px] px-1.5 py-0">
                {node.overrides.length} override{node.overrides.length !== 1 ? 's' : ''}
              </Badge>
            )}
          </div>
          <p className="text-xs text-muted-foreground leading-snug">
            {node.description}
          </p>
          {expanded && node.overrides.length > 0 && (
            <div className="flex flex-wrap gap-1 mt-1">
              {node.overrides.map((key) => (
                <Badge
                  key={key}
                  variant="outline"
                  className="text-[10px] px-1.5 py-0 font-mono"
                >
                  {key}
                </Badge>
              ))}
            </div>
          )}
        </div>
      </div>

      {expanded && hasChildren && (
        <div className="mt-1">
          {node.children.map((child) => (
            <TreeNodeComponent
              key={child.id}
              node={child}
              depth={depth + 1}
              highlight={highlight}
            />
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export interface InheritanceTreeProps {
  highlight?: string;
}

export function InheritanceTree({ highlight }: InheritanceTreeProps) {
  const tree = buildInheritanceTree(rulesetIndex, rulesets);

  return (
    <div className="my-6 space-y-1">
      {tree.map((root) => (
        <TreeNodeComponent
          key={root.id}
          node={root}
          depth={0}
          highlight={highlight}
        />
      ))}
    </div>
  );
}
