import { describe, it, expect } from 'vitest';
import { buildInheritanceTree, type TreeNode } from '@/components/policy-lab/inheritance-tree';
import { rulesetIndex, rulesets } from '@/lib/ruleset-data';

describe('buildInheritanceTree', () => {
  let tree: TreeNode[];

  // Build tree once for all tests
  tree = buildInheritanceTree(rulesetIndex, rulesets);

  it('produces 6 root nodes (default, strict, permissive, ai-agent, cicd, spider-sense)', () => {
    const rootNames = tree.map((n) => n.id).sort();
    expect(rootNames).toEqual([
      'ai-agent',
      'cicd',
      'default',
      'permissive',
      'spider-sense',
      'strict',
    ]);
  });

  it('ai-agent root has 2 children (ai-agent-posture, remote-desktop)', () => {
    const aiAgent = tree.find((n) => n.id === 'ai-agent');
    expect(aiAgent).toBeDefined();
    const childIds = aiAgent!.children.map((c) => c.id).sort();
    expect(childIds).toEqual(['ai-agent-posture', 'remote-desktop']);
  });

  it('remote-desktop node has 2 children (remote-desktop-strict, remote-desktop-permissive)', () => {
    const aiAgent = tree.find((n) => n.id === 'ai-agent');
    const remoteDesktop = aiAgent!.children.find((c) => c.id === 'remote-desktop');
    expect(remoteDesktop).toBeDefined();
    const childIds = remoteDesktop!.children.map((c) => c.id).sort();
    expect(childIds).toEqual(['remote-desktop-permissive', 'remote-desktop-strict']);
  });

  it('"clawdstrike:" prefix is stripped from extends field during tree building', () => {
    // ai-agent-posture has extends: "clawdstrike:ai-agent" in the index
    // It should appear as a child of ai-agent, not a root
    const rootIds = tree.map((n) => n.id);
    expect(rootIds).not.toContain('ai-agent-posture');
    const aiAgent = tree.find((n) => n.id === 'ai-agent');
    expect(aiAgent!.children.some((c) => c.id === 'ai-agent-posture')).toBe(true);
  });

  it('overrides array lists guard config keys that differ from parent', () => {
    const aiAgent = tree.find((n) => n.id === 'ai-agent');
    const remoteDesktop = aiAgent!.children.find((c) => c.id === 'remote-desktop');
    expect(remoteDesktop).toBeDefined();
    // remote-desktop extends ai-agent and adds computer_use, remote_desktop_side_channel, input_injection_capability
    expect(remoteDesktop!.overrides.length).toBeGreaterThan(0);
    expect(remoteDesktop!.overrides).toContain('computer_use');
  });
});
