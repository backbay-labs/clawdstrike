import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { rulesets, rulesetIndex, RULESET_NAMES } from '../ruleset-data';

const RULESETS_DIR = path.resolve(import.meta.dirname, '../../data/rulesets');

describe('ruleset extraction', () => {
  // ---------- Test 1 ----------
  it('extract-rulesets script writes 10 JSON files to src/data/rulesets/', () => {
    const files = fs.readdirSync(RULESETS_DIR).filter((f) => f.endsWith('.json') && f !== 'index.json');
    expect(files).toHaveLength(10);
  });

  // ---------- Test 2 ----------
  it('extract-rulesets script writes index.json with name, extends, description for each ruleset', () => {
    const indexPath = path.join(RULESETS_DIR, 'index.json');
    expect(fs.existsSync(indexPath)).toBe(true);

    const index = JSON.parse(fs.readFileSync(indexPath, 'utf-8'));
    const entries = Object.values(index) as Array<{ name: string; description: string }>;

    for (const entry of entries) {
      expect(entry).toHaveProperty('name');
      expect(entry).toHaveProperty('description');
    }
  });

  // ---------- Test 3 ----------
  it('index.json records ai-agent-posture as extending "clawdstrike:ai-agent"', () => {
    const indexPath = path.join(RULESETS_DIR, 'index.json');
    const index = JSON.parse(fs.readFileSync(indexPath, 'utf-8'));
    expect(index['ai-agent-posture'].extends).toBe('clawdstrike:ai-agent');
  });

  // ---------- Test 4 ----------
  it('index.json records remote-desktop as extending "ai-agent"', () => {
    const indexPath = path.join(RULESETS_DIR, 'index.json');
    const index = JSON.parse(fs.readFileSync(indexPath, 'utf-8'));
    expect(index['remote-desktop'].extends).toBe('ai-agent');
  });

  // ---------- Test 5 ----------
  it('rulesetIndex has exactly 10 entries', () => {
    expect(Object.keys(rulesetIndex)).toHaveLength(10);
  });

  // ---------- Test 6 ----------
  it('RULESET_NAMES array has exactly 10 entries matching expected names', () => {
    expect(RULESET_NAMES).toHaveLength(10);
    const expected = [
      'default', 'strict', 'permissive', 'ai-agent', 'ai-agent-posture',
      'cicd', 'remote-desktop', 'remote-desktop-strict', 'remote-desktop-permissive',
      'spider-sense',
    ];
    expect([...RULESET_NAMES]).toEqual(expected);
  });
});
