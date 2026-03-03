import { describe, it, expect } from 'vitest';
import { parseHumanDuration } from './duration.js';

describe('parseHumanDuration', () => {
  describe('short suffixes', () => {
    it('parses seconds', () => {
      expect(parseHumanDuration('30s')).toBe(30_000);
    });

    it('parses minutes', () => {
      expect(parseHumanDuration('5m')).toBe(300_000);
    });

    it('parses hours', () => {
      expect(parseHumanDuration('1h')).toBe(3_600_000);
    });

    it('parses days', () => {
      expect(parseHumanDuration('2d')).toBe(172_800_000);
    });
  });

  describe('long suffixes', () => {
    it('parses sec', () => {
      expect(parseHumanDuration('30sec')).toBe(30_000);
    });

    it('parses secs', () => {
      expect(parseHumanDuration('30secs')).toBe(30_000);
    });

    it('parses second', () => {
      expect(parseHumanDuration('1second')).toBe(1_000);
    });

    it('parses seconds', () => {
      expect(parseHumanDuration('10seconds')).toBe(10_000);
    });

    it('parses min', () => {
      expect(parseHumanDuration('5min')).toBe(300_000);
    });

    it('parses mins', () => {
      expect(parseHumanDuration('5mins')).toBe(300_000);
    });

    it('parses minute', () => {
      expect(parseHumanDuration('1minute')).toBe(60_000);
    });

    it('parses minutes', () => {
      expect(parseHumanDuration('10minutes')).toBe(600_000);
    });

    it('parses hr', () => {
      expect(parseHumanDuration('1hr')).toBe(3_600_000);
    });

    it('parses hrs', () => {
      expect(parseHumanDuration('2hrs')).toBe(7_200_000);
    });

    it('parses hour', () => {
      expect(parseHumanDuration('1hour')).toBe(3_600_000);
    });

    it('parses hours', () => {
      expect(parseHumanDuration('3hours')).toBe(10_800_000);
    });

    it('parses day', () => {
      expect(parseHumanDuration('1day')).toBe(86_400_000);
    });

    it('parses days', () => {
      expect(parseHumanDuration('3days')).toBe(259_200_000);
    });
  });

  describe('invalid inputs', () => {
    it('rejects empty string', () => {
      expect(parseHumanDuration('')).toBeUndefined();
    });

    it('rejects whitespace only', () => {
      expect(parseHumanDuration('   ')).toBeUndefined();
    });

    it('rejects letters only', () => {
      expect(parseHumanDuration('abc')).toBeUndefined();
    });

    it('rejects unknown suffix', () => {
      expect(parseHumanDuration('10x')).toBeUndefined();
    });

    it('rejects digits only', () => {
      expect(parseHumanDuration('1')).toBeUndefined();
    });

    it('rejects no digits', () => {
      expect(parseHumanDuration('seconds')).toBeUndefined();
    });
  });

  describe('edge cases', () => {
    it('parses zero', () => {
      expect(parseHumanDuration('0s')).toBe(0);
    });

    it('trims whitespace', () => {
      expect(parseHumanDuration('  30s  ')).toBe(30_000);
    });

    it('handles space between digits and suffix', () => {
      expect(parseHumanDuration('30 s')).toBe(30_000);
    });

    it('handles case-insensitive suffix', () => {
      expect(parseHumanDuration('5HOURS')).toBe(18_000_000);
    });
  });
});
