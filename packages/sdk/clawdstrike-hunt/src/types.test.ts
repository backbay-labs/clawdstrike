import { describe, it, expect } from 'vitest';
import {
  EventSourceType,
  TimelineEventKind,
  NormalizedVerdict,
  QueryVerdict,
  RuleSeverity,
  IocType,
} from './types.js';

describe('types', () => {
  describe('EventSourceType', () => {
    it('has expected values', () => {
      expect(EventSourceType.Tetragon).toBe('tetragon');
      expect(EventSourceType.Hubble).toBe('hubble');
      expect(EventSourceType.Receipt).toBe('receipt');
      expect(EventSourceType.Scan).toBe('scan');
    });
  });

  describe('TimelineEventKind', () => {
    it('has expected values', () => {
      expect(TimelineEventKind.ProcessExec).toBe('process_exec');
      expect(TimelineEventKind.ProcessExit).toBe('process_exit');
      expect(TimelineEventKind.ProcessKprobe).toBe('process_kprobe');
      expect(TimelineEventKind.NetworkFlow).toBe('network_flow');
      expect(TimelineEventKind.GuardDecision).toBe('guard_decision');
      expect(TimelineEventKind.ScanResult).toBe('scan_result');
    });
  });

  describe('NormalizedVerdict', () => {
    it('has expected values', () => {
      expect(NormalizedVerdict.Allow).toBe('allow');
      expect(NormalizedVerdict.Deny).toBe('deny');
      expect(NormalizedVerdict.Warn).toBe('warn');
      expect(NormalizedVerdict.None).toBe('none');
      expect(NormalizedVerdict.Forwarded).toBe('forwarded');
      expect(NormalizedVerdict.Dropped).toBe('dropped');
    });
  });

  describe('QueryVerdict', () => {
    it('has expected values', () => {
      expect(QueryVerdict.Allow).toBe('allow');
      expect(QueryVerdict.Deny).toBe('deny');
      expect(QueryVerdict.Warn).toBe('warn');
      expect(QueryVerdict.Forwarded).toBe('forwarded');
      expect(QueryVerdict.Dropped).toBe('dropped');
    });

    it('does not include None', () => {
      expect('None' in QueryVerdict).toBe(false);
    });
  });

  describe('RuleSeverity', () => {
    it('has expected values', () => {
      expect(RuleSeverity.Low).toBe('low');
      expect(RuleSeverity.Medium).toBe('medium');
      expect(RuleSeverity.High).toBe('high');
      expect(RuleSeverity.Critical).toBe('critical');
    });
  });

  describe('IocType', () => {
    it('has expected values', () => {
      expect(IocType.Sha256).toBe('sha256');
      expect(IocType.Sha1).toBe('sha1');
      expect(IocType.Md5).toBe('md5');
      expect(IocType.Domain).toBe('domain');
      expect(IocType.IPv4).toBe('ipv4');
      expect(IocType.IPv6).toBe('ipv6');
      expect(IocType.Url).toBe('url');
    });
  });
});
