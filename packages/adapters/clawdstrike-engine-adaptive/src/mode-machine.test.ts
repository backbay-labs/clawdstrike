import { describe, it, expect } from 'vitest';
import { createModeMachine } from './mode-machine.js';
import type { ModeChangeEvent } from './types.js';

describe('ModeMachine', () => {
  it('starts in the given initial mode', () => {
    const machine = createModeMachine('standalone');
    expect(machine.current()).toBe('standalone');
  });

  it('transitions standalone → connected', async () => {
    const machine = createModeMachine('standalone');
    const ok = await machine.transition('connected', 'remote healthy');
    expect(ok).toBe(true);
    expect(machine.current()).toBe('connected');
  });

  it('transitions connected → degraded', async () => {
    const machine = createModeMachine('connected');
    const ok = await machine.transition('degraded', 'connectivity lost');
    expect(ok).toBe(true);
    expect(machine.current()).toBe('degraded');
  });

  it('transitions degraded → connected', async () => {
    const machine = createModeMachine('degraded');
    const ok = await machine.transition('connected', 'remote recovered');
    expect(ok).toBe(true);
    expect(machine.current()).toBe('connected');
  });

  it('transitions degraded → standalone', async () => {
    const machine = createModeMachine('degraded');
    const ok = await machine.transition('standalone', 'gave up on remote');
    expect(ok).toBe(true);
    expect(machine.current()).toBe('standalone');
  });

  it('rejects invalid transition standalone → degraded', async () => {
    const machine = createModeMachine('standalone');
    const ok = await machine.transition('degraded', 'invalid');
    expect(ok).toBe(false);
    expect(machine.current()).toBe('standalone');
  });

  it('rejects invalid transition connected → standalone', async () => {
    const machine = createModeMachine('connected');
    const ok = await machine.transition('standalone', 'invalid');
    expect(ok).toBe(false);
    expect(machine.current()).toBe('connected');
  });

  it('rejects no-op transition to same mode', async () => {
    const machine = createModeMachine('standalone');
    const ok = await machine.transition('standalone', 'noop');
    expect(ok).toBe(false);
    expect(machine.current()).toBe('standalone');
  });

  it('emits ModeChangeEvent on valid transition', async () => {
    const machine = createModeMachine('standalone');
    const events: ModeChangeEvent[] = [];
    machine.onModeChange((e) => events.push(e));

    await machine.transition('connected', 'test reason');
    expect(events).toHaveLength(1);
    expect(events[0].from).toBe('standalone');
    expect(events[0].to).toBe('connected');
    expect(events[0].reason).toBe('test reason');
    expect(events[0].timestamp).toBeTruthy();
  });

  it('does not emit on rejected transition', async () => {
    const machine = createModeMachine('standalone');
    const events: ModeChangeEvent[] = [];
    machine.onModeChange((e) => events.push(e));

    await machine.transition('degraded', 'should not fire');
    expect(events).toHaveLength(0);
  });

  it('serializes concurrent transitions', async () => {
    const machine = createModeMachine('standalone');
    const events: ModeChangeEvent[] = [];
    machine.onModeChange((e) => events.push(e));

    // Fire two transitions concurrently. Only standalone → connected is valid.
    // The second (connected → degraded) should see the updated state.
    const [r1, r2] = await Promise.all([
      machine.transition('connected', 'first'),
      machine.transition('degraded', 'second'),
    ]);

    expect(r1).toBe(true);
    // After serialized execution: standalone → connected (first), then connected → degraded (second)
    expect(r2).toBe(true);
    expect(machine.current()).toBe('degraded');
    expect(events).toHaveLength(2);
  });

  it('swallows listener errors without breaking', async () => {
    const machine = createModeMachine('standalone');
    machine.onModeChange(() => {
      throw new Error('listener boom');
    });
    const ok = await machine.transition('connected', 'should not throw');
    expect(ok).toBe(true);
    expect(machine.current()).toBe('connected');
  });

  it('supports multiple listeners', async () => {
    const machine = createModeMachine('standalone');
    const calls: string[] = [];
    machine.onModeChange(() => calls.push('a'));
    machine.onModeChange(() => calls.push('b'));

    await machine.transition('connected', 'multi');
    expect(calls).toEqual(['a', 'b']);
  });
});
