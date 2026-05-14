/**
 * Unit tests for Deque and PriorityQueue data structures.
 *
 * Covers: TASK-02 (5-level priority queue with extracted Deque/PriorityQueue
 * from ruflo message-bus.ts).
 */

import { describe, it, expect } from "vitest";
import { Deque, PriorityQueue } from "./collections.js";
import type { TaskPriority } from "./types.js";

// ============================================================================
// Deque Tests
// ============================================================================

describe("Deque", () => {
  it("popFront on empty deque returns undefined", () => {
    const d = new Deque<number>();
    expect(d.popFront()).toBeUndefined();
  });

  it("single push/pop round-trip", () => {
    const d = new Deque<string>();
    d.pushBack("hello");
    expect(d.length).toBe(1);
    expect(d.popFront()).toBe("hello");
    expect(d.length).toBe(0);
  });

  it("maintains FIFO ordering", () => {
    const d = new Deque<number>();
    d.pushBack(1);
    d.pushBack(2);
    d.pushBack(3);
    expect(d.popFront()).toBe(1);
    expect(d.popFront()).toBe(2);
    expect(d.popFront()).toBe(3);
  });

  it("handles capacity growth (push 20 items into capacity-16 deque)", () => {
    const d = new Deque<number>(16);
    for (let i = 0; i < 20; i++) {
      d.pushBack(i);
    }
    expect(d.length).toBe(20);
    // Verify FIFO order is preserved after growth
    for (let i = 0; i < 20; i++) {
      expect(d.popFront()).toBe(i);
    }
    expect(d.length).toBe(0);
  });

  it("clear resets to empty", () => {
    const d = new Deque<number>();
    d.pushBack(1);
    d.pushBack(2);
    d.pushBack(3);
    d.clear();
    expect(d.length).toBe(0);
    expect(d.popFront()).toBeUndefined();
  });

  it("iterator yields all elements in FIFO order", () => {
    const d = new Deque<number>();
    d.pushBack(10);
    d.pushBack(20);
    d.pushBack(30);
    const result = [...d];
    expect(result).toEqual([10, 20, 30]);
  });

  it("findAndRemove returns and removes matching element", () => {
    const d = new Deque<{ id: number; name: string }>();
    d.pushBack({ id: 1, name: "a" });
    d.pushBack({ id: 2, name: "b" });
    d.pushBack({ id: 3, name: "c" });

    const removed = d.findAndRemove((item) => item.id === 2);
    expect(removed).toEqual({ id: 2, name: "b" });
    expect(d.length).toBe(2);

    // Remaining items should be in order
    const remaining = [...d];
    expect(remaining).toEqual([
      { id: 1, name: "a" },
      { id: 3, name: "c" },
    ]);
  });

  it("findAndRemove returns undefined when no match", () => {
    const d = new Deque<number>();
    d.pushBack(1);
    d.pushBack(2);
    const result = d.findAndRemove((x) => x === 99);
    expect(result).toBeUndefined();
    expect(d.length).toBe(2);
  });

  it("find returns matching element without removing", () => {
    const d = new Deque<number>();
    d.pushBack(10);
    d.pushBack(20);
    d.pushBack(30);
    const found = d.find((x) => x === 20);
    expect(found).toBe(20);
    expect(d.length).toBe(3); // not removed
  });

  it("find returns undefined when no match", () => {
    const d = new Deque<number>();
    d.pushBack(1);
    const found = d.find((x) => x === 99);
    expect(found).toBeUndefined();
  });

  it("peekFront returns head without removing", () => {
    const d = new Deque<string>();
    d.pushBack("first");
    d.pushBack("second");
    expect(d.peekFront()).toBe("first");
    expect(d.length).toBe(2);
  });

  it("peekFront on empty deque returns undefined", () => {
    const d = new Deque<number>();
    expect(d.peekFront()).toBeUndefined();
  });

  it("length tracks count accurately after mixed push/pop", () => {
    const d = new Deque<number>();
    d.pushBack(1);
    d.pushBack(2);
    expect(d.length).toBe(2);
    d.popFront();
    expect(d.length).toBe(1);
    d.pushBack(3);
    d.pushBack(4);
    expect(d.length).toBe(3);
    d.popFront();
    d.popFront();
    d.popFront();
    expect(d.length).toBe(0);
  });
});

// ============================================================================
// PriorityQueue Tests
// ============================================================================

describe("PriorityQueue", () => {
  it("dequeue on empty queue returns undefined", () => {
    const q = new PriorityQueue<string>();
    expect(q.dequeue()).toBeUndefined();
  });

  it("single enqueue/dequeue round-trip", () => {
    const q = new PriorityQueue<string>();
    q.enqueue("task-1", "normal");
    expect(q.length).toBe(1);
    expect(q.dequeue()).toBe("task-1");
    expect(q.length).toBe(0);
  });

  it("dequeue returns items in strict priority order (critical > high > normal > low > background)", () => {
    const q = new PriorityQueue<string>();
    // Enqueue in reverse priority order
    q.enqueue("bg-task", "background");
    q.enqueue("low-task", "low");
    q.enqueue("normal-task", "normal");
    q.enqueue("high-task", "high");
    q.enqueue("critical-task", "critical");

    expect(q.dequeue()).toBe("critical-task");
    expect(q.dequeue()).toBe("high-task");
    expect(q.dequeue()).toBe("normal-task");
    expect(q.dequeue()).toBe("low-task");
    expect(q.dequeue()).toBe("bg-task");
    expect(q.dequeue()).toBeUndefined();
  });

  it("maintains FIFO within same priority level", () => {
    const q = new PriorityQueue<string>();
    q.enqueue("first-normal", "normal");
    q.enqueue("second-normal", "normal");
    q.enqueue("third-normal", "normal");

    expect(q.dequeue()).toBe("first-normal");
    expect(q.dequeue()).toBe("second-normal");
    expect(q.dequeue()).toBe("third-normal");
  });

  it("length tracks total across all lanes", () => {
    const q = new PriorityQueue<string>();
    q.enqueue("a", "critical");
    q.enqueue("b", "high");
    q.enqueue("c", "normal");
    q.enqueue("d", "low");
    q.enqueue("e", "background");
    expect(q.length).toBe(5);

    q.dequeue();
    expect(q.length).toBe(4);
    q.dequeue();
    q.dequeue();
    expect(q.length).toBe(2);
  });

  it("clear empties all lanes", () => {
    const q = new PriorityQueue<string>();
    q.enqueue("a", "critical");
    q.enqueue("b", "high");
    q.enqueue("c", "low");
    q.clear();
    expect(q.length).toBe(0);
    expect(q.dequeue()).toBeUndefined();
  });

  it("removeLowestPriority checks background first, then low, then normal", () => {
    const q = new PriorityQueue<string>();
    q.enqueue("normal-1", "normal");
    q.enqueue("low-1", "low");
    q.enqueue("bg-1", "background");

    // Should remove background first
    expect(q.removeLowestPriority()).toBe("bg-1");
    // Then low
    expect(q.removeLowestPriority()).toBe("low-1");
    // Then normal
    expect(q.removeLowestPriority()).toBe("normal-1");
    expect(q.length).toBe(0);
  });

  it("removeLowestPriority falls back to higher priorities when lower are empty", () => {
    const q = new PriorityQueue<string>();
    q.enqueue("critical-1", "critical");
    q.enqueue("high-1", "high");

    // No background/low/normal, so falls back: high first, then critical
    expect(q.removeLowestPriority()).toBe("high-1");
    expect(q.removeLowestPriority()).toBe("critical-1");
  });

  it("removeLowestPriority returns undefined when empty", () => {
    const q = new PriorityQueue<string>();
    expect(q.removeLowestPriority()).toBeUndefined();
  });

  it("find locates item across lanes", () => {
    const q = new PriorityQueue<{ id: string }>();
    q.enqueue({ id: "a" }, "low");
    q.enqueue({ id: "b" }, "critical");
    q.enqueue({ id: "c" }, "normal");

    const found = q.find((item) => item.id === "c");
    expect(found).toEqual({ id: "c" });
    expect(q.length).toBe(3); // not removed
  });

  it("find returns undefined when no match", () => {
    const q = new PriorityQueue<string>();
    q.enqueue("x", "normal");
    const found = q.find((item) => item === "y");
    expect(found).toBeUndefined();
  });

  it("supports all 5 TaskPriority levels", () => {
    const priorities: TaskPriority[] = [
      "critical",
      "high",
      "normal",
      "low",
      "background",
    ];
    const q = new PriorityQueue<string>();

    for (const p of priorities) {
      q.enqueue(`task-${p}`, p);
    }
    expect(q.length).toBe(5);

    // Dequeue order matches priority order
    for (const p of priorities) {
      expect(q.dequeue()).toBe(`task-${p}`);
    }
  });
});
