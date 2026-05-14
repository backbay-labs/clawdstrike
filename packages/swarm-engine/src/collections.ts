/**
 * Deque and PriorityQueue data structures for the swarm engine.
 *
 * @module
 */

import type { TaskPriority } from "./types.js";

/** Circular buffer deque. O(1) pushBack/popFront, auto-grows. */
export class Deque<T> {
  private buffer: (T | undefined)[];
  private head: number = 0;
  private tail: number = 0;
  private count: number = 0;
  private capacity: number;

  constructor(initialCapacity: number = 16) {
    this.capacity = initialCapacity;
    this.buffer = new Array(this.capacity);
  }

  get length(): number {
    return this.count;
  }

  private grow(): void {
    const newCapacity = this.capacity * 2;
    const newBuffer = new Array(newCapacity);

    for (let i = 0; i < this.count; i++) {
      newBuffer[i] = this.buffer[(this.head + i) % this.capacity];
    }

    this.buffer = newBuffer;
    this.head = 0;
    this.tail = this.count;
    this.capacity = newCapacity;
  }

  pushBack(item: T): void {
    if (this.count === this.capacity) {
      this.grow();
    }
    this.buffer[this.tail] = item;
    this.tail = (this.tail + 1) % this.capacity;
    this.count++;
  }

  popFront(): T | undefined {
    if (this.count === 0) {
      return undefined;
    }
    const item = this.buffer[this.head];
    this.buffer[this.head] = undefined;
    this.head = (this.head + 1) % this.capacity;
    this.count--;
    return item;
  }

  peekFront(): T | undefined {
    if (this.count === 0) {
      return undefined;
    }
    return this.buffer[this.head];
  }

  clear(): void {
    this.buffer = new Array(this.capacity);
    this.head = 0;
    this.tail = 0;
    this.count = 0;
  }

  findAndRemove(predicate: (item: T) => boolean): T | undefined {
    for (let i = 0; i < this.count; i++) {
      const idx = (this.head + i) % this.capacity;
      const item = this.buffer[idx];
      if (item !== undefined && predicate(item)) {
        for (let j = i; j < this.count - 1; j++) {
          const currentIdx = (this.head + j) % this.capacity;
          const nextIdx = (this.head + j + 1) % this.capacity;
          this.buffer[currentIdx] = this.buffer[nextIdx];
        }
        this.tail = (this.tail - 1 + this.capacity) % this.capacity;
        this.buffer[this.tail] = undefined;
        this.count--;
        return item;
      }
    }
    return undefined;
  }

  find(predicate: (item: T) => boolean): T | undefined {
    for (let i = 0; i < this.count; i++) {
      const idx = (this.head + i) % this.capacity;
      const item = this.buffer[idx];
      if (item !== undefined && predicate(item)) {
        return item;
      }
    }
    return undefined;
  }

  *[Symbol.iterator](): Iterator<T> {
    for (let i = 0; i < this.count; i++) {
      const item = this.buffer[(this.head + i) % this.capacity];
      if (item !== undefined) {
        yield item;
      }
    }
  }
}

const PRIORITY_ORDER: TaskPriority[] = [
  "critical",
  "high",
  "normal",
  "low",
  "background",
];

const REVERSE_PRIORITY_ORDER: TaskPriority[] = [
  "background",
  "low",
  "normal",
  "high",
  "critical",
];

/**
 * 5-lane priority queue (critical > high > normal > low > background).
 * O(1) enqueue/dequeue, FIFO within each lane.
 */
export class PriorityQueue<T> {
  private lanes = new Map<TaskPriority, Deque<T>>();
  private totalCount: number = 0;

  constructor() {
    for (const priority of PRIORITY_ORDER) {
      this.lanes.set(priority, new Deque<T>());
    }
  }

  get length(): number {
    return this.totalCount;
  }

  enqueue(item: T, priority: TaskPriority): void {
    const lane = this.lanes.get(priority)!;
    lane.pushBack(item);
    this.totalCount++;
  }

  dequeue(): T | undefined {
    for (const priority of PRIORITY_ORDER) {
      const lane = this.lanes.get(priority)!;
      if (lane.length > 0) {
        this.totalCount--;
        return lane.popFront();
      }
    }
    return undefined;
  }

  /** Remove and return the lowest-priority item for overflow handling. */
  removeLowestPriority(): T | undefined {
    for (const priority of REVERSE_PRIORITY_ORDER) {
      const lane = this.lanes.get(priority)!;
      if (lane.length > 0) {
        this.totalCount--;
        return lane.popFront();
      }
    }
    return undefined;
  }

  clear(): void {
    for (const lane of this.lanes.values()) {
      lane.clear();
    }
    this.totalCount = 0;
  }

  find(predicate: (item: T) => boolean): T | undefined {
    for (const lane of this.lanes.values()) {
      const found = lane.find(predicate);
      if (found) {
        return found;
      }
    }
    return undefined;
  }
}
