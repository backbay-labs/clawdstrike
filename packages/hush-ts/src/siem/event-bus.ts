export type Unsubscribe = () => void;

export type EventPredicate<T> = (event: T) => boolean;

export type EventHandler<T> = (event: T) => void | Promise<void>;

export class EventBus<T> {
  private readonly subscribers = new Set<{
    handler: EventHandler<T>;
    predicate?: EventPredicate<T>;
  }>();

  subscribe(handler: EventHandler<T>, options: { predicate?: EventPredicate<T> } = {}): Unsubscribe {
    const entry = { handler, predicate: options.predicate };
    this.subscribers.add(entry);
    return () => {
      this.subscribers.delete(entry);
    };
  }

  emit(event: T): void {
    for (const sub of this.subscribers) {
      if (sub.predicate && !sub.predicate(event)) {
        continue;
      }
      void sub.handler(event);
    }
  }

  clear(): void {
    this.subscribers.clear();
  }
}

