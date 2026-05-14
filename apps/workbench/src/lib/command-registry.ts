/**
 * CommandRegistry — singleton registry for all workbench commands.
 *
 * Commands are registered at app boot and consumed by the command palette,
 * shortcut provider, and any future command-driven UI (context menus, etc.).
 */

export type CommandCategory =
  | "Navigate"
  | "File"
  | "Edit"
  | "Policy"
  | "Guard"
  | "Fleet"
  | "Test"
  | "Sentinel"
  | "Receipt"
  | "Swarm"
  | "View"
  | "Sidebar"
  | "Hunt"
  | "Observatory"
  | "Help";

export type CommandContext = "global" | "editor" | "terminal" | "pane";

export interface Command {
  id: string;
  title: string;
  category: CommandCategory;
  /** Key binding string, e.g. "Meta+S", "Meta+Shift+V". */
  keybinding?: string;
  /** Shortcut dispatch context. Defaults to global. */
  context?: CommandContext | CommandContext[];
  icon?: string;
  /** If provided, the command is only visible/active when this returns true. */
  when?: () => boolean;
  execute: () => void | Promise<void>;
}

type Subscriber = () => void;
type ExecutionSubscriber = (event: CommandExecutionEvent) => void;

export interface CommandExecutionEvent {
  commandId: string;
  title: string;
  category: CommandCategory;
  status: "success" | "error";
  timestamp: number;
  durationMs: number;
  error?: string;
}

function isPromiseLike<T>(value: T | Promise<T>): value is Promise<T> {
  return typeof value === "object" && value !== null && "then" in value;
}

class CommandRegistry {
  private commands = new Map<string, Command>();
  private subscribers = new Set<Subscriber>();
  private executionSubscribers = new Set<ExecutionSubscriber>();
  private version = 0;

  // ---- Mutation ----

  register(cmd: Command): void {
    this.commands.set(cmd.id, cmd);
    this.notify();
  }

  registerAll(cmds: Command[]): void {
    for (const cmd of cmds) {
      this.commands.set(cmd.id, cmd);
    }
    this.notify();
  }

  unregister(id: string): void {
    if (this.commands.delete(id)) {
      this.notify();
    }
  }

  // ---- Queries ----

  getAll(): Command[] {
    return Array.from(this.commands.values()).filter(
      (cmd) => !cmd.when || cmd.when(),
    );
  }

  getById(id: string): Command | undefined {
    const cmd = this.commands.get(id);
    if (cmd && cmd.when && !cmd.when()) return undefined;
    return cmd;
  }

  getByCategory(category: CommandCategory): Command[] {
    return this.getAll().filter((cmd) => cmd.category === category);
  }

  getVersion(): number {
    return this.version;
  }

  /**
   * Fuzzy search across title + category.
   * Splits the query into words; every word must match somewhere in
   * `title` or `category` (case-insensitive).
   */
  search(query: string): Command[] {
    const trimmed = query.trim().toLowerCase();
    if (!trimmed) return this.getAll();

    const words = trimmed.split(/\s+/);
    return this.getAll().filter((cmd) => {
      const haystack = `${cmd.title} ${cmd.category}`.toLowerCase();
      return words.every((w) => haystack.includes(w));
    });
  }

  // ---- Execution ----

  execute(id: string): void | Promise<void> {
    const cmd = this.commands.get(id);
    if (!cmd) {
      console.warn(`[command-registry] Unknown command: ${id}`);
      return;
    }
    if (cmd.when && !cmd.when()) {
      console.warn(`[command-registry] Command disabled: ${id}`);
      return;
    }

    const startedAt = Date.now();

    try {
      const result = cmd.execute();
      if (isPromiseLike(result)) {
        return result
          .then(() => {
            this.notifyExecution({
              commandId: cmd.id,
              title: cmd.title,
              category: cmd.category,
              status: "success",
              timestamp: Date.now(),
              durationMs: Math.max(0, Date.now() - startedAt),
            });
          })
          .catch((error) => {
            this.notifyExecution({
              commandId: cmd.id,
              title: cmd.title,
              category: cmd.category,
              status: "error",
              timestamp: Date.now(),
              durationMs: Math.max(0, Date.now() - startedAt),
              error:
                error instanceof Error
                  ? error.message
                  : typeof error === "string"
                    ? error
                    : "Command execution failed.",
            });
            throw error;
          });
      }

      this.notifyExecution({
        commandId: cmd.id,
        title: cmd.title,
        category: cmd.category,
        status: "success",
        timestamp: Date.now(),
        durationMs: Math.max(0, Date.now() - startedAt),
      });
      return result;
    } catch (error) {
      this.notifyExecution({
        commandId: cmd.id,
        title: cmd.title,
        category: cmd.category,
        status: "error",
        timestamp: Date.now(),
        durationMs: Math.max(0, Date.now() - startedAt),
        error:
          error instanceof Error
            ? error.message
            : typeof error === "string"
              ? error
              : "Command execution failed.",
      });
      throw error;
    }
  }

  // ---- Subscriptions ----

  subscribe(fn: Subscriber): () => void {
    this.subscribers.add(fn);
    return () => {
      this.subscribers.delete(fn);
    };
  }

  subscribeExecutions(fn: ExecutionSubscriber): () => void {
    this.executionSubscribers.add(fn);
    return () => {
      this.executionSubscribers.delete(fn);
    };
  }

  private notify(): void {
    this.version += 1;
    for (const fn of this.subscribers) {
      try {
        fn();
      } catch (e) {
        console.error("[command-registry] subscriber threw:", e);
      }
    }
  }

  private notifyExecution(event: CommandExecutionEvent): void {
    for (const fn of this.executionSubscribers) {
      try {
        fn(event);
      } catch (e) {
        console.error("[command-registry] execution subscriber threw:", e);
      }
    }
  }
}

/** Global singleton. Imported by command palette, shortcut provider, factories. */
export const commandRegistry = new CommandRegistry();
