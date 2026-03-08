# Spec 18: Huntronomer Shell Command Model

> **Status:** Draft | **Date:** 2026-03-07
> **Author:** Codex
> **Dependencies:** Spec 16, Spec 17, Huntronomer target architecture

## 1. Overview

This specification defines the keyboard-first command model for the Huntronomer desktop shell. It
covers the omnibox, command palette, route-aware actions, and how surfaces register commands
without binding the product back to legacy plugin IDs.

The purpose is to make the shell behave like one coherent operating environment across:

- `Signal Wire`
- `Huntboard`
- `Receipt Vault / Replay`
- `Cases`
- `Profile`
- `Workspace`
- `Settings`

## 2. Scope

This spec defines:

- command scopes and context
- command registration rules
- dispatch behavior
- command history and ranking basics
- shell-level invariants for keyboard-first navigation

This spec does not define:

- final visual styling of the omnibox
- backend command payloads outside the shell contract
- ranking algorithms beyond basic ordering rules

## 3. Design Invariants

1. Commands must not depend on legacy plugin IDs such as `nexus` or `events`.
2. Every command must declare its scope, context requirements, and result behavior.
3. Keyboard navigation must be available without touching the mouse.
4. The omnibox must be able to open objects and run actions from one place.
5. Surface-local commands may extend the registry, but global navigation stays shell-owned.
6. A command can be visible yet unavailable, but the reason must be explainable from context.

## 4. Command Scope Model

```ts
type CommandScope =
  | "global"
  | "wire"
  | "huntboard"
  | "vault"
  | "replay"
  | "cases"
  | "profile"
  | "workspace"
  | "settings";
```

Global commands are always eligible. Surface commands only participate when the active surface
matches.

## 5. Command Context

```ts
interface CommandContext {
  activeScope: CommandScope;
  workspaceRootId?: string;
  activeSurfaceRoute: string;
  activeObject?: { type: string; id: string };
  selectedObjectIds: string[];
  focusedPane?: "main" | "right" | "bottom" | "workspace-tree" | "terminal";
  connectivity: {
    daemon: "connected" | "degraded" | "offline";
    openclaw: "connected" | "degraded" | "offline";
  };
}
```

The shell should construct this context centrally so individual surfaces do not invent competing
context models.

## 6. Command Registration Contract

```ts
interface ShellCommand {
  id: string;
  title: string;
  description?: string;
  keywords?: string[];
  group: string;
  scope: CommandScope | CommandScope[];
  shortcut?: string;
  when?: (context: CommandContext) => boolean;
  run: (context: CommandContext) => CommandResult | Promise<CommandResult>;
}
```

```ts
type CommandResult =
  | { kind: "navigate"; to: string }
  | { kind: "invoke"; action: string; payload?: Record<string, unknown> }
  | { kind: "open-panel"; panel: string; payload?: Record<string, unknown> }
  | { kind: "toast"; level: "info" | "warning" | "error"; message: string }
  | { kind: "noop" };
```

## 7. Required Command Categories

### 7.1 Global navigation

- open Wire
- open Huntboard
- open Vault
- open Cases
- open Profile
- open Workspace
- open Settings

### 7.2 Object lookup

The omnibox must be able to open:

- hunts
- signals
- receipts
- entities
- rules
- cases
- users
- workspace files

### 7.3 Wire and hunt actions

- fork hunt
- assign swarm
- validate
- challenge
- cite
- promote

### 7.4 Workspace actions

- open folder
- quick open file
- search in workspace
- open terminal
- open git status
- save file

### 7.5 Proof actions

- open replay
- compare receipts
- copy proof link
- open related case

## 8. Dispatch Rules

1. Navigation results are handled by the shell router.
2. Backend actions are dispatched through typed service wrappers, not inline shell execution.
3. Commands that depend on active selections must fail gracefully when selection is missing.
4. Surface modules may register commands, but they must do so through one central registry.
5. Command history should bias toward recency within scope, but exact ranking can remain simple at
   first ship.

## 9. Initial Keyboard Contract

Minimum expected shortcuts:

- `Cmd+K` opens the omnibox
- arrow keys move through results
- `Enter` executes the selected command
- `Esc` closes the omnibox or active overlay
- surface-specific shortcuts may extend this, but must not collide with shell-global shortcuts

## 10. Migration Rule

Any existing command-palette behavior that still assumes legacy plugin navigation should be treated
as compatibility code only. The target command model is route- and object-based, not plugin-card
based.
