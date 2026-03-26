/**
 * NoteNode unit tests — tests the real NoteNode component's rendering,
 * editing workflow, and keyboard handling.
 *
 * NOTE: The existing note-node.test.tsx uses a stub component. This file
 * tests the actual NoteNode import with proper mocks.
 */
import React from "react";
import { render, screen, fireEvent, act } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi, beforeEach } from "vitest";
import type { SwarmBoardNodeData } from "@/features/swarm/swarm-board-types";

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

const mockUpdateNode = vi.fn();

vi.mock("@xyflow/react", () => ({
  NodeResizer: () => null,
  useStore: (selector: (s: any) => any) => selector({ transform: [0, 0, 1] }),
}));

vi.mock("@/features/swarm/stores/swarm-board-store", () => ({
  useSwarmBoard: () => ({
    updateNode: mockUpdateNode,
  }),
}));

vi.mock("../../hooks/use-zoom-tier", () => ({
  useZoomTier: () => "full",
}));

// ---------------------------------------------------------------------------
// Import after mocks
// ---------------------------------------------------------------------------

import { NoteNode } from "../nodes/note-node";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function renderNoteNode(dataOverrides: Partial<SwarmBoardNodeData> = {}, selected = false) {
  const data: SwarmBoardNodeData = {
    title: "My Note",
    status: "idle",
    nodeType: "note",
    content: "Some content here",
    ...dataOverrides,
  };

  return render(
    <NoteNode
      {...({
        id: "note-1",
        data,
        selected,
        type: "note",
        isConnectable: true,
        positionAbsoluteX: 0,
        positionAbsoluteY: 0,
        zIndex: 0,
        dragging: false,
        deletable: true,
        selectable: true,
        width: 200,
        height: 150,
      } as any)}
    />,
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("NoteNode", () => {
  beforeEach(() => {
    mockUpdateNode.mockClear();
  });

  it("renders title and content", () => {
    renderNoteNode({ title: "Test Title", content: "Test body text" });
    expect(screen.getByText("Test Title")).toBeInTheDocument();
    expect(screen.getByText("Test body text")).toBeInTheDocument();
  });

  it("shows placeholder when content is empty", () => {
    renderNoteNode({ content: "" });
    expect(screen.getByText("Click to add notes...")).toBeInTheDocument();
  });

  it("shows placeholder when content is undefined", () => {
    renderNoteNode({ content: undefined });
    expect(screen.getByText("Click to add notes...")).toBeInTheDocument();
  });

  it("falls back to 'Note' when title is empty", () => {
    renderNoteNode({ title: "" });
    expect(screen.getByText("Note")).toBeInTheDocument();
  });

  it("enters editing mode on edit button click", () => {
    renderNoteNode();
    const editButton = screen.getByRole("button", { name: "Edit note" });
    fireEvent.click(editButton);
    // After clicking edit, a textarea should appear
    expect(screen.getByRole("textbox")).toBeInTheDocument();
  });

  it("saves on save button click", () => {
    renderNoteNode({ content: "original" });

    // Enter edit mode
    const editButton = screen.getByRole("button", { name: "Edit note" });
    fireEvent.click(editButton);

    // Modify the textarea
    const textarea = screen.getByRole("textbox");
    fireEvent.change(textarea, { target: { value: "updated content" } });

    // Click save button (the same button now shows "Save note")
    const saveButton = screen.getByRole("button", { name: "Save note" });
    fireEvent.click(saveButton);

    expect(mockUpdateNode).toHaveBeenCalledWith("note-1", { content: "updated content" });
  });

  it("saves on Ctrl+Enter", () => {
    renderNoteNode({ content: "before" });

    // Enter edit mode
    fireEvent.click(screen.getByRole("button", { name: "Edit note" }));

    const textarea = screen.getByRole("textbox");
    fireEvent.change(textarea, { target: { value: "ctrl-enter save" } });
    fireEvent.keyDown(textarea, { key: "Enter", ctrlKey: true });

    expect(mockUpdateNode).toHaveBeenCalledWith("note-1", { content: "ctrl-enter save" });
  });

  it("cancels on Escape without saving", () => {
    renderNoteNode({ content: "original" });

    // Enter edit mode
    fireEvent.click(screen.getByRole("button", { name: "Edit note" }));

    const textarea = screen.getByRole("textbox");
    fireEvent.change(textarea, { target: { value: "should be discarded" } });
    fireEvent.keyDown(textarea, { key: "Escape" });

    // Should not save the changed content
    expect(mockUpdateNode).not.toHaveBeenCalledWith(
      "note-1",
      expect.objectContaining({ content: "should be discarded" }),
    );

    // Should exit editing mode (textarea gone, content text back)
    expect(screen.queryByRole("textbox")).toBeNull();
    expect(screen.getByText("original")).toBeInTheDocument();
  });

  it("enters editing mode when clicking on content text", () => {
    renderNoteNode({ content: "click me" });
    const contentDiv = screen.getByText("click me");
    fireEvent.click(contentDiv);
    expect(screen.getByRole("textbox")).toBeInTheDocument();
  });
});
