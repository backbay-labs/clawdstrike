import React, { useState } from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { SwarmBoardNodeData } from "@/lib/workbench/swarm-board-types";

// ---------------------------------------------------------------------------
// Stub component exercising the note node contract.
// Replace with real component import when available.
// ---------------------------------------------------------------------------

function NoteNode({
  data,
  onContentChange,
}: {
  data: SwarmBoardNodeData;
  onContentChange?: (content: string) => void;
}) {
  const [content, setContent] = useState(data.content ?? "");

  const handleBlur = () => {
    onContentChange?.(content);
  };

  const handleChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setContent(e.target.value);
  };

  return (
    <div data-testid="note-node">
      <h3 data-testid="node-title">{data.title}</h3>
      <textarea
        data-testid="note-textarea"
        value={content}
        onChange={handleChange}
        onBlur={handleBlur}
        placeholder="Add a note..."
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("NoteNode", () => {
  it("renders an editable text area", () => {
    render(
      <NoteNode
        data={{
          title: "Notes",
          status: "idle",
          nodeType: "note",
          content: "Initial content",
        }}
      />,
    );

    const textarea = screen.getByTestId("note-textarea") as HTMLTextAreaElement;
    expect(textarea.tagName).toBe("TEXTAREA");
    expect(textarea.value).toBe("Initial content");
  });

  it("content is preserved on blur", async () => {
    const onContentChange = vi.fn();
    const user = userEvent.setup();

    render(
      <NoteNode
        data={{
          title: "Notes",
          status: "idle",
          nodeType: "note",
          content: "Original",
        }}
        onContentChange={onContentChange}
      />,
    );

    const textarea = screen.getByTestId("note-textarea") as HTMLTextAreaElement;

    await user.clear(textarea);
    await user.type(textarea, "Updated content");

    // Trigger blur
    await user.tab();

    expect(onContentChange).toHaveBeenCalledWith("Updated content");
  });

  it("renders with empty content when content is undefined", () => {
    render(
      <NoteNode
        data={{
          title: "Empty Note",
          status: "idle",
          nodeType: "note",
        }}
      />,
    );

    const textarea = screen.getByTestId("note-textarea") as HTMLTextAreaElement;
    expect(textarea.value).toBe("");
  });

  it("renders with empty string content", () => {
    render(
      <NoteNode
        data={{
          title: "Blank Note",
          status: "idle",
          nodeType: "note",
          content: "",
        }}
      />,
    );

    const textarea = screen.getByTestId("note-textarea") as HTMLTextAreaElement;
    expect(textarea.value).toBe("");
  });

  it("shows placeholder text", () => {
    render(
      <NoteNode
        data={{
          title: "Note",
          status: "idle",
          nodeType: "note",
        }}
      />,
    );

    const textarea = screen.getByTestId("note-textarea");
    expect(textarea.getAttribute("placeholder")).toBe("Add a note...");
  });

  it("renders node title", () => {
    render(
      <NoteNode
        data={{
          title: "My Custom Note",
          status: "idle",
          nodeType: "note",
          content: "some text",
        }}
      />,
    );

    expect(screen.getByTestId("node-title").textContent).toBe("My Custom Note");
  });

  it("allows typing multiline content", async () => {
    const user = userEvent.setup();

    render(
      <NoteNode
        data={{
          title: "Multiline",
          status: "idle",
          nodeType: "note",
          content: "",
        }}
      />,
    );

    const textarea = screen.getByTestId("note-textarea") as HTMLTextAreaElement;
    await user.type(textarea, "Line 1{enter}Line 2{enter}Line 3");

    expect(textarea.value).toContain("Line 1");
    expect(textarea.value).toContain("Line 2");
    expect(textarea.value).toContain("Line 3");
  });

  it("preserves content across multiple edits without blur", async () => {
    const user = userEvent.setup();
    const onContentChange = vi.fn();

    render(
      <NoteNode
        data={{
          title: "Multi-edit",
          status: "idle",
          nodeType: "note",
          content: "Start",
        }}
        onContentChange={onContentChange}
      />,
    );

    const textarea = screen.getByTestId("note-textarea") as HTMLTextAreaElement;

    await user.clear(textarea);
    await user.type(textarea, "Edit 1");
    expect(textarea.value).toBe("Edit 1");

    // No blur yet, so onContentChange should not have been called
    expect(onContentChange).not.toHaveBeenCalled();

    await user.clear(textarea);
    await user.type(textarea, "Edit 2");
    expect(textarea.value).toBe("Edit 2");

    // Blur to commit
    await user.tab();
    expect(onContentChange).toHaveBeenCalledWith("Edit 2");
    expect(onContentChange).toHaveBeenCalledTimes(1);
  });
});
