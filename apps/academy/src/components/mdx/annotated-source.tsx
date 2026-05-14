'use client';

import * as React from 'react';
import { codeToHtml } from 'shiki';

export interface Annotation {
  /** 1-indexed line number within the extracted snippet */
  line: number;
  /** Short badge text (e.g., "1", "2", "A") */
  label: string;
  /** Expanded explanation text */
  explanation: string;
}

export interface AnnotatedSourceProps {
  /** Maps to extracted source JSON file name */
  tag: string;
  /** Annotations to overlay on the code */
  annotations: Annotation[];
  /** Optional title above the code block */
  title?: string;
}

interface ExtractedSource {
  tag: string;
  file: string;
  startLine: number;
  endLine: number;
  code: string;
  language: string;
  extractedAt: string;
}

export function AnnotatedSource({ tag, annotations, title }: AnnotatedSourceProps) {
  const [source, setSource] = React.useState<ExtractedSource | null>(null);
  const [highlighted, setHighlighted] = React.useState<string | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [expanded, setExpanded] = React.useState<Set<number>>(new Set());
  const containerRef = React.useRef<HTMLDivElement>(null);

  // Load extracted source JSON
  React.useEffect(() => {
    let cancelled = false;

    import(`@/data/extracted-sources/${tag}.json`)
      .then((mod: { default: ExtractedSource }) => {
        if (!cancelled) {
          setSource(mod.default);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setError(`Source not available: ${tag}`);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [tag]);

  // Highlight with Shiki once source is loaded
  React.useEffect(() => {
    if (!source) return;

    let cancelled = false;

    codeToHtml(source.code, {
      lang: source.language,
      themes: {
        dark: 'github-dark',
        light: 'github-light',
      },
      defaultColor: false,
      transformers: [
        {
          line(node, line) {
            node.properties['data-line'] = line;
          },
        },
      ],
    })
      .then((html) => {
        if (!cancelled) {
          setHighlighted(html);
        }
      })
      .catch(() => {
        // Fall back to unhighlighted display
      });

    return () => {
      cancelled = true;
    };
  }, [source]);

  // Mark annotated lines after highlighting renders
  React.useEffect(() => {
    if (!highlighted || !containerRef.current) return;

    const annotatedLines = new Set(annotations.map((a) => a.line));
    const lineElements = containerRef.current.querySelectorAll('[data-line]');

    lineElements.forEach((el) => {
      const lineNum = Number(el.getAttribute('data-line'));
      if (annotatedLines.has(lineNum)) {
        el.classList.add('annotated-line');
      }
    });
  }, [highlighted, annotations]);

  const toggleAnnotation = (line: number) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(line)) {
        next.delete(line);
      } else {
        next.add(line);
      }
      return next;
    });
  };

  if (error) {
    return (
      <div className="my-4 rounded-lg border border-destructive/50 bg-destructive/10 p-4 text-sm text-destructive">
        {error}
      </div>
    );
  }

  if (!source || !highlighted) {
    return (
      <div className="my-4 animate-pulse rounded-lg border bg-muted/50 p-4">
        <div className="h-4 w-48 rounded bg-muted" />
        <div className="mt-3 space-y-2">
          <div className="h-3 w-full rounded bg-muted" />
          <div className="h-3 w-3/4 rounded bg-muted" />
          <div className="h-3 w-5/6 rounded bg-muted" />
        </div>
      </div>
    );
  }

  // Build annotation map for quick lookup
  const annotationsByLine = new Map(annotations.map((a) => [a.line, a]));

  // Split the highlighted HTML into lines for interleaving explanations
  // We render the full Shiki output, then overlay badges and explanation panels
  return (
    <div className="annotated-source my-4">
      {title && (
        <div className="mb-1 text-sm font-medium text-foreground">
          {title}
        </div>
      )}
      <div className="mb-1 text-xs text-muted-foreground">
        from {source.file} (lines {source.startLine}-{source.endLine})
      </div>
      <div className="relative" ref={containerRef}>
        <div dangerouslySetInnerHTML={{ __html: highlighted }} />

        {/* Callout badges positioned at annotated lines */}
        {annotations.map((annotation) => (
          <AnnotationBadge
            key={annotation.line}
            annotation={annotation}
            isExpanded={expanded.has(annotation.line)}
            onToggle={() => toggleAnnotation(annotation.line)}
            containerRef={containerRef}
          />
        ))}

        {/* Expanded explanation panels */}
        {annotations
          .filter((a) => expanded.has(a.line))
          .map((annotation) => (
            <AnnotationPanel
              key={`panel-${annotation.line}`}
              annotation={annotation}
              containerRef={containerRef}
            />
          ))}
      </div>
    </div>
  );
}

function AnnotationBadge({
  annotation,
  isExpanded,
  onToggle,
  containerRef,
}: {
  annotation: Annotation;
  isExpanded: boolean;
  onToggle: () => void;
  containerRef: React.RefObject<HTMLDivElement | null>;
}) {
  const [position, setPosition] = React.useState<{ top: number; right: number } | null>(null);

  React.useEffect(() => {
    if (!containerRef.current) return;

    const lineEl = containerRef.current.querySelector(
      `[data-line="${annotation.line}"]`,
    );
    if (!lineEl) return;

    const containerRect = containerRef.current.getBoundingClientRect();
    const lineRect = lineEl.getBoundingClientRect();

    setPosition({
      top: lineRect.top - containerRect.top + (lineRect.height - 20) / 2,
      right: 8,
    });
  }, [annotation.line, containerRef]);

  if (!position) return null;

  return (
    <button
      type="button"
      onClick={onToggle}
      className={`absolute flex h-5 w-5 cursor-pointer items-center justify-center rounded-full text-xs font-medium transition-colors ${
        isExpanded
          ? 'bg-primary text-primary-foreground ring-2 ring-primary/30'
          : 'bg-primary/80 text-primary-foreground hover:bg-primary'
      }`}
      style={{ top: position.top, right: position.right }}
      aria-label={`Annotation ${annotation.label}: ${annotation.explanation}`}
    >
      {annotation.label}
    </button>
  );
}

function AnnotationPanel({
  annotation,
  containerRef,
}: {
  annotation: Annotation;
  containerRef: React.RefObject<HTMLDivElement | null>;
}) {
  const [top, setTop] = React.useState<number | null>(null);

  React.useEffect(() => {
    if (!containerRef.current) return;

    const lineEl = containerRef.current.querySelector(
      `[data-line="${annotation.line}"]`,
    );
    if (!lineEl) return;

    const containerRect = containerRef.current.getBoundingClientRect();
    const lineRect = lineEl.getBoundingClientRect();

    setTop(lineRect.bottom - containerRect.top);
  }, [annotation.line, containerRef]);

  if (top === null) return null;

  return (
    <div
      className="absolute left-0 right-0 border-l-2 border-primary bg-muted/80 px-4 py-2 text-sm"
      style={{ top }}
    >
      <span className="mr-2 inline-flex h-5 w-5 items-center justify-center rounded-full bg-primary text-xs font-medium text-primary-foreground">
        {annotation.label}
      </span>
      {annotation.explanation}
    </div>
  );
}
