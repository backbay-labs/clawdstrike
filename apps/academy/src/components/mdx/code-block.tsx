'use client';

import * as React from 'react';
import { useTheme } from 'next-themes';
import { codeToHtml } from 'shiki';
import { CopyButton } from './copy-button';

/**
 * Unwrap an RSC lazy element: { _payload: { status, value } } -> value,
 * or return the node as-is for standard React elements.
 */
function unwrapRsc(node: unknown): unknown {
  if (node && typeof node === 'object' && '_payload' in (node as Record<string, unknown>)) {
    const payload = (node as { _payload: { status: string; value: unknown } })._payload;
    if (payload.status === 'fulfilled') return payload.value;
  }
  return node;
}

/** Extract the props bag from either a standard React element or an RSC lazy element. */
function getProps(node: unknown): Record<string, unknown> | null {
  const unwrapped = unwrapRsc(node);
  if (unwrapped && typeof unwrapped === 'object' && 'props' in (unwrapped as Record<string, unknown>)) {
    return (unwrapped as { props: Record<string, unknown> }).props;
  }
  if (React.isValidElement(node) && node.props) {
    return node.props as Record<string, unknown>;
  }
  return null;
}

function extractText(children: React.ReactNode): string {
  if (typeof children === 'string') return children;
  if (Array.isArray(children)) return children.map(extractText).join('');
  const props = getProps(children);
  if (props) {
    return extractText(props.children as React.ReactNode);
  }
  return '';
}

function extractLanguage(children: React.ReactNode): string {
  const props = getProps(children);
  if (props) {
    const className = (props.className as string) ?? '';
    const match = className.match(/language-(\w+)/);
    if (match) return match[1];
  }
  return 'text';
}

/** Resolve the effective theme, falling back to system preference. */
function useResolvedTheme(): 'light' | 'dark' {
  const { resolvedTheme } = useTheme();
  return resolvedTheme === 'dark' ? 'dark' : 'light';
}

export function CodeBlock(props: React.HTMLAttributes<HTMLPreElement>) {
  const { children, ...rest } = props;
  const [highlighted, setHighlighted] = React.useState<string | null>(null);
  const code = extractText(children);
  const language = extractLanguage(children);
  const theme = useResolvedTheme();

  React.useEffect(() => {
    let cancelled = false;
    codeToHtml(code.trim(), {
      lang: language,
      theme: theme === 'dark' ? 'github-dark' : 'github-light',
    }).then((html) => {
      if (!cancelled) setHighlighted(html);
    }).catch(() => {
      // Fall back to unstyled code
    });
    return () => { cancelled = true; };
  }, [code, language, theme]);

  return (
    <div className="relative group my-4">
      {highlighted ? (
        <div dangerouslySetInnerHTML={{ __html: highlighted }} />
      ) : (
        <pre
          {...rest}
          className="overflow-x-auto rounded-lg border bg-muted/50 p-4 text-sm font-mono"
        >
          {children}
        </pre>
      )}
      <CopyButton text={code.trim()} />
    </div>
  );
}
