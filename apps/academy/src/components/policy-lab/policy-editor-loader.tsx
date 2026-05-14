'use client';

import dynamic from 'next/dynamic';
import type { PolicyEditorProps } from './policy-editor';

const PolicyEditorDynamic = dynamic(() => import('./policy-editor'), {
  ssr: false,
  loading: () => (
    <div className="h-64 animate-pulse bg-muted rounded-lg my-6" />
  ),
});

export function PolicyEditorLoader(props: PolicyEditorProps) {
  return <PolicyEditorDynamic {...props} />;
}
