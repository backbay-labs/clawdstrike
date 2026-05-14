'use client';

import { useState } from 'react';
import CodeMirror from '@uiw/react-codemirror';
import { yaml } from '@codemirror/lang-yaml';
import { oneDark } from '@codemirror/theme-one-dark';
import { lintGutter } from '@codemirror/lint';
import { useTheme } from 'next-themes';
import { policyLinter } from '@/lib/policy-linter';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';

const DEFAULT_POLICY = `version: "1.5.0"
name: My Custom Policy
description: A custom security policy

guards:
  forbidden_path:
    patterns:
      - "**/.ssh/**"
      - "**/.aws/**"
      - "**/.env"
  egress_allowlist:
    allow:
      - "*.openai.com"
      - "api.github.com"
    default_action: block
`;

export interface PolicyEditorProps {
  defaultValue?: string;
  onChange?: (value: string) => void;
  height?: string;
  readOnly?: boolean;
}

export default function PolicyEditor({
  defaultValue,
  onChange,
  height = '400px',
  readOnly = false,
}: PolicyEditorProps) {
  const [value, setValue] = useState(defaultValue ?? DEFAULT_POLICY);
  const { resolvedTheme } = useTheme();

  const handleChange = (newValue: string) => {
    setValue(newValue);
    onChange?.(newValue);
  };

  return (
    <Card className="my-6">
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-lg">Policy Editor</CardTitle>
        <Badge variant="outline" className="text-xs font-mono">
          v1.5.0
        </Badge>
      </CardHeader>
      <CardContent>
        <div className="overflow-hidden rounded-md border">
          <CodeMirror
            value={value}
            onChange={handleChange}
            extensions={[yaml(), policyLinter, lintGutter()]}
            theme={resolvedTheme === 'dark' ? oneDark : undefined}
            height={height}
            readOnly={readOnly}
            basicSetup={{ lineNumbers: true, foldGutter: true }}
          />
        </div>
      </CardContent>
    </Card>
  );
}
