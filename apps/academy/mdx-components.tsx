import type { MDXComponents } from 'mdx/types';
import { CodeBlock } from '@/components/mdx/code-block';
import { LessonNav } from '@/components/layout/lesson-nav';
import { GuardPlayground } from '@/components/playground/guard-playground-loader';
import { AnnotatedSource } from '@/components/mdx/annotated-source';
import { LessonCompleteButton } from '@/components/mdx/lesson-complete-button';
import { BypassChallenge } from '@/components/mdx/bypass-challenge';
import { PolicyEditorLoader } from '@/components/policy-lab/policy-editor-loader';
import { InheritanceTree } from '@/components/policy-lab/inheritance-tree';
import { RulesetComparison } from '@/components/policy-lab/ruleset-comparison';

export function useMDXComponents(components: MDXComponents): MDXComponents {
  return {
    ...components,
    pre: CodeBlock,
    LessonNav,
    GuardPlayground,
    AnnotatedSource,
    LessonCompleteButton,
    BypassChallenge,
    PolicyEditor: PolicyEditorLoader,
    InheritanceTree,
    RulesetComparison,
  };
}
