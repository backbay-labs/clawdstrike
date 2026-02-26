import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

const fromHere = (relativePath: string): string =>
  fileURLToPath(new URL(relativePath, import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      '@clawdstrike/adapter-core': fromHere('./src/index.ts'),
      '@clawdstrike/claude': fromHere('../clawdstrike-claude/src/claude-adapter.ts'),
      '@clawdstrike/vercel-ai': fromHere('../clawdstrike-vercel-ai/src/vercel-ai-adapter.ts'),
    },
  },
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/cross-adapter/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
    },
  },
});
