/**
 * Postbuild script: indexes all MDX lesson content via Pagefind Node.js API
 * and writes the search index to public/pagefind/.
 *
 * Runs automatically after `next build` via the "postbuild" script.
 */
import * as pagefind from 'pagefind';
import fs from 'node:fs';
import path from 'node:path';

const TRACKS_DIR = path.resolve(process.cwd(), 'src/app/tracks');

/** Strip MDX component tags and fenced code blocks from content. */
function stripMdxComponents(content: string): string {
  // Remove fenced code blocks (```...```)
  let stripped = content.replace(/```[\s\S]*?```/g, '');
  // Remove self-closing component tags: <Component ... />
  stripped = stripped.replace(/<[A-Z][A-Za-z]*\b[^>]*\/>/g, '');
  // Remove opening/closing component tags and their content: <Component>...</Component>
  stripped = stripped.replace(/<[A-Z][A-Za-z]*\b[^>]*>[\s\S]*?<\/[A-Z][A-Za-z]*>/g, '');
  // Remove remaining opening/closing tags (non-self-closing components without content between)
  stripped = stripped.replace(/<\/?[A-Z][A-Za-z]*\b[^>]*>/g, '');
  return stripped.trim();
}

/** Extract guard names from the guard gallery page.tsx as searchable text. */
function extractGuardNames(source: string): string {
  const nameMatches = source.match(/name:\s*'([^']+)'/g);
  if (!nameMatches) return '';
  return nameMatches
    .map((m) => {
      const match = m.match(/name:\s*'([^']+)'/);
      return match ? match[1] : '';
    })
    .filter(Boolean)
    .join(', ');
}

async function buildIndex() {
  const { index } = await pagefind.createIndex({});
  if (!index) {
    throw new Error('Failed to create Pagefind index');
  }

  let pageCount = 0;

  // Index MDX lessons across all tracks
  if (fs.existsSync(TRACKS_DIR)) {
    const trackDirs = fs.readdirSync(TRACKS_DIR, { withFileTypes: true })
      .filter((entry) => entry.isDirectory());

    for (const trackDir of trackDirs) {
      const trackSlug = trackDir.name;
      const trackPath = path.join(TRACKS_DIR, trackSlug);

      const lessonDirs = fs.readdirSync(trackPath, { withFileTypes: true })
        .filter((entry) => entry.isDirectory());

      for (const lessonDir of lessonDirs) {
        const mdxPath = path.join(trackPath, lessonDir.name, 'page.mdx');
        if (!fs.existsSync(mdxPath)) continue;

        const raw = fs.readFileSync(mdxPath, 'utf8');
        // Parse exported metadata object literal
        const metaMatch = raw.match(
          /export\s+const\s+metadata\s*=\s*(\{[\s\S]*?\n\})/,
        );
        let title = lessonDir.name;
        if (metaMatch) {
          try {
            // eslint-disable-next-line no-new-func
            const parsed = new Function(`return (${metaMatch[1]});`)() as { title?: string };
            if (parsed.title) title = parsed.title;
          } catch { /* use fallback title */ }
        }
        // Content is everything after the export const metadata block
        const content = raw.replace(
          /export\s+const\s+metadata\s*=\s*\{[\s\S]*?\n\}\s*/,
          '',
        );
        const textContent = stripMdxComponents(content);

        await index.addCustomRecord({
          url: `/tracks/${trackSlug}/${lessonDir.name}`,
          content: textContent,
          language: 'en',
          meta: { title },
        });
        pageCount++;
      }

      // Index guard gallery index page if it exists
      const galleryPagePath = path.join(trackPath, 'page.tsx');
      if (fs.existsSync(galleryPagePath)) {
        const source = fs.readFileSync(galleryPagePath, 'utf8');
        const guardNames = extractGuardNames(source);
        if (guardNames) {
          await index.addCustomRecord({
            url: `/tracks/${trackSlug}`,
            content: `Guard Gallery: ${guardNames}`,
            language: 'en',
            meta: {
              title: `${trackSlug.split('-').map((w) => w.charAt(0).toUpperCase() + w.slice(1)).join(' ')} Index`,
            },
          });
          pageCount++;
        }
      }
    }
  }

  await index.writeFiles({ outputPath: './public/pagefind' });
  await pagefind.close();

  console.log(`[build-search-index] Indexed ${pageCount} pages`);
}

buildIndex();
