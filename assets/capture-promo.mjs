import { chromium } from 'playwright';
import { execSync } from 'child_process';
import { mkdirSync, existsSync, rmSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const framesDir = join(__dirname, 'frames');
const outputGif = join(__dirname, 'promo-reel.gif');

if (existsSync(framesDir)) rmSync(framesDir, { recursive: true });
mkdirSync(framesDir, { recursive: true });

const BASE = 'http://localhost:1421/#';
const WIDTH = 1280;
const HEIGHT = 720;

/** Click first button matching text via DOM evaluate */
async function clickButton(page, textMatch, label) {
  const result = await page.evaluate((text) => {
    const btns = Array.from(document.querySelectorAll('button'));
    for (const btn of btns) {
      if (btn.textContent?.includes(text)) {
        btn.click();
        return `Clicked: ${btn.textContent.trim().slice(0, 60)}`;
      }
    }
    return null;
  }, textMatch);
  if (result) console.log(`  ✓ ${label}: ${result}`);
  else console.log(`  ✗ ${label}: not found`);
  return !!result;
}

async function main() {
  console.log('Launching browser...');
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: { width: WIDTH, height: HEIGHT },
    deviceScaleFactor: 2,
    colorScheme: 'dark',
  });
  const page = await context.newPage();

  // ── Step 1: Load "strict" from Library ──
  console.log('Loading app → Library...');
  await page.goto(`${BASE}/library`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(2000);

  const loadResult = await page.evaluate(() => {
    const headings = Array.from(document.querySelectorAll('h3'));
    for (const h of headings) {
      if (h.textContent?.trim().toLowerCase() === 'strict') {
        let el = h.parentElement;
        for (let i = 0; i < 10 && el; i++) {
          const btns = el.querySelectorAll('button');
          for (const btn of btns) {
            if (btn.textContent?.trim().includes('Load')) {
              btn.click();
              return 'Loaded "Strict"';
            }
          }
          el = el.parentElement;
        }
      }
    }
    return 'Not found';
  });
  console.log(`  ${loadResult}`);
  await page.waitForTimeout(1500);

  // ── Step 2: Threat Lab — select scenario + execute ──
  console.log('Navigating to Threat Lab...');
  await page.goto(`${BASE}/simulator`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(1500);

  // Select the SSH Key scenario
  await clickButton(page, 'SSH Key', 'Select scenario');
  await page.waitForTimeout(500);

  // Scroll down to find Execute Probe button (it may be below fold)
  await page.evaluate(() => {
    const main = document.querySelector('main') || document.querySelector('[class*="flex-1"]');
    if (main) main.scrollTop = main.scrollHeight;
    // Also try scrolling any scrollable container
    document.querySelectorAll('[class*="overflow"]').forEach(el => {
      el.scrollTop = el.scrollHeight;
    });
  });
  await page.waitForTimeout(500);

  // Execute Probe on the selected scenario
  await clickButton(page, 'Execute Probe', 'Execute Probe');
  await page.waitForTimeout(3000);

  // Execute All
  await clickButton(page, 'Execute All', 'Execute All');
  await page.waitForTimeout(5000);

  // Re-select SSH Key to show its results
  await clickButton(page, 'SSH Key', 'Re-select scenario');
  await page.waitForTimeout(1000);

  // ── Step 3: Generate test receipts ──
  console.log('Generating test receipts...');
  await page.goto(`${BASE}/receipts`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(1000);

  // Click "Generate Test" several times to populate
  for (let i = 0; i < 4; i++) {
    await clickButton(page, 'Generate Test', `Generate receipt ${i + 1}`);
    await page.waitForTimeout(600);
  }

  // ── Step 4: Capture scenes ──
  const SCENES = [
    { path: '/home',       label: 'Dashboard',      holdFrames: 35 },
    { path: '/editor',     label: 'Editor',         holdFrames: 40 },
    { path: '/simulator',  label: 'Threat Lab',     holdFrames: 40, setup: 'scenarios' },
    { path: null,          label: 'Threat Matrix',   holdFrames: 35, setup: 'matrix' },
    { path: '/compliance', label: 'Compliance',     holdFrames: 35 },
    { path: '/approvals',  label: 'Approvals',      holdFrames: 30 },
    { path: '/receipts',   label: 'Receipts',       holdFrames: 30 },
  ];

  let frameIndex = 0;

  for (const scene of SCENES) {
    console.log(`Capturing: ${scene.label}`);

    if (scene.path) {
      await page.goto(`${BASE}${scene.path}`, { waitUntil: 'networkidle' });
      await page.waitForTimeout(1500);
    }

    if (scene.setup === 'scenarios') {
      await clickButton(page, 'SSH Key', 'Select SSH Key');
      await page.waitForTimeout(500);
    } else if (scene.setup === 'matrix') {
      await page.evaluate(() => {
        // Click Threat Matrix tab
        const btns = Array.from(document.querySelectorAll('button'));
        for (const btn of btns) {
          if (btn.textContent?.trim() === 'Threat Matrix' ||
              (btn.textContent?.includes('Threat') && btn.textContent?.includes('Matrix'))) {
            btn.click();
            break;
          }
        }
      });
      await page.waitForTimeout(1000);
    }

    const framePath = join(framesDir, `frame-${String(frameIndex).padStart(4, '0')}.png`);
    await page.screenshot({ path: framePath, type: 'png' });

    for (let i = 1; i < scene.holdFrames; i++) {
      execSync(`cp "${framePath}" "${join(framesDir, `frame-${String(frameIndex + i).padStart(4, '0')}.png`)}"`);
    }
    frameIndex += scene.holdFrames;
  }

  await browser.close();
  console.log(`\nCaptured ${frameIndex} frames.`);

  // ── Assemble GIF ──
  console.log('Assembling GIF...');
  try {
    execSync([
      'ffmpeg', '-y', '-framerate', '15',
      '-i', `"${join(framesDir, 'frame-%04d.png')}"`,
      '-vf', '"fps=15,scale=960:-1:flags=lanczos,split[s0][s1];[s0]palettegen=max_colors=128:stats_mode=diff[p];[s1][p]paletteuse=dither=bayer:bayer_scale=3"',
      '-loop', '0', `"${outputGif}"`,
    ].join(' '), { stdio: 'inherit' });
  } catch {
    execSync([
      'ffmpeg', '-y', '-framerate', '15',
      '-i', `"${join(framesDir, 'frame-%04d.png')}"`,
      '-vf', '"fps=15,scale=960:-1"', '-loop', '0', `"${outputGif}"`,
    ].join(' '), { stdio: 'inherit' });
  }

  console.log(`\n✓ Done: ${execSync(`ls -lh "${outputGif}"`).toString().trim()}`);
}

main().catch(err => { console.error(err); process.exit(1); });
