// engine-session-scraper.ts
// ---------------------------------------------------------------------------
// DOM scrape fallback for undeployed Airtable automations.
// The internal API cannot return scripts for undeployed automations --
// they have no deploymentId. This module navigates to each automation's
// editor URL, waits for the canvas to render, and extracts the script
// body from the DOM using the same text extraction strategy as scraper.js.
//
// Only called for automations where:
//   - deployment_status === 'undeployed'
//   - the graph contains a watCUSTOMSCRIPT00 action
// ---------------------------------------------------------------------------

import type { Page } from 'playwright';

const STEP_DELAY_MS   = 1200;
const CANVAS_TIMEOUT  = 8000;

// ---------------------------------------------------------------------------
// Extract script body from the rendered automation canvas text.
// Airtable renders the script in the Properties panel with this structure:
//   "Script\nEdit code\n<script body>\nTEST STEP"
// We extract everything between the marker and the end sentinel.
// ---------------------------------------------------------------------------
function extractScriptFromCanvasText(raw: string): string | null {
  const MARKER = 'Script\nEdit code\n';
  let codeStart = raw.indexOf(MARKER);

  if (codeStart !== -1) {
    codeStart += MARKER.length;
  } else {
    // Fallback: just "Edit code\n"
    const alt = raw.indexOf('Edit code\n');
    if (alt === -1) return null;
    codeStart = alt + 'Edit code\n'.length;
  }

  const chunk = raw.slice(codeStart);

  // Find end of script at TEST STEP section or end of content
  let endIdx = chunk.length;
  for (const marker of ['\nTEST STEP', '\nTest step\n', '\nRESULTS\n', '\nTest action\n', '\nSave and run']) {
    const m = chunk.indexOf(marker);
    if (m !== -1 && m < endIdx) endIdx = m;
  }

  const code = chunk.slice(0, endIdx).trim();
  return code.length > 10 ? code : null;
}

// ---------------------------------------------------------------------------
// Scrape a single undeployed automation.
// Navigates to the automation editor, clicks the script step, reads the DOM.
// Returns the script body or null if not found.
// ---------------------------------------------------------------------------
export async function scrapeUndeployedScript(
  page: Page,
  appId: string,
  workflowId: string,
  workflowName: string,
): Promise<string | null> {
  const url = `https://airtable.com/${appId}/${workflowId}`;
  console.log(`[scraper] Navigating to undeployed automation: ${workflowName} (${workflowId})`);

  try {
    await page.goto(url, { waitUntil: 'networkidle', timeout: 30_000 });

    // Wait for canvas to render -- look for TRIGGER label or Add trigger text
    await page.waitForFunction(
      () => {
        const main = document.querySelector('main');
        if (!main) return false;
        const text = (main as HTMLElement).innerText || '';
        return text.includes('TRIGGER') || text.includes('Add trigger') || text.includes('ACTIONS');
      },
      { timeout: CANVAS_TIMEOUT },
    ).catch(() => null);

    await new Promise((r) => setTimeout(r, STEP_DELAY_MS));

    // Find and click the script step in the canvas.
    // Script steps show as "Run a script" or "Run script" action cards.
    const clicked = await page.evaluate(() => {
      const candidates = Array.from(document.querySelectorAll('button, [role="button"]'));
      const scriptBtn = candidates.find((el) => {
        const text = ((el as HTMLElement).innerText || '').toLowerCase();
        return text.includes('run a script') || text.includes('run script') || text.includes('custom script');
      }) as HTMLElement | undefined;

      if (scriptBtn) {
        scriptBtn.click();
        return true;
      }
      return false;
    });

    if (!clicked) {
      console.log(`[scraper] No script step button found for ${workflowName}, trying full text extraction`);
    } else {
      // Wait for Properties panel to open with script content
      await page.waitForFunction(
        () => {
          const text = document.body.innerText || '';
          return text.includes('Edit code') || text.includes('Script');
        },
        { timeout: 5000 },
      ).catch(() => null);

      await new Promise((r) => setTimeout(r, 800));
    }

    // Extract script from full page text
    const pageText = await page.evaluate(() => document.body.innerText || '');
    const script = extractScriptFromCanvasText(pageText);

    if (script) {
      console.log(`[scraper] Extracted script from ${workflowName}: ${script.split('\n').length} lines`);
    } else {
      console.log(`[scraper] No script extracted from ${workflowName}`);
    }

    return script;
  } catch (err: any) {
    console.error(`[scraper] Failed to scrape ${workflowName}: ${err.message}`);
    return null;
  }
}
