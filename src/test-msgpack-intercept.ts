/**
 * test-msgpack-intercept.ts
 * 
 * Run on docker01:
 *   cd /opt/at-auditor/repo
 *   npm install @msgpack/msgpack
 *   npx tsx src/test-msgpack-intercept.ts
 * 
 * What it does:
 *   1. Launches Playwright with the Phoebe Philo browser profile
 *   2. Navigates to a known base
 *   3. Intercepts the /application/{appId}/read msgpack response
 *   4. Decodes it and dumps the structure to /tmp/bootstrap-dump.json
 * 
 * Output: /tmp/bootstrap-dump.json (top-level keys + nested key samples)
 */

import { chromium } from 'playwright';
import { decode } from '@msgpack/msgpack';
import { writeFileSync } from 'fs';

const BASE_URL = 'https://airtable.com/appKPQcnqmc7fVxh9/tblWtnh4YznIPBcAo/viwn6bZY2LMqyneRW?blocks=hide';

// Adjust if needed: the client_id folder name for the Phoebe Philo profile
const PROFILE_DIR = process.env.BROWSER_PROFILE_DIR || '/data/browser-profiles';

// Recursively map the shape of an object (keys + types), sampling arrays
function mapShape(obj: unknown, depth = 0, maxDepth = 4): unknown {
  if (depth > maxDepth) return '...(truncated)';
  if (obj === null || obj === undefined) return obj;
  if (typeof obj !== 'object') return typeof obj;
  if (obj instanceof Uint8Array) return `Uint8Array(${obj.length})`;
  if (Array.isArray(obj)) {
    if (obj.length === 0) return '[]';
    // Sample first item only
    return [`Array(${obj.length}) first:`, mapShape(obj[0], depth + 1, maxDepth)];
  }
  const mapped: Record<string, unknown> = {};
  const keys = Object.keys(obj as Record<string, unknown>);
  for (const k of keys) {
    mapped[k] = mapShape((obj as Record<string, unknown>)[k], depth + 1, maxDepth);
  }
  return mapped;
}

// Also extract a full sample of one table's data to find sync config + row counts
function extractTableSample(decoded: Record<string, unknown>): unknown {
  // Look for tableSchemas, tableDatasById, or similar
  const candidates = ['tableDatasById', 'tableSchemas', 'table', 'tables', 'data'];
  for (const key of candidates) {
    if (key in decoded) {
      const val = decoded[key];
      if (val && typeof val === 'object' && !Array.isArray(val)) {
        const innerKeys = Object.keys(val as Record<string, unknown>);
        if (innerKeys.length > 0) {
          // Return first table entry fully (up to depth 5)
          const firstKey = innerKeys[0];
          return {
            _foundAt: key,
            _totalEntries: innerKeys.length,
            _sampleKey: firstKey,
            _sample: mapShape((val as Record<string, unknown>)[firstKey], 0, 5),
          };
        }
      }
    }
  }
  return { _note: 'No known table container found at top level' };
}

// Search recursively for keys that look sync-related
function findSyncKeys(obj: unknown, path = '', results: string[] = [], depth = 0): string[] {
  if (depth > 6 || !obj || typeof obj !== 'object') return results;
  if (obj instanceof Uint8Array) return results;
  if (Array.isArray(obj)) {
    if (obj.length > 0) findSyncKeys(obj[0], `${path}[0]`, results, depth + 1);
    return results;
  }
  for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
    const fullPath = path ? `${path}.${k}` : k;
    const lower = k.toLowerCase();
    if (lower.includes('sync') || lower.includes('rowcount') || lower.includes('numrecord') ||
        lower.includes('record_count') || lower.includes('numrow') || lower.includes('externalSync') ||
        lower.includes('sourcetable') || lower.includes('syncsource')) {
      results.push(`${fullPath} = ${JSON.stringify(v)?.slice(0, 300)}`);
    }
    if (v && typeof v === 'object') {
      findSyncKeys(v, fullPath, results, depth + 1);
    }
  }
  return results;
}

async function main() {
  console.log('Launching browser...');
  
  // Find the right profile directory
  const fs = await import('fs');
  let profilePath = PROFILE_DIR;
  
  // If PROFILE_DIR points to the profiles root, find the first (or only) client folder
  if (fs.existsSync(PROFILE_DIR)) {
    const entries = fs.readdirSync(PROFILE_DIR);
    const subdirs = entries.filter(e => fs.statSync(`${PROFILE_DIR}/${e}`).isDirectory());
    if (subdirs.length > 0 && !fs.existsSync(`${PROFILE_DIR}/Default`)) {
      // It's the parent dir with client folders; pick the first one
      profilePath = `${PROFILE_DIR}/${subdirs[0]}`;
      console.log(`Using profile: ${profilePath}`);
    }
  }

  const browser = await chromium.launchPersistentContext(profilePath, {
    headless: false,
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
    viewport: { width: 1280, height: 800 },
  });

  const page = browser.pages()[0] || await browser.newPage();

  let intercepted = false;
  const output: Record<string, unknown> = {};

  // Intercept the msgpack response
  await page.route('**/v0.3/application/*/read**', async (route) => {
    console.log('Intercepted read request, fetching response...');
    const response = await route.fetch();
    const body = await response.body();
    console.log(`Response body: ${body.length} bytes, content-type: ${response.headers()['content-type']}`);

    try {
      const decoded = decode(body) as Record<string, unknown>;
      console.log('Msgpack decoded successfully');
      
      // 1. Top-level shape
      output.topLevelKeys = Object.keys(decoded);
      output.shape = mapShape(decoded, 0, 3);
      
      // 2. Table sample
      output.tableSample = extractTableSample(decoded);
      
      // 3. Sync-related keys anywhere in the tree
      output.syncRelatedPaths = findSyncKeys(decoded);
      
      // 4. Raw top-level key sizes (to understand the payload)
      const keySizes: Record<string, string> = {};
      for (const [k, v] of Object.entries(decoded)) {
        if (v && typeof v === 'object' && !Array.isArray(v)) {
          keySizes[k] = `object with ${Object.keys(v as object).length} keys`;
        } else if (Array.isArray(v)) {
          keySizes[k] = `array with ${v.length} items`;
        } else {
          keySizes[k] = `${typeof v}: ${JSON.stringify(v)?.slice(0, 100)}`;
        }
      }
      output.keySizes = keySizes;

      intercepted = true;
    } catch (err) {
      console.error('Msgpack decode failed:', err);
      output.error = String(err);
      output.rawBytesHex = body.slice(0, 200).toString('hex');
      intercepted = true;
    }

    // Continue the route so the page loads normally
    await route.fulfill({
      status: response.status(),
      headers: response.headers(),
      body: body,
    });
  });

  console.log(`Navigating to ${BASE_URL}...`);
  await page.goto(BASE_URL, { waitUntil: 'networkidle', timeout: 60000 });

  // Wait a bit for the intercept
  if (!intercepted) {
    console.log('Waiting for read request...');
    await page.waitForTimeout(10000);
  }

  if (!intercepted) {
    console.log('WARNING: No /application/*/read request intercepted. The base may have been cached.');
    console.log('Try: open a DIFFERENT base first, then navigate to this one.');
    output.warning = 'No read request captured. Page may have loaded from cache or realtime socket.';
  }

  // Write output
  const outPath = '/tmp/bootstrap-dump.json';
  writeFileSync(outPath, JSON.stringify(output, null, 2));
  console.log(`\nDump written to ${outPath}`);
  console.log(`Top-level keys: ${output.topLevelKeys}`);
  console.log(`Sync-related paths found: ${(output.syncRelatedPaths as string[])?.length || 0}`);

  await browser.close();
  console.log('Done.');
}

main().catch(err => {
  console.error('Fatal:', err);
  process.exit(1);
});
