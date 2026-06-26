// worker-server.ts
// ---------------------------------------------------------------------------
// Tiny HTTP server that runs alongside the worker.
// Exposes two endpoints for the UI to call via the worker-proxy Edge Function:
//   POST /login  -- opens Chromium headful, waits for login, saves profile
//   GET  /status -- returns current worker status
//   POST /ping   -- health check
// ---------------------------------------------------------------------------

import { createServer, type IncomingMessage, type ServerResponse } from 'http';
import { chromium } from 'playwright';

export type WorkerStatus = 'idle' | 'logged_in' | 'busy';

let _status: WorkerStatus = 'idle';
let _profileDir: string = '';

export function setStatus(s: WorkerStatus) { _status = s; }
export function getStatus(): WorkerStatus  { return _status; }
export function setProfileDir(dir: string) { _profileDir = dir; }

function json(res: ServerResponse, status: number, body: unknown) {
  const data = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type':                'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers':'Content-Type, Authorization',
  });
  res.end(data);
}

async function handleLogin(res: ServerResponse) {
  if (_status === 'busy') {
    return json(res, 409, { error: 'Worker is busy running an audit' });
  }

  console.log('[server] Opening browser for login...');
  _status = 'busy';

  try {
    const context = await chromium.launchPersistentContext(_profileDir, { headless: false });
    const page = await context.newPage();
    await page.goto('https://airtable.com/login', { waitUntil: 'domcontentloaded' });

    console.log('[server] Waiting for login (up to 5 min)...');
    const deadline = Date.now() + 5 * 60 * 1000;

    while (Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 2000));
      try {
        const url = page.url();
        if (url.includes('airtable.com') && !url.includes('/login') && !url.includes('/signup')) {
          await page.waitForLoadState('networkidle').catch(() => {});
          if (!page.url().includes('/login')) {
            console.log('[server] Login confirmed.');
            break;
          }
        }
      } catch (_) {}
    }

    await context.close();
    _status = 'logged_in';
    console.log('[server] Browser closed. Status: logged_in');
    json(res, 200, { ok: true, status: 'logged_in' });
  } catch (e: any) {
    _status = 'idle';
    json(res, 500, { error: e.message });
  }
}

export function startServer(port: number, profileDir: string) {
  _profileDir = profileDir;

  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    // CORS preflight
    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        'Access-Control-Allow-Origin':  '*',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      });
      res.end();
      return;
    }

    const url = req.url ?? '/';

    if (req.method === 'GET' && url === '/status') {
      return json(res, 200, { status: _status });
    }

    if (req.method === 'POST' && url === '/ping') {
      return json(res, 200, { ok: true });
    }

    if (req.method === 'POST' && url === '/login') {
      handleLogin(res);
      return;
    }

    json(res, 404, { error: 'Not found' });
  });

  server.listen(port, '0.0.0.0', () => {
    console.log(`[server] Worker HTTP server listening on http://0.0.0.0:${port}`);
  });

  return server;
}
