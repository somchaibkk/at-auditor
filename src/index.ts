// index.ts
// Worker entry point. Starts HTTP server + polls for queued audits.

import { RateLimiter }   from './rate-limiter.js';
import { PatEngine }     from './engine-pat.js';
import { SessionEngine } from './engine-session.js';
import { Store }         from './store.js';
import { startServer, setStatus, getStatus } from './worker-server.js';
import { runAnalysis }   from './analysis.js';
import { createClient }  from '@supabase/supabase-js';

const POLL_INTERVAL_MS = 10_000;
const SERVER_PORT      = 3456;

function loadBaseConfig() {
  const required = (name: string): string => {
    const v = process.env[name];
    if (!v) throw new Error(`Missing required env var: ${name}`);
    return v;
  };
  return {
    supabaseUrl:            required('SUPABASE_URL'),
    supabaseServiceRoleKey: required('SUPABASE_SERVICE_ROLE_KEY'),
    browserProfileDir:      required('BROWSER_PROFILE_DIR'),
    recordSampleSize:       Number(process.env.RECORD_SAMPLE_SIZE ?? 25),
    patRequestsPerSecond:   Number(process.env.PAT_RPS ?? 5),
  };
}

async function claimNextAudit(db: any): Promise<any | null> {
  const { data, error } = await db
    .schema('audit')
    .from('audits')
    .select('*')
    .eq('status', 'queued')
    .order('created_at', { ascending: true })
    .limit(1)
    .maybeSingle();

  if (error) { console.error('[worker] Query error:', error.message); return null; }
  if (!data)  return null;

  console.log(`[worker] Found queued audit: ${data.id} "${data.prospect_name}"`);

  const { error: claimErr } = await db
    .schema('audit')
    .from('audits')
    .update({ status: 'running', started_at: new Date().toISOString() })
    .eq('id', data.id)
    .eq('status', 'queued');

  if (claimErr) { console.error('[worker] Claim failed:', claimErr.message); return null; }
  return { ...data, status: 'running' };
}

async function fetchPat(db: any, vaultSecretId: string): Promise<string> {
  const { data, error } = await db.rpc('vault_read_secret', { secret_id: vaultSecretId });
  if (error || !data) throw new Error(`Failed to read PAT from vault: ${error?.message}`);
  return data as string;
}

async function runAudit(audit: any, baseConfig: ReturnType<typeof loadBaseConfig>) {
  const cfg = {
    supabaseUrl:            baseConfig.supabaseUrl,
    supabaseServiceRoleKey: baseConfig.supabaseServiceRoleKey,
    auditId:                audit.id,
    recordSampleSize:       audit.config?.record_sample_size ?? baseConfig.recordSampleSize,
    patRequestsPerSecond:   baseConfig.patRequestsPerSecond,
    enterpriseModule:       false, // deprecated: collaborator collection now uses session engine
  };

  const db    = createClient(baseConfig.supabaseUrl, baseConfig.supabaseServiceRoleKey, { auth: { persistSession: false } });
  const store = new Store(cfg);

  try {
    await store.event('discover', 'Worker started');
    if (!audit.vault_secret_id) throw new Error('No PAT stored for this audit');
    const pat = await fetchPat(db, audit.vault_secret_id);

    const limiter   = new RateLimiter(cfg.patRequestsPerSecond);
    const patEngine = new PatEngine(pat, limiter);
    const session   = new SessionEngine();

    const targets = await store.getTargetBases();
    await store.event('discover', `Collecting ${targets.length} base(s)`);

    // Start session headless -- login was done separately via /login endpoint
    await session.startHeadless(baseConfig.browserProfileDir);

    for (const { baseId, baseName } of targets) {
      try {
        await store.event('schema', `Schema: ${baseName ?? baseId}`);
        const { tables, tableCount, fieldCount } = await patEngine.getBaseSchema(baseId);

        // Collaborator collection: session-based scraper (works on all plans)
        let collaborators: any = null;
        if (audit.config?.collect_collaborators) {
          try {
            await store.event('collaborators', `Scraping collaborators for ${baseName ?? baseId}`);
            const collabResult = await session.scrapeCollaborators(baseId);
            if (collabResult.collaborators.length > 0) {
              collaborators = collabResult;
              await store.event('collaborators', `Found ${collabResult.collaborators.length} collaborator(s) in workspace ${collabResult.workspaceName || collabResult.workspaceId || 'unknown'}`);
            } else {
              await store.event('collaborators', collabResult.error || 'No collaborators found', 'warn');
            }

            // Re-navigate to base for subsequent steps (automations etc)
            // since collaborator scraping may have navigated away
          } catch (e: any) {
            await store.event('collaborators', `Collaborator scraping failed: ${e.message}`, 'warn');
          }
        }

        await store.saveSchema(baseId, tables, tableCount, fieldCount, collaborators);
        await store.upsertBaseStatus(baseId, 'schema_done');

        if (audit.config?.include_record_samples !== false) {
          await store.event('records', `Sampling up to ${cfg.recordSampleSize}/table across ${tableCount} table(s)`);
          for (const t of tables) {
            const { sample, sampledCount, hasMore } = await patEngine.sampleTable(baseId, t.id, cfg.recordSampleSize);
            await store.saveRecordSample(baseId, t.id, t.name, sample, sampledCount, hasMore);
          }
          await store.upsertBaseStatus(baseId, 'records_done');
        }

        if (audit.config?.include_automations !== false) {
          await store.event('automations', `Automations: ${baseName ?? baseId}`);
          const collected = await session.collectBase(baseId);
          await store.saveAutomations(baseId, collected.automations);
          const scriptCount = collected.automations.reduce((n, a) => n + a.scriptSources.length, 0);
          await store.event('automations', `Found ${collected.automations.length} automation(s), ${scriptCount} script(s)`);
          await store.upsertBaseStatus(baseId, 'automations_done');
        }

        await store.upsertBaseStatus(baseId, 'complete');
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        await store.event('schema', `Base ${baseId} failed: ${msg}`, 'error');
        await store.upsertBaseStatus(baseId, 'failed', msg);
      }
    }

    await session.stop();
    await store.setAuditStatus('analysing');
    await store.event('analyse', 'Running analysis...');

    await runAnalysis({
      supabaseUrl:            baseConfig.supabaseUrl,
      supabaseServiceRoleKey: baseConfig.supabaseServiceRoleKey,
      auditId:                audit.id,
    });

    await store.setAuditStatus('complete');
    await store.event('analyse', 'Analysis complete');
    console.log('[worker] Audit complete');
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.error('[worker] Audit failed:', msg);
    await store.event('discover', `Worker failed: ${msg}`, 'error');
    await store.setAuditStatus('failed', msg);
  }
}

async function main() {
  const baseConfig = loadBaseConfig();

  // DB connectivity check
  const db = createClient(baseConfig.supabaseUrl, baseConfig.supabaseServiceRoleKey, { auth: { persistSession: false } });
  const { error: dbErr } = await db.schema('audit').from('audits').select('id').limit(1);
  if (dbErr) { console.error('[worker] DB check failed:', dbErr.message); process.exit(1); }

  // Start HTTP server
  startServer(SERVER_PORT, baseConfig.browserProfileDir);
  console.log('[worker] Ready. Use the Login button in the UI, then Start Audit.');

  // Poll loop
  while (true) {
    const status = getStatus();

    if (status === 'logged_in') {
      const audit = await claimNextAudit(db);
      if (audit) {
        setStatus('busy');
        await runAudit(audit, baseConfig);
        setStatus('logged_in'); // keep logged_in so next audit can run without re-login
      }
    }

    await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
  }
}

main().catch((err) => {
  console.error('[worker] FATAL:', err);
  process.exit(1);
});
