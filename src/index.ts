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

async function notifyAuditComplete(baseConfig: ReturnType<typeof loadBaseConfig>, auditId: string) {
  try {
    const url = `${baseConfig.supabaseUrl}/functions/v1/audit-notify`;
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${baseConfig.supabaseServiceRoleKey}`,
      },
      body: JSON.stringify({ audit_id: auditId }),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) {
      console.error('[worker] audit-notify failed:', res.status, body);
    } else {
      console.log('[worker] audit-notify:', JSON.stringify(body));
    }
  } catch (e) {
    console.error('[worker] audit-notify error:', e instanceof Error ? e.message : e);
  }
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

    // Resolve PAT: audit-level first, then client-level fallback
    let vaultSecretId = audit.vault_secret_id;
    if (!vaultSecretId && audit.client_id) {
      const { data: clientData } = await db
        .from('clients')
        .select('vault_secret_id')
        .eq('id', audit.client_id)
        .single();
      vaultSecretId = clientData?.vault_secret_id ?? null;
    }
    if (!vaultSecretId) throw new Error('No PAT stored for this audit or its client');
    const pat = await fetchPat(db, vaultSecretId);

    const limiter   = new RateLimiter(cfg.patRequestsPerSecond);
    const patEngine = new PatEngine(pat, limiter);
    const session   = new SessionEngine();

    const targets = await store.getTargetBases();
    await store.event('discover', `Collecting ${targets.length} base(s)`);

    // Start session headless -- login was done separately via /login endpoint
    await session.startHeadless(baseConfig.browserProfileDir);

    // --- Environment data collection (once per audit, not per base) ---
    const wantEnv        = audit.config?.collect_environment !== false && audit.config?.collect_collaborators;
    const wantEnterprise = audit.config?.collect_enterprise === true;
    const wantAutoStats  = audit.config?.collect_auto_stats !== false && audit.config?.collect_collaborators;

    if (wantEnv || wantEnterprise) {
      try {
        const firstBase = targets[0];
        if (firstBase) {
          await store.event('environment', 'Collecting environment data...');
          const envData = await session.collectEnvironment(firstBase.baseId, { enterprise: wantEnterprise });

          const envErrors = (envData.errors as string[]) || [];
          const entErrors = (envData.enterprise?.errors as string[]) || [];
          const allErrors = [...envErrors, ...entErrors].filter(Boolean);

          if (envData.workspace) {
            await store.event('environment', `Workspace: ${envData.workspace.workspaceName || 'unknown'}, Plan: ${envData.workspace.billingPlan?.name || 'unknown'}`);
          }
          if (envData.enterprise?.users) {
            await store.event('environment', `Enterprise: ${envData.enterprise.users.length} user(s)`);
          }
          if (envData.usageStats) {
            await store.event('environment', `Usage: ${envData.usageStats.numWorkflowExecutions || 0} workflow executions this month`);
          }
          if (allErrors.length > 0) {
            await store.event('environment', `Warnings: ${allErrors.join('; ')}`, 'warn');
          }

          await store.saveEnvironmentData(envData);
          await store.event('environment', 'Environment data saved');
        }
      } catch (e: any) {
        await store.event('environment', `Environment collection failed: ${e.message}`, 'warn');
      }
    }

    let baseIndex = 0;
    const RESTART_EVERY = 15; // Restart browser every N bases to prevent memory exhaustion

    for (const { baseId, baseName } of targets) {
      // Periodic browser restart to prevent Chromium memory crashes
      if (baseIndex > 0 && baseIndex % RESTART_EVERY === 0 && (audit.config?.collect_collaborators || wantEnv)) {
        try {
          await store.event('browser', `Restarting browser after ${baseIndex} bases to free memory`);
          await session.restartBrowser(baseConfig.browserProfileDir);
        } catch (e: any) {
          await store.event('browser', `Browser restart failed: ${e.message}`, 'warn');
        }
      }
      baseIndex++;

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
          const keepCellValues = audit.config?.include_cell_values === true;
          await store.event('records', `Sampling up to ${cfg.recordSampleSize}/table across ${tableCount} table(s)${keepCellValues ? ' (with cell values)' : ' (metadata only)'}`);
          for (const t of tables) {
            const { sample, sampledCount, hasMore } = await patEngine.sampleTable(baseId, t.id, cfg.recordSampleSize);
            const storedSample = keepCellValues
              ? sample
              : sample.map((r: any) => ({
                  id:      r.id,
                  createdTime: r.createdTime,
                  // Store field names and value types but not actual values
                  fieldSummary: Object.fromEntries(
                    Object.entries(r.fields || {}).map(([k, v]) => [
                      k,
                      { type: Array.isArray(v) ? 'array' : typeof v, empty: v === null || v === '' || v === undefined },
                    ]),
                  ),
                }));
            await store.saveRecordSample(baseId, t.id, t.name, storedSample, sampledCount, hasMore);
          }
          await store.upsertBaseStatus(baseId, 'records_done');
        }

        if (audit.config?.include_automations !== false) {
          await store.event('automations', `Automations: ${baseName ?? baseId}`);
          const collected = await session.collectBase(baseId);
          await store.saveAutomations(baseId, collected.automations);
          const scriptCount = collected.automations.reduce((n, a) => n + a.scriptSources.length, 0);
          await store.event('automations', `Found ${collected.automations.length} automation(s), ${scriptCount} script(s)`);

          // Collect automation execution stats
          if (wantAutoStats) {
            try {
              const autoStats = await session.collectAutomationStats(baseId);
              await store.saveAutomationStats(baseId, autoStats);
              await store.event('automations', `Execution stats collected for ${baseName ?? baseId}`);
            } catch (e: any) {
              await store.event('automations', `Execution stats failed: ${e.message}`, 'warn');
            }
          }

          await store.upsertBaseStatus(baseId, 'automations_done');
        }

        await store.upsertBaseStatus(baseId, 'complete');
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        await store.event('schema', `Base ${baseId} failed: ${msg}`, 'error');
        await store.upsertBaseStatus(baseId, 'failed', msg);
      }
    }

    // --- Usage stats collection (all workspaces, after workspace cache is warm) ---
    if (wantEnv || audit.config?.collect_collaborators) {
      try {
        // Restart browser before usage stats to ensure it's alive
        await session.restartBrowser(baseConfig.browserProfileDir);
        await store.event('usage', 'Collecting usage stats for all workspaces...');
        const allBaseIds = targets.map(t => t.baseId);
        const usageData = await session.collectAllUsageStats(allBaseIds);
        const coveredBases = Object.keys(usageData.byBase).length;
        const totalWorkspaces = Object.keys(usageData.byWorkspace).length;
        await store.event('usage', `Usage stats: ${totalWorkspaces} workspace(s), ${coveredBases}/${allBaseIds.length} bases with per-base data`);
        if (usageData.errors.length > 0) {
          await store.event('usage', `Usage warnings: ${usageData.errors.join('; ')}`, 'warn');
        }
        await store.saveUsageStats(usageData);
        await store.event('usage', 'Usage stats saved');
      } catch (e: any) {
        await store.event('usage', `Usage stats collection failed: ${e.message}`, 'warn');
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

    // Generate full JSON export and upload to storage
    try {
      await store.event('export', 'Generating full audit export...');
      const exportUrl = await store.generateAndUploadExport();
      if (exportUrl) {
        await store.event('export', `Export uploaded: ${exportUrl}`);
      } else {
        await store.event('export', 'Export generation failed', 'warn');
      }
    } catch (e: any) {
      await store.event('export', `Export failed: ${e.message}`, 'warn');
    }

    // Send email notification
    await notifyAuditComplete(baseConfig, audit.id);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.error('[worker] Audit failed:', msg);
    await store.event('discover', `Worker failed: ${msg}`, 'error');
    await store.setAuditStatus('failed', msg);

    // Send email notification on failure too
    await notifyAuditComplete(baseConfig, audit.id);
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
