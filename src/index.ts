// index.ts
// Worker entry point. Starts HTTP server + polls for queued audits.

import fs   from 'fs';
import path from 'path';
import { RateLimiter }   from './rate-limiter.js';
import { PatEngine }     from './engine-pat.js';
import { SessionEngine } from './engine-session.js';
import { Store }         from './store.js';
import { startServer, setStatus, getStatus, waitForLoginConfirm } from './worker-server.js';
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

/** True when a client profile directory is empty or missing (needs VNC login). */
function isProfileFresh(profileDir: string): boolean {
  if (!fs.existsSync(profileDir)) return true;
  const entries = fs.readdirSync(profileDir);
  return entries.length === 0;
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

    // --- Per-client browser profile ---
    const clientId = audit.client_id || audit.id;
    const clientProfileDir = path.join(baseConfig.browserProfileDir, clientId);
    fs.mkdirSync(clientProfileDir, { recursive: true });

    if (isProfileFresh(clientProfileDir)) {
      // Fresh profile: open headful browser on VNC, wait for operator to confirm login
      await store.event('browser', `No session for client ${audit.prospect_name || clientId}. Log in via VNC then press Continue.`);
      console.log(`[worker] Fresh profile for ${clientId}. Opening headful browser, waiting for login confirmation.`);
      setStatus('login_required');
      // Open headful browser (visible on VNC) - does NOT wait for login automatically
      await session.startHeadfulOnly(clientProfileDir);
      // Block until operator presses "Continue" in the UI
      await waitForLoginConfirm();
      await store.event('browser', 'Login confirmed. Relaunching headless...');
      console.log(`[worker] Login confirmed for ${clientId}. Relaunching headless.`);
      // Relaunch headless with the now-populated profile
      await session.stop();
      await session.startHeadless(clientProfileDir);
      await store.event('browser', 'Browser ready, starting collection.');
      setStatus('busy');
    } else {
      await session.startHeadless(clientProfileDir);
    }

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

    // --- Interface inventory (one call, all bases) ---
    if (wantEnv || audit.config?.collect_collaborators) {
      try {
        await store.event('interfaces', 'Collecting interface inventory...');
        const ifResult = await session.collectAllInterfaces();
        if (ifResult.interfaces.length > 0) {
          await store.saveInterfaces(ifResult.interfaces);
          await store.event('interfaces', `Found ${ifResult.interfaces.length} interface(s)`);
        }
        if (ifResult.errors.length > 0) {
          await store.event('interfaces', `Warnings: ${ifResult.errors.join('; ')}`, 'warn');
        }
      } catch (e: any) {
        await store.event('interfaces', `Interface collection failed: ${e.message}`, 'warn');
      }
    }

    // --- Extract admin users + billing from enterprise data (if collected) ---
    if (wantEnterprise) {
      try {
        const { data: envRow } = await db.schema('audit').from('environment_data').select('data').eq('audit_id', audit.id).limit(1).maybeSingle();
        const envData = envRow?.data;
        if (envData?.enterprise) {
          const adminUsers = SessionEngine.extractAdminUsers(envData.enterprise);
          if (adminUsers.length > 0) {
            await store.saveAdminUsers(adminUsers);
            await store.event('environment', `Extracted ${adminUsers.length} admin user(s) to normalized table`);
          }
          const billingSnapshot = SessionEngine.extractBillingSnapshot(envData.enterprise, envData.workspace);
          if (billingSnapshot) {
            await store.saveBillingSnapshot(billingSnapshot);
            await store.event('environment', `Billing snapshot saved (plan: ${billingSnapshot.plan || 'unknown'})`);
          }
        }
      } catch (e: any) {
        await store.event('environment', `Admin user/billing extraction failed: ${e.message}`, 'warn');
      }
    }

    let baseIndex = 0;
    const RESTART_EVERY = 10; // Restart browser every N bases to prevent memory exhaustion
    const BASE_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes max per base

    for (const { baseId, baseName } of targets) {
      // Periodic browser restart to prevent Chromium memory crashes
      if (baseIndex > 0 && baseIndex % RESTART_EVERY === 0 && (audit.config?.collect_collaborators || wantEnv)) {
        try {
          await store.event('browser', `Restarting browser after ${baseIndex} bases to free memory`);
          await session.restartBrowser(clientProfileDir);
        } catch (e: any) {
          await store.event('browser', `Browser restart failed: ${e.message}`, 'warn');
        }
      }
      baseIndex++;

      const baseStartTime = Date.now();
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
            const crashMsg = e.message || '';
            const collabCrash = crashMsg.includes('Page crashed') || crashMsg.includes('Target closed');
            await store.event('collaborators', `Collaborator collection failed: ${crashMsg}`, 'warn');
            if (collabCrash) {
              await store.event('browser', 'Restarting browser after collaborator crash');
              try { await session.restartBrowser(clientProfileDir); } catch (_) {}
            }
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

        // --- Bootstrap read: sync topology + share links + table stats ---
        if (audit.config?.collect_collaborators || wantEnv) {
          try {
            await store.event('bootstrap', `Bootstrap read: ${baseName ?? baseId}`);
            // Pass table IDs from schema to get row counts
            const tblIds = null; // TODO: batch per-table for row counts
            const bootstrap = await session.collectBootstrapRead(baseId, tblIds);

            if (bootstrap.syncLinks.length > 0) {
              await store.saveSyncLinks(bootstrap.syncLinks.map(sl => ({ ...sl, destBaseId: baseId })));
              await store.event('bootstrap', `${bootstrap.syncLinks.length} sync link(s)`);
            }
            if (bootstrap.shares.length > 0) {
              await store.saveShareLinks(bootstrap.shares.map(s => ({ ...s, baseId })));
              await store.event('bootstrap', `${bootstrap.shares.length} share link(s)`);
            }
            if (bootstrap.tableStats.length > 0) {
              await store.saveTableStats(bootstrap.tableStats.map(ts => ({ ...ts, baseId })));
              await store.event('bootstrap', `Row counts for ${bootstrap.tableStats.length} table(s)`);
            }
            if (bootstrap.errors.length > 0) {
              await store.event('bootstrap', bootstrap.errors.join('; '), 'warn');
            }

            // Save base-level metadata (extensions, AI, revision history)
            await store.saveBaseExtras(baseId, {
              hasExtensions: bootstrap.hasExtensions ?? undefined,
              aiCreditsMonth: bootstrap.aiConsumption?.creditsMonth,
              aiCreditsRemaining: bootstrap.aiConsumption?.creditsRemaining,
              revisionHistoryEnabled: bootstrap.revisionHistoryEnabled ?? undefined,
            });

            // Scrape extensions if present
            if (bootstrap.hasExtensions) {
              try {
                const extResult = await session.collectExtensions(baseId);
                if (extResult.extensions.length > 0) {
                  await store.saveExtensions(baseId, extResult.extensions);
                  const scriptCount = extResult.extensions.filter((e: any) => e.isScripting).length;
                  await store.event('extensions', `${extResult.extensions.length} extension(s) in ${baseName ?? baseId}${scriptCount > 0 ? `, ${scriptCount} scripting` : ''}`);
                }
                if (extResult.errors.length > 0) {
                  await store.event('extensions', extResult.errors.join('; '), 'warn');
                }
              } catch (e: any) {
                await store.event('extensions', `Extension scrape failed: ${e.message}`, 'warn');
              }
            }
          } catch (e: any) {
            await store.event('bootstrap', `Bootstrap read failed: ${e.message}`, 'warn');
          }
        }

        // --- Automation run summaries (per-workflow) ---
        if (wantAutoStats && audit.config?.include_automations !== false) {
          try {
            const wfIds = (await (createClient(baseConfig.supabaseUrl, baseConfig.supabaseServiceRoleKey, { auth: { persistSession: false } })
              .schema('audit').from('automations').select('workflow_id')
              .eq('audit_id', audit.id).eq('base_id', baseId).not('workflow_id', 'is', null)
            )).data?.map((r: any) => r.workflow_id).filter(Boolean) || [];

            if (wfIds.length > 0) {
              const runSummaries = await session.collectAutomationRunSummaries(baseId, wfIds);
              await store.saveAutomationRuns(runSummaries.map(s => ({ ...s, baseId })));
              const activeCount = runSummaries.filter(s => s.runsCurrentMonth > 0).length;
              await store.event('automations', `Run summaries: ${activeCount}/${wfIds.length} active this month`);
            }
          } catch (e: any) {
            await store.event('automations', `Run summary failed: ${e.message}`, 'warn');
          }
        }

        // --- Normalized collaborators (to base_collaborators table) ---
        if (audit.config?.collect_collaborators && collaborators?.collaborators?.length > 0) {
          try {
            await store.saveBaseCollaborators(baseId, collaborators.collaborators.map((c: any) => ({
              userId: c.userId, email: c.email, permissionLevel: c.permissionLevel, source: c.source,
            })));
          } catch (e: any) {
            await store.event('collaborators', `Normalized save failed: ${e.message}`, 'warn');
          }
        }

        await store.upsertBaseStatus(baseId, 'complete');
        const elapsed = ((Date.now() - baseStartTime) / 1000).toFixed(1);
        await store.event('schema', `Base ${baseName ?? baseId} complete in ${elapsed}s`);
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        const isTimeout = msg.includes('timed out after');
        const isCrash = msg.includes('Page crashed') || msg.includes('Target closed') || msg.includes('Protocol error');
        await store.event('schema', `Base ${baseId} failed${isTimeout ? ' (timeout)' : isCrash ? ' (crash)' : ''}: ${msg}`, 'error');
        await store.upsertBaseStatus(baseId, 'failed', msg);
        // If crash or timeout, browser is in a bad state; restart immediately
        if ((isTimeout || isCrash) && (audit.config?.collect_collaborators || wantEnv)) {
          try {
            await store.event('browser', `Restarting browser after ${isCrash ? 'crash' : 'timeout'}`);
            await session.restartBrowser(clientProfileDir);
          } catch (re: any) {
            await store.event('browser', `Post-crash restart failed: ${re.message}`, 'warn');
          }
        }
      }
    }

    // --- Usage stats collection (all workspaces, after workspace cache is warm) ---
    if (wantEnv || audit.config?.collect_collaborators) {
      try {
        // Restart browser before usage stats to ensure it's alive
        await session.restartBrowser(clientProfileDir);
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

    // --- DERIVE: integration endpoints scan (no browser needed) ---
    try {
      await store.event('integrations', 'Scanning automations for integration endpoints...');
      const db2 = createClient(baseConfig.supabaseUrl, baseConfig.supabaseServiceRoleKey, { auth: { persistSession: false } });
      const { data: allAutos } = await db2.schema('audit').from('automations')
        .select('base_id,workflow_id,name,script_sources,trigger_config')
        .eq('audit_id', audit.id);

      if (allAutos && allAutos.length > 0) {
        const endpoints = SessionEngine.scanIntegrationEndpoints(allAutos);
        if (endpoints.length > 0) {
          await store.saveIntegrationEndpoints(endpoints);
          const domainCounts: Record<string, number> = {};
          for (const ep of endpoints) domainCounts[ep.domain] = (domainCounts[ep.domain] || 0) + 1;
          const summary = Object.entries(domainCounts).sort((a, b) => b[1] - a[1]).slice(0, 10)
            .map(([d, n]) => `${d}(${n})`).join(', ');
          await store.event('integrations', `Found ${endpoints.length} endpoint(s): ${summary}`);
        } else {
          await store.event('integrations', 'No external endpoints found');
        }
      }
    } catch (e: any) {
      await store.event('integrations', `Integration scan failed: ${e.message}`, 'warn');
    }

    // --- DERIVE: field fill rates from record samples ---
    try {
      const db3 = createClient(baseConfig.supabaseUrl, baseConfig.supabaseServiceRoleKey, { auth: { persistSession: false } });
      const { data: samples } = await db3.schema('audit').from('record_samples')
        .select('base_id,table_id,sample,sampled_count').eq('audit_id', audit.id);

      if (samples && samples.length > 0) {
        const fieldStats: any[] = [];
        for (const s of samples) {
          const records = s.sample || [];
          if (!records.length) continue;
          const n = records.length;
          const fills: Record<string, { nonEmpty: number }> = {};
          for (const rec of records) {
            const fields = rec.fields || rec.fieldSummary || {};
            for (const [key, val] of Object.entries(fields)) {
              if (!fills[key]) fills[key] = { nonEmpty: 0 };
              if (rec.fieldSummary) {
                if (!(val as any)?.empty) fills[key].nonEmpty++;
              } else {
                if (val !== null && val !== '' && val !== undefined) fills[key].nonEmpty++;
              }
            }
          }
          for (const [fieldName, info] of Object.entries(fills)) {
            fieldStats.push({
              baseId: s.base_id, tableId: s.table_id, fieldId: fieldName,
              fieldName, fillRate: Math.round((info.nonEmpty / n) * 10000) / 100, sampleN: n,
            });
          }
        }
        if (fieldStats.length > 0) {
          await store.saveFieldStats(fieldStats);
          await store.event('analysis', `Computed fill rates for ${fieldStats.length} field(s)`);
        }
      }
    } catch (e: any) {
      await store.event('analysis', `Field fill rate computation failed: ${e.message}`, 'warn');
    }

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
  console.log('[worker] Ready. Polling for queued audits (per-client browser profiles).');

  // Poll loop
  while (true) {
    const status = getStatus();

    if (status !== 'busy') {
      const audit = await claimNextAudit(db);
      if (audit) {
        setStatus('busy');
        await runAudit(audit, baseConfig);
        setStatus('idle');
      }
    }

    await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
  }
}

main().catch((err) => {
  console.error('[worker] FATAL:', err);
  process.exit(1);
});
