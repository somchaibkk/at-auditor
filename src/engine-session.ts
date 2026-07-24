// engine-session.ts
// ---------------------------------------------------------------------------
// Engine 2: automation collection via Airtable internal API.
// Fetches run inside a live Playwright page (same-origin) using a persistent
// browser profile. Credentials never leave the browser process.
//
// Confirmed endpoints (from real network inspection):
//   GET /v0.3/application/{appId}/listWorkflows
//     -> { data: { workflows: [...] } }
//     -> each workflow includes id, name, deploymentStatus,
//        targetWorkflowDeploymentId, trigger, graph (with actionsById)
//
//   GET /v0.3/workflowDeployment/{wfdId}/read
//     -> { data: { workflowDeployment: { workflowDefinition: { graph, trigger, ... } } } }
//     -> script body at graph.actionsById[id].inputExpressions.script.value
// ---------------------------------------------------------------------------

import { chromium, type BrowserContext, type Page } from 'playwright';
import { scrapeUndeployedScript } from './engine-session-scraper.js';

export interface ScriptSource {
  actionId:   string;
  stepIndex:  number;
  actionType: string;
  lines:      number;
  code:       string;
}

export interface CollectedAutomation {
  workflowId:       string | null;
  deploymentId:     string | null;
  name:             string | null;
  deploymentStatus: string | null;
  triggerTypeId:    string | null;
  trigger:          string;
  triggerConfig:    Record<string, any> | null;
  stepCount:        number;
  actionTypes:      string[];
  scriptSources:    ScriptSource[];
  createdByUserId?: string | null;
  deploymentCreatedTime?: string | null;
  error?:           string;
}

export interface CollectedBase {
  appId:        string;
  collectedAt:  string;
  automations:  CollectedAutomation[];
}

// ---------------------------------------------------------------------------
// Label maps (extend as new type IDs are observed in the wild)
// ---------------------------------------------------------------------------

const TRIGGER_LABELS: Record<string, string> = {
  wttRECORDCREATED0: 'record created',
  wttRECORDUPDATED0: 'record updated',
  wttRECORDMATCHES0: 'record matches condition',
  wttFORMSUBMITTED0: 'form submitted',
  wttCRON0000000000: 'scheduled',
  wttCONNECTIONINPT: 'connected app',
  wttBUTTONCLICKED0: 'button clicked',
  wttWEBHOOK00000:   'webhook',
  wttRECORDINVIEW00: 'record enters view',
  wttSHAREVIEWFRM0:  'shared view form submitted',
  wttEXTERNALACTN0:  'external action',
  wttMANUALTRIGGER:  'manual trigger',
  wttRECORDDELETED0: 'record deleted',
  wttCOMMENTADDED0:  'comment added',
  wttAIGENERATED00:  'AI generated',
};

const ACTION_LABELS: Record<string, string> = {
  watUPDATERECORD00: 'update record',
  watCREATERECORD00: 'create record',
  watDELETERECORD00: 'delete record',
  watCUSTOMSCRIPT00: 'run script',
  watSENDEMAIL00000: 'send email',
  watSENDSMS0000000: 'send SMS',
  watSLACKMESSAGE00: 'send Slack message',
  watFINDRECORDS000: 'find records',
  watCREATERECORDS0: 'create records',
  watSORT0000000000: 'sort records',
  wdtNWAY0000000000: 'condition (branch)',
  wdtFANOUT00000000: 'repeat for each',
  wdtREDUCER0000000: 'summarize',
  watCONNECTIONOUTP: 'connected app action',
  watUPDATERECORDS0: 'update records',
  watSENDWEBHOOK000: 'send webhook',
  watLEAVECOMMENT00: 'leave comment',
  watGENERATEAI0000: 'AI generate',
  watSENDTEAMS00000: 'send Teams message',
  watSENDGOOGLECHAT: 'send Google Chat',
};

// ---------------------------------------------------------------------------
// SessionEngine
// ---------------------------------------------------------------------------

export interface CollaboratorInfo {
  userId:          string | null;
  email:           string | null;
  name:            string | null;
  permissionLevel: string | null;
  source:          'workspace' | 'base';
}

export interface CollaboratorsResult {
  workspaceId:    string | null;
  workspaceName:  string | null;
  collaborators:  CollaboratorInfo[];
  error?:         string;
}

export class SessionEngine {
  private context!: BrowserContext;
  private page!:    Page;

  // Cache workspace resolution results to avoid redundant navigation
  private workspaceCache: Map<string, string> = new Map(); // baseId -> wspId
  private wspSettingsCache: Map<string, any> = new Map();  // wspId -> workspaceSettings data

  /**
   * Start using a persistent browser profile.
   * If the profile is already logged in, continues immediately.
   * If not, opens headful and waits for the operator to log in (up to 5 min).
   */
  async start(profileDir: string, headless = false): Promise<void> {
    this.context = await chromium.launchPersistentContext(profileDir, { headless: false, chromiumSandbox: false, args: ['--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu'] });
    this.page = await this.context.newPage();
    await this.page.goto('https://airtable.com/login', { waitUntil: 'domcontentloaded' });
    await this.ensureLoggedIn();
    // If headless was requested and we're already logged in, relaunch headless
    if (headless) {
      await this.context.close();
      this.context = await chromium.launchPersistentContext(profileDir, { headless: true, chromiumSandbox: false, args: ['--no-sandbox', '--disable-dev-shm-usage'] });
      this.page = await this.context.newPage();
    }
  }

  private async ensureLoggedIn(): Promise<void> {
    const LOGIN_TIMEOUT_MS = 5 * 60 * 1000;
    const POLL_MS = 2000;
    const deadline = Date.now() + LOGIN_TIMEOUT_MS;

    while (Date.now() < deadline) {
      try {
        const url = this.page.url();
        if (url.includes('airtable.com') && !url.includes('/login') && !url.includes('/signup')) {
          await this.page.waitForLoadState('networkidle').catch(() => {});
          if (!this.page.url().includes('/login')) {
            console.log('[engine-session] Logged in at:', this.page.url());
            return;
          }
        }
      } catch (_) {}
      await new Promise((r) => setTimeout(r, POLL_MS));
    }
    throw new Error('Airtable login timeout after 5 minutes');
  }


  /** Open headful browser on VNC without waiting for login. Operator confirms via UI. */
  async startHeadfulOnly(profileDir: string): Promise<void> {
    this.context = await chromium.launchPersistentContext(profileDir, {
      headless: false,
      chromiumSandbox: false,
      args: ['--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu'],
    });
    this.page = await this.context.newPage();
    await this.page.goto('https://airtable.com/login', { waitUntil: 'domcontentloaded', timeout: 30_000 }).catch(() => {});
    console.log('[engine-session] Headful browser open on VNC, waiting for operator to log in...');
  }

  // Start headless using an already-logged-in persistent profile (no login wait)
  async startHeadless(profileDir: string): Promise<void> {
    this.context = await chromium.launchPersistentContext(profileDir, { headless: true, chromiumSandbox: false, args: ['--no-sandbox', '--disable-dev-shm-usage'] });
    this.page    = await this.context.newPage();
  }

  async stop(): Promise<void> {
    await this.context?.close();
  }

  /** Restart the browser to free memory. Clears page caches but keeps workspace/settings caches. */
  async restartBrowser(profileDir: string): Promise<void> {
    console.log('[engine-session] Restarting browser to free memory...');
    try { await this.context?.close(); } catch (_) {}
    // Small delay to let OS reclaim memory
    await new Promise((r) => setTimeout(r, 2000));
    this.context = await chromium.launchPersistentContext(profileDir, { headless: true, chromiumSandbox: false, args: ['--no-sandbox', '--disable-dev-shm-usage'] });
    this.page    = await this.context.newPage();
    console.log('[engine-session] Browser restarted');
  }

  // ---------------------------------------------------------------------------
  // Collaborator collection via internal API
  // ---------------------------------------------------------------------------

  /**
   * Collect collaborators for a base using the internal workspaceSettings API.
   * Strategy:
   *   1. Navigate to the base to bootstrap the app shell + session cookies
   *   2. Extract the workspace ID from the page HTML
   *   3. Call GET /v0.3/{wspId}/workspace/workspaceSettings via page.evaluate
   *   4. Parse the structured JSON response for user profiles + permissions
   */
  async scrapeCollaborators(baseId: string): Promise<CollaboratorsResult> {
    const result: CollaboratorsResult = {
      workspaceId:   null,
      workspaceName: null,
      collaborators: [],
    };

    try {
      // Step 1: resolve workspace ID (uses cache after first call)
      console.log(`[engine-session] Resolving workspace for base ${baseId}...`);
      const wspId = await this.resolveWorkspaceId(baseId);

      if (!wspId) {
        result.error = 'Could not resolve workspace ID for base';
        return result;
      }
      result.workspaceId = wspId;

      // Step 2: get workspace settings (fetch once, cache for reuse)
      let wsData = this.wspSettingsCache.get(wspId) || null;
      if (!wsData) {
        console.log(`[engine-session] Fetching workspaceSettings for ${wspId}...`);
        wsData = await this.fetchInternalApi(`/v0.3/${wspId}/workspace/workspaceSettings`);
        if (wsData) this.wspSettingsCache.set(wspId, wsData);
      } else {
        console.log(`[engine-session] Using cached workspaceSettings for ${wspId}`);
      }

      if (!wsData) {
        result.error = 'workspaceSettings API returned no data';
        return result;
      }

      // Step 3: parse collaborators with base-specific permission resolution
      result.workspaceName = wsData.workspaceData?.workspaceName || null;

      const breakdown = wsData.workspaceData?.billableUserBreakdown;
      if (!breakdown) {
        result.error = 'No billableUserBreakdown in workspaceSettings response';
        return result;
      }

      const profiles: Record<string, { id: string; name: string; email: string }> =
        breakdown.billableUserProfileInfoById || {};

      // Workspace-level permissions (same for all bases)
      const wsPerms: Record<string, string> = {};
      for (const wc of breakdown.workspaceCollaborators || []) {
        wsPerms[wc.userId] = wc.permissionLevel;
      }

      // Base-level permissions - filter for THIS specific base
      const basePerms: Record<string, string> = {};
      for (const ac of breakdown.applicationCollaborators || []) {
        if (ac.applicationId === baseId) {
          basePerms[ac.userId] = ac.permissionLevel;
        }
      }

      for (const [userId, profile] of Object.entries(profiles)) {
        const wspPerm  = wsPerms[userId] || null;
        const basePerm = basePerms[userId] || null;

        // Determine effective permission and source
        let permissionLevel: string | null;
        let source: 'workspace' | 'base';
        if (basePerm) {
          // Explicit base-level permission takes precedence
          permissionLevel = basePerm;
          source = 'base';
        } else if (wspPerm) {
          // Workspace-level permission inherited by all bases
          permissionLevel = wspPerm;
          source = 'workspace';
        } else {
          // User is billable but has no explicit workspace or base-level permission for this base
          permissionLevel = null;
          source = 'base';
        }

        result.collaborators.push({
          userId,
          email:           profile.email,
          name:            profile.name,
          permissionLevel,
          source,
        });
      }

      (result as any).workspacePlan = wsData.workspaceData?.billingPlan?.name || null;
      (result as any).workspacePlanGrouping = wsData.workspaceData?.billingPlan?.grouping || null;
      (result as any).totalBillable = breakdown.numTotalBillableCollaborators || 0;
      (result as any).totalNonBillable = breakdown.numTotalNonBillableCollaborators || 0;

      const nullCount = result.collaborators.filter(c => !c.permissionLevel).length;
      console.log(`[engine-session] Found ${result.collaborators.length} collaborator(s) for base ${baseId} (${nullCount} with unknown permission)`);
      console.log(`[engine-session] Workspace: "${result.workspaceName}", Plan: ${(result as any).workspacePlan}`);

    } catch (err: any) {
      result.error = `Collaborator collection failed: ${err.message}`;
      console.error(`[engine-session] ${result.error}`);
    }

    return result;
  }

  // ---------------------------------------------------------------------------
  // Full environment data collection (Tier 1 + Tier 2 + Tier 3)
  // ---------------------------------------------------------------------------

  /**
   * Collect comprehensive environment data: workspace settings, usage stats,
   * enterprise admin panel data (users, licenses, security, workspaces),
   * and per-workflow execution counts.
   *
   * Requires: browser navigated to an Airtable page (session cookies active).
   * Returns a single object with all collected data, null fields where access
   * was denied or data unavailable.
   */
  async collectEnvironment(baseId: string, opts: { enterprise?: boolean } = {}): Promise<Record<string, any>> {
    const env: Record<string, any> = {
      collectedAt: new Date().toISOString(),
      workspace:   null,
      usageStats:  null,
      enterprise:  null,
      errors:      [] as string[],
    };

    try {
      // --- Tier 1: Workspace level ---
      console.log(`[engine-session] Starting environment collection...`);
      const wspId = await this.resolveWorkspaceId(baseId);
      if (wspId) {
        console.log(`[engine-session] Tier 1: fetching workspace data for ${wspId}...`);

        // workspaceSettings (use cache if available)
        let wsSettings = this.wspSettingsCache.get(wspId) || null;
        if (!wsSettings) {
          wsSettings = await this.fetchInternalApi(`/v0.3/${wspId}/workspace/workspaceSettings`);
          if (wsSettings) this.wspSettingsCache.set(wspId, wsSettings);
        } else {
          console.log(`[engine-session] Tier 1: using cached workspaceSettings`);
        }
        if (wsSettings) {
          env.workspace = {
            workspaceId:   wspId,
            workspaceName: wsSettings.workspaceData?.workspaceName,
            billingPlan:   wsSettings.workspaceData?.billingPlan,
            billingAddOnIds: wsSettings.workspaceData?.billingAddOnIds,
            billableUserBreakdown: wsSettings.workspaceData?.billableUserBreakdown ? {
              numWorkspaceLevelBillableCollaborators:  wsSettings.workspaceData.billableUserBreakdown.numWorkspaceLevelBillableCollaborators,
              numAppLevelBillableCollaborators:        wsSettings.workspaceData.billableUserBreakdown.numAppLevelBillableCollaborators,
              numTotalBillableCollaborators:           wsSettings.workspaceData.billableUserBreakdown.numTotalBillableCollaborators,
              numTotalNonBillableCollaborators:        wsSettings.workspaceData.billableUserBreakdown.numTotalNonBillableCollaborators,
              numTotalEditorOrAbovePermissionCollaborators: wsSettings.workspaceData.billableUserBreakdown.numTotalEditorOrAbovePermissionCollaborators,
              numTotalCommenterPermissionCollaborators:     wsSettings.workspaceData.billableUserBreakdown.numTotalCommenterPermissionCollaborators,
              workspaceCollaborators:   wsSettings.workspaceData.billableUserBreakdown.workspaceCollaborators,
              applicationCollaborators: wsSettings.workspaceData.billableUserBreakdown.applicationCollaborators,
              billableUserProfileInfoById: wsSettings.workspaceData.billableUserBreakdown.billableUserProfileInfoById,
            } : null,
          };
          console.log(`[engine-session] Tier 1: workspaceSettings OK`);
        } else {
          env.errors.push('workspaceSettings failed');
        }

        // workspaceUsageStats
        const usageStats = await this.fetchInternalApi(`/v0.3/${wspId}/workspace/workspaceUsageStats`);
        if (usageStats) {
          env.usageStats = usageStats.workspaceUsageStats || usageStats;
          console.log(`[engine-session] Tier 1: workspaceUsageStats OK`);
        } else {
          env.errors.push('workspaceUsageStats failed');
        }

        // --- Tier 2: Enterprise/Admin level ---
        // Extract enterprise account ID from workspace settings
        if (opts.enterprise !== false) {
          const entId = this.extractEnterpriseId(wsSettings);
          if (entId) {
            console.log(`[engine-session] Tier 2: fetching enterprise data for ${entId}...`);
            env.enterprise = await this.collectEnterpriseData(entId);
            console.log(`[engine-session] Tier 2: enterprise data collection complete`);
          } else {
            env.errors.push('No enterprise account ID found (may not be enterprise plan)');
            console.log(`[engine-session] Tier 2: skipped (no enterprise account ID)`);
          }
        } else {
          console.log(`[engine-session] Tier 2: skipped (disabled in config)`);
        }
      } else {
        env.errors.push('Could not resolve workspace ID');
      }
    } catch (err: any) {
      env.errors.push(`Environment collection failed: ${err.message}`);
      console.error(`[engine-session] ${err.message}`);
    }

    return env;
  }

  /**
   * Collect per-base automation execution stats.
   * Call after collectBase() with the workflow IDs from the automations.
   */
  async collectAutomationStats(appId: string): Promise<Record<string, any>> {
    const stats: Record<string, any> = {
      executionCountsThisMonth: null,
      errors: [] as string[],
    };

    try {
      // Navigate to automations tab to bootstrap context
      await this.page.goto(`https://airtable.com/${appId}/automations`, {
        waitUntil: 'domcontentloaded',
        timeout: 90_000,
      });
      await new Promise((r) => setTimeout(r, 3000));

      // Get monthly execution counts for all workflows in this base
      const counts = await this.fetchInternalApi(
        `/v0.3/application/${appId}/getWorkflowExecutionCountsInCurrentMonth?stringifiedObjectParams=%7B%7D`,
      );
      if (counts) {
        stats.executionCountsThisMonth = counts.data || counts;
        console.log(`[engine-session] Automation stats OK for ${appId}`);
      } else {
        stats.errors.push('getWorkflowExecutionCountsInCurrentMonth failed');
      }
    } catch (err: any) {
      stats.errors.push(`Automation stats failed: ${err.message}`);
    }

    return stats;
  }

  /**
   * Collect recent execution history for a specific workflow.
   */
  async collectWorkflowExecutions(workflowId: string): Promise<any[]> {
    try {
      const data = await this.fetchInternalApi(
        `/v0.3/workflow/${workflowId}/listExecutions?stringifiedObjectParams=%7B%22filter%22%3Anull%2C%22createdBefore%22%3Anull%7D`,
      );
      return data?.data?.workflowExecutions || data?.data?.executions || [];
    } catch {
      return [];
    }
  }

  /**
   * Collect workspaceUsageStats for ALL unique workspaces across audit bases.
   * Call after the per-base loop so workspaceCache is warm.
   * Returns { byWorkspace: { [wspId]: stats }, byBase: { [baseId]: stats }, errors: string[] }
   */
  async collectAllUsageStats(baseIds: string[]): Promise<Record<string, any>> {
    const result: Record<string, any> = {
      byWorkspace: {} as Record<string, any>,
      byBase:      {} as Record<string, any>,
      errors:      [] as string[],
    };

    // Resolve all bases to workspace IDs (using cache)
    const wspToBasesMap = new Map<string, string[]>();
    for (const baseId of baseIds) {
      const wspId = await this.resolveWorkspaceId(baseId);
      if (wspId) {
        const existing = wspToBasesMap.get(wspId) || [];
        existing.push(baseId);
        wspToBasesMap.set(wspId, existing);
      } else {
        result.errors.push(`Could not resolve workspace for base ${baseId}`);
      }
    }

    console.log(`[engine-session] Usage stats: ${wspToBasesMap.size} unique workspace(s) across ${baseIds.length} base(s)`);

    for (const [wspId, bases] of wspToBasesMap) {
      try {
        const usageStats = await this.fetchInternalApi(`/v0.3/${wspId}/workspace/workspaceUsageStats`);
        if (!usageStats) {
          result.errors.push(`workspaceUsageStats failed for workspace ${wspId}`);
          continue;
        }

        const statsData = usageStats.workspaceUsageStats || usageStats;
        result.byWorkspace[wspId] = statsData;

        // Log shape on first successful response for future reference
        if (Object.keys(result.byWorkspace).length === 1) {
          console.log(`[engine-session] workspaceUsageStats response keys: ${JSON.stringify(Object.keys(statsData))}`);
          // If there's per-base data, log those keys too
          if (statsData.baseUsageByBaseId) {
            const firstBaseKey = Object.keys(statsData.baseUsageByBaseId)[0];
            if (firstBaseKey) {
              console.log(`[engine-session] Per-base usage keys: ${JSON.stringify(Object.keys(statsData.baseUsageByBaseId[firstBaseKey]))}`);
            }
          } else if (statsData.applicationUsageByApplicationId) {
            const firstAppKey = Object.keys(statsData.applicationUsageByApplicationId)[0];
            if (firstAppKey) {
              console.log(`[engine-session] Per-app usage keys: ${JSON.stringify(Object.keys(statsData.applicationUsageByApplicationId[firstAppKey]))}`);
            }
          }
        }

        // Try to extract per-base data (field name might be baseUsageByBaseId or applicationUsageByApplicationId)
        const perBase = statsData.baseUsageByBaseId
          || statsData.applicationUsageByApplicationId
          || null;

        if (perBase && typeof perBase === 'object') {
          for (const baseId of bases) {
            const baseStats = perBase[baseId] || null;
            if (baseStats) {
              result.byBase[baseId] = baseStats;
            }
          }
        }

        console.log(`[engine-session] Usage stats OK for workspace ${wspId} (${bases.length} bases)`);
      } catch (err: any) {
        result.errors.push(`workspaceUsageStats error for ${wspId}: ${err.message}`);
      }
    }

    const coveredBases = Object.keys(result.byBase).length;
    console.log(`[engine-session] Usage stats: ${coveredBases}/${baseIds.length} bases have per-base data`);
    return result;
  }

  // ---------------------------------------------------------------------------
  // Bootstrap /read: sync topology + share links per base
  // Confirmed: /v0.3/application/{appId}/read with allowMsgpackOfResult:false
  // returns JSON. Needs x-time-zone + x-airtable-application-id headers.
  // ---------------------------------------------------------------------------

  async collectBootstrapRead(appId, tableIds) {
    const out = { syncLinks: [], shares: [], tableStats: [], hasExtensions: null, aiConsumption: null, revisionHistoryEnabled: null, errors: [] };
    try {
      const params = {
        includeDataForTableIds: tableIds,
        includeDataForViewIds: null,
        shouldIncludeSchemaChecksum: false,
        mayOnlyIncludeRowAndCellDataForIncludedViews: false,
        mayExcludeCellDataForLargeViews: false,
        allowMsgpackOfResult: false,
        canClientSupportPreviewMode: false,
      };
      const url = '/v0.3/application/' + appId + '/read?stringifiedObjectParams=' + encodeURIComponent(JSON.stringify(params));
      console.log('[DEBUG] About to call fetchInternalApi for bootstrap, url length:', url.length, 'appId:', appId);
      const data = await this.fetchInternalApi(url, appId, 120_000); // 120s for large bootstrap payloads
      console.log('[DEBUG] fetchInternalApi returned:', data === null ? 'NULL' : typeof data, data?.__error ? 'ERROR' : 'ok');
      const d = data?.data || data || {};

      // Sync links
      const schemas = d.tableSchemas || [];
      for (const ts of schemas) {
        const syncById = ts.externalTableSyncById || {};
        const syncIds = Object.keys(syncById);
        const isMulti = syncIds.length > 1;
        for (const syncId of syncIds) {
          const se = syncById[syncId];
          out.syncLinks.push({
            destTableId: ts.id || null, syncId,
            sourceType: se?.dataSourceConfig?.dataSourceType || 'unknown',
            sourceAccountId: se?.dataSourceConfig?.externalAccountId || null,
            syncState: se?.syncState || null, isMultiSource: isMulti,
            fieldMapping: se?.dataSourceConfig?.externalFieldIdByColumnId || null,
          });
        }
        const tgt = ts.externalTableSyncTargetConfiguration;
        if (tgt && syncIds.length > 0) {
          const first = out.syncLinks[out.syncLinks.length - syncIds.length];
          if (first) {
            first.syncState = tgt.syncState || first.syncState;
            first.lastSuccessTime = tgt.lastSuccessTime || null;
            first.lastFailureTime = tgt.lastFailureTime || null;
            first.lastFailureInfo = tgt.lastFailureInfo || null;
            first.syncFrequency = tgt.metadata?.syncFrequency || null;
            first.shouldSyncRowDeletions = tgt.metadata?.shouldSyncRowDeletions;
            first.resyncTime = tgt.resyncTime || null;
          }
        }
      }

      // Shares
      const sharesMap = d.sharesById || {};
      for (const [sid, sh] of Object.entries(sharesMap)) {
        out.shares.push({
          shareId: sid, kind: sh.type || sh.shareType || null,
          isPasswordProtected: sh.isPasswordProtected || false,
          isDomainRestricted: sh.restrictedDomains ? true : false,
        });
      }

      // Table stats
      const tableDatas = d.tableDatas || [];
      const tdArr = Array.isArray(tableDatas) ? tableDatas : Object.entries(tableDatas).map(([id, v]) => ({ id, ...v }));
      for (const td of tdArr) {
        if (td?.id) {
          out.tableStats.push({ tableId: td.id, tableName: td.name || null, rowCount: td.rowCount != null ? td.rowCount : (td.rows ? td.rows.length : null) });
        }
      }

      // Extras
      out.hasExtensions = d.hasBlockInstallations || false;
      out.revisionHistoryEnabled = d.isRevisionHistoryEnabled || false;
      if (d.aiConsumptionInfo) {
        out.aiConsumption = { creditsMonth: d.aiConsumptionInfo.creditsConsumedForMonth || 0, creditsRemaining: d.aiConsumptionInfo.remainingCreditsForMonth || 0 };
      }

      console.log('[engine-session] Bootstrap ' + appId + ': ' + out.syncLinks.length + ' sync, ' + out.shares.length + ' shares, ' + out.tableStats.length + ' table stats, ext=' + out.hasExtensions);
    } catch (err) {
      out.errors.push('Bootstrap read ' + appId + ': ' + err.message);
    }
    return out;
  }

  async collectAllInterfaces() {
    const out = { interfaces: [], errors: [] };
    try {
      await this.page.goto("https://airtable.com/", { waitUntil: "domcontentloaded", timeout: 60000 });
      await new Promise(r => setTimeout(r, 3000));

      // Extract userId from page HTML
      const userId = await this.page.evaluate(function() {
        var m = document.documentElement.innerHTML.match(/"userId":"(usr[a-zA-Z0-9]+)"/);
        return m ? m[1] : null;
      });
      if (!userId) { out.errors.push("no userId found"); return out; }

      // Fetch interfaces via fetchInternalApi
      var params = { shouldIncludePageBundleSharingApplications: true, shouldIncludePageBundleIndex: true };
      var url = "/v0.3/user/" + userId + "/listApplicationsAndPageBundlesForDisplay?stringifiedObjectParams=" + encodeURIComponent(JSON.stringify(params));
      var data = await this.fetchInternalApi(url);
      if (!data) { out.errors.push("fetchInternalApi returned null"); return out; }
      var d = data.data || data;
      var pbs = d.pageBundles || [];
      out.interfaces = pbs.map(function(pb) {
        return { baseId: pb.applicationId, interfaceId: pb.id, name: pb.name || null, createdTime: pb.createdTime || null, firstPublishedTime: pb.firstPagePublishedTime || null };
      });
      console.log("[engine-session] Collected " + out.interfaces.length + " interface(s)");
    } catch (err) {
      out.errors.push("Interfaces: " + err.message);
    }
    return out;
  }

  // ---------------------------------------------------------------------------
  // Automation run summaries: monthly counts + last-run per workflow
  // ---------------------------------------------------------------------------

  async collectAutomationRunSummaries(appId: string, workflowIds: string[]): Promise<any[]> {
    const summaries: any[] = [];

    // Monthly counts (one call for all workflows in this base)
    let monthlyCounts: Record<string, number> = {};
    try {
      const d = await this.fetchInternalApi(
        `/v0.3/application/${appId}/getWorkflowExecutionCountsInCurrentMonth?stringifiedObjectParams=%7B%7D`,
      );
      monthlyCounts = d?.data?.workflowExecutionCountByWorkflowId || {};
    } catch { /* non-fatal */ }

    // Per-workflow: first page of listExecutions (20 runs)
    for (const wfId of workflowIds) {
      const s: any = {
        workflowId: wfId, runsCurrentMonth: monthlyCounts[wfId] ?? 0,
        lastRunAt: null, lastRunStatus: null,
        totalRunsSampled: 0, successCount: 0, failureCount: 0, oldestSampledRun: null,
      };
      try {
        const d = await this.fetchInternalApi(
          `/v0.3/workflow/${wfId}/listExecutions?stringifiedObjectParams=%7B%22filter%22%3Anull%2C%22createdBefore%22%3Anull%7D`,
        );
        const execs = d?.data?.workflowExecutions || [];
        s.totalRunsSampled = execs.length;
        if (execs.length > 0) {
          s.lastRunAt = execs[0].createdTime || null;
          s.lastRunStatus = execs[0].status || null;
          s.oldestSampledRun = execs[execs.length - 1].createdTime || null;
          for (const ex of execs) {
            if (ex.status === 'success') s.successCount++;
            else s.failureCount++;
          }
        }
      } catch { /* non-fatal */ }
      summaries.push(s);
    }
    return summaries;
  }

  // ---------------------------------------------------------------------------
  // DERIVE: scan automations for integration URLs (static, no browser needed)
  // ---------------------------------------------------------------------------

  static scanIntegrationEndpoints(automations: any[]): any[] {
    const endpoints: any[] = [];
    const urlRegex = /https?:\/\/[^\s"'`<>\]\)\\]+/g;
    const ignoreDomains = new Set([
      'airtable.com', 'static.airtable.com', 'dl.airtable.com',
      'api.airtable.com', 'localhost', '127.0.0.1',
    ]);

    for (const auto of automations) {
      const baseId = auto.base_id;
      const wfRef = auto.name || auto.workflow_id || 'unknown';

      for (const script of (auto.script_sources || [])) {
        const code = typeof script === 'string' ? script : (script.code || '');
        const urls = code.match(urlRegex) || [];
        for (const u of urls) {
          try {
            const domain = new URL(u).hostname;
            if (!ignoreDomains.has(domain)) {
              endpoints.push({ baseId, sourceKind: 'script', domain, url: u.slice(0, 500), evidenceRef: `Automation: ${wfRef}` });
            }
          } catch { /* skip */ }
        }
      }

      const cfg = auto.trigger_config;
      if (cfg) {
        if (cfg.webhookUrl) {
          try {
            endpoints.push({ baseId, sourceKind: 'webhook_trigger', domain: new URL(cfg.webhookUrl).hostname, url: cfg.webhookUrl, evidenceRef: `Trigger: ${wfRef}` });
          } catch { /* skip */ }
        }
        if (cfg.appName || cfg.connectionName) {
          endpoints.push({ baseId, sourceKind: 'connected_app', domain: (cfg.appName || cfg.connectionName || '').toLowerCase(), url: '', evidenceRef: `Connected app: ${wfRef}` });
        }
      }
    }

    // Deduplicate
    const seen = new Set<string>();
    return endpoints.filter(e => {
      const key = `${e.baseId}:${e.sourceKind}:${e.domain}:${e.url}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  // ---------------------------------------------------------------------------
  // Extract admin users from enterprise data (already collected)
  // ---------------------------------------------------------------------------

  // ---------------------------------------------------------------------------
  // Extensions: DOM scrape from the extensions panel per base (2.3)
  // Only called when hasBlockInstallations is true.
  // Navigates to base?blocks=show, waits for .blockFrame elements,
  // extracts name, installation ID, block ID from each.
  // ---------------------------------------------------------------------------

  async collectExtensions(appId: string): Promise<{
    extensions: Array<{
      extensionName: string; blockInstallationId: string;
      blockId: string; isScripting: boolean; scriptCode: string | null;
    }>;
    errors: string[];
  }> {
    const out = { extensions: [] as any[], errors: [] as string[] };
    try {
      // Open extensions panel
      await this.page.goto(`https://airtable.com/${appId}?blocks=show`, {
        waitUntil: 'domcontentloaded', timeout: 90_000,
      });
      // Wait for block frames to render (up to 15s)
      try {
        await this.page.waitForSelector('.blockFrame', { timeout: 15_000 });
      } catch {
        // No extensions loaded, or panel didn't open
        return out;
      }
      await new Promise(r => setTimeout(r, 2000)); // let all frames settle

      const extensions = await this.page.evaluate(() => {
        var frames = document.querySelectorAll('.blockFrame');
        var results: any[] = [];
        frames.forEach(function(frame) {
          // Extension name
          var nameEl = frame.querySelector('.truncate.no-user-select');
          var name = nameEl ? nameEl.textContent?.trim() || '' : '';
          // Installation ID
          var installEl = frame.querySelector('[data-blockinstallationid]');
          var installId = installEl ? installEl.getAttribute('data-blockinstallationid') || '' : '';
          // Block ID from iframe src
          var iframe = frame.querySelector('iframe[src]');
          var blockId = '';
          if (iframe) {
            var src = iframe.getAttribute('src') || '';
            var match = src.match(/blockId=([a-zA-Z0-9]+)/);
            if (match) blockId = match[1];
          }
          results.push({ extensionName: name, blockInstallationId: installId, blockId: blockId });
        });
        return results;
      });

      // Check for scripting extensions (name contains "script" or known scripting block IDs)
      for (const ext of extensions) {
        const lower = (ext.extensionName || '').toLowerCase();
        ext.isScripting = lower.includes('script') || lower.includes('custom code');
        ext.scriptCode = null;

        // If it's a scripting extension, try to click into it and grab the code
        if (ext.isScripting && ext.blockInstallationId) {
          try {
            // Click the extension name to focus/open it
            const nameEl = await this.page.$(`[data-blockinstallationid="${ext.blockInstallationId}"]`);
            if (nameEl) {
              await nameEl.click();
              await new Promise(r => setTimeout(r, 2000));
              // Try to get code from CodeMirror editor
              const code = await this.page.evaluate(() => {
                // CodeMirror 6
                var cm = document.querySelector('.cm-content');
                if (cm) return cm.textContent || '';
                // Monaco
                var monaco = document.querySelector('.monaco-editor .view-lines');
                if (monaco) return monaco.textContent || '';
                // Fallback: any textarea in the focused block
                var ta = document.querySelector('.blockFrame textarea');
                if (ta) return (ta as HTMLTextAreaElement).value || '';
                return null;
              });
              if (code) ext.scriptCode = code;
            }
          } catch {
            // Non-fatal: could not extract script code
          }
        }
      }

      out.extensions = extensions;
      console.log(`[engine-session] Extensions for ${appId}: ${extensions.length} found, ${extensions.filter((e: any) => e.isScripting).length} scripting`);
    } catch (err: any) {
      out.errors.push(`Extensions scrape ${appId}: ${err.message}`);
    }
    return out;
  }

  static extractAdminUsers(enterpriseData: any): any[] {
    if (!enterpriseData?.users) return [];
    return (enterpriseData.users || []).map((u: any) => ({
      userId: u.id || u.userId || '',
      email: u.email || '',
      displayName: u.name || u.displayName || null,
      role: u.seatType || u.role || null,
      status: u.state || u.status || null,
      lastActiveAt: u.lastActivityTime || null,
      createdAtSource: u.createdTime || null,
      twoFa: u.isTwoFactorAuthEnabled ?? null,
    }));
  }

  // ---------------------------------------------------------------------------
  // Extract billing snapshot from enterprise data (already collected)
  // ---------------------------------------------------------------------------

  static extractBillingSnapshot(enterpriseData: any, workspaceData: any): any | null {
    const billing = enterpriseData?.billing;
    const license = enterpriseData?.licenseSummary;
    const wsPlan = workspaceData?.billingPlan;
    if (!billing && !license && !wsPlan) return null;

    return {
      plan: wsPlan?.name || wsPlan?.grouping || null,
      paidSeats: license?.totalPaidSeats || license?.aggregateUserLicenseCount || null,
      addons: workspaceData?.billingAddOnIds || null,
      nextInvoiceAmount: billing?.nextInvoiceAmount ?? null,
      nextInvoiceDate: billing?.nextInvoiceDate || null,
      billingCycle: billing?.billingCycle || billing?.billingInterval || null,
      businessName: billing?.businessName || billing?.companyName || null,
      billingContact: billing?.billingContactEmail || null,
      invoiceHistory: billing?.invoices || billing?.invoiceHistory || null,
    };
  }

  // ---------------------------------------------------------------------------
  // Private: enterprise data collection
  // ---------------------------------------------------------------------------

  private async collectEnterpriseData(entId: string): Promise<Record<string, any>> {
    const ent: Record<string, any> = {
      enterpriseAccountId: entId,
      users:               null,
      userDetails:         null,
      userGroups:          null,
      enterpriseSettings:  null,
      licenseSummary:      null,
      roles:               null,
      pendingInvites:      null,
      workspaces:          null,
      shadowWorkspaces:    null,
      bases:               null,
      interfaces:          null,
      billing:             null,
      errors:              [] as string[],
    };

    // Pre-flight: getUsersWithSearch (first page only to test admin access)
    try {
      const params = JSON.stringify({ includeDescendantEnterpriseAccounts: false, filters: { state: 'active' }, offset: 0, limit: 50 });
      const data = await this.fetchInternalApi(
        `/v0.3/enterpriseAccount/${entId}/getUsersWithSearch?stringifiedObjectParams=${encodeURIComponent(params)}`,
      );
      const firstPageUsers = data?.data?.userAccounts || [];
      const aggregateCount = data?.data?.aggregateUserLicenseCount ?? 0;

      if (!data || (!firstPageUsers.length && !aggregateCount)) {
        ent.noAdminAccess = true;
        ent.errors.push('Enterprise admin pre-flight failed: no admin access.');
        console.log(`[engine-session] Enterprise pre-flight FAILED: no admin access`);
        return ent;
      }

      // Collect aggregates
      if (data?.data) {
        ent.userAggregates = {
          totalBasicUsersCount:               data.data.totalBasicUsersCount,
          aggregateUserLicenseCount:          data.data.aggregateUserLicenseCount,
          enterpriseAccountBillingModelType:  data.data.enterpriseAccountBillingModelType,
          enterpriseAccountEmailDomainInfos:  data.data.enterpriseAccountEmailDomainInfos,
        };
      }

      // Paginate all users
      const allUsers: any[] = [...firstPageUsers];
      let offset = 50;
      const limit = 50;
      let hasMore = firstPageUsers.length === limit;
      while (hasMore) {
        const pageParams = JSON.stringify({ includeDescendantEnterpriseAccounts: false, filters: { state: 'active' }, offset, limit });
        const pageData = await this.fetchInternalApi(
          `/v0.3/enterpriseAccount/${entId}/getUsersWithSearch?stringifiedObjectParams=${encodeURIComponent(pageParams)}`,
        );
        const users = pageData?.data?.userAccounts || [];
        allUsers.push(...users);
        hasMore = users.length === limit;
        offset += limit;
      }
      ent.users = allUsers;
      console.log(`[engine-session] Enterprise users: ${allUsers.length}`);

      // getUserAccountDetails for every user (PATs, workspace access, API restriction)
      console.log(`[engine-session] Fetching user account details for ${allUsers.length} users...`);
      const userDetails: Record<string, any> = {};
      for (const user of allUsers) {
        const uid = user.id || user.userId;
        if (!uid) continue;
        try {
          const detailParams = JSON.stringify({ userId: uid, shouldFetchPageBundles: true });
          const detail = await this.fetchInternalApi(
            `/v0.3/enterpriseAccount/${entId}/getUserAccountDetails?stringifiedObjectParams=${encodeURIComponent(detailParams)}`,
          );
          if (detail?.data) {
            userDetails[uid] = {
              workspaceInfos:        detail.data.workspaceInfos || [],
              sharedApplicationInfos: detail.data.sharedApplicationInfos || [],
              sharedPageBundleInfos:  detail.data.sharedPageBundleInfos || [],
              userGroups:            detail.data.userGroups || [],
              maximalUserApiScopes:  detail.data.maximalUserApiScopes || [],
              isApiAccessDisabled:   detail.data.isApiAccessDisabledForUserDueToEnterpriseRestriction || false,
              personalAccessTokens:  detail.data.personalAccessTokens || [],
              oauthAccessTokens:     detail.data.oauthAccessTokens || [],
            };
          }
        } catch (err: any) {
          console.warn(`[engine-session] getUserAccountDetails failed for ${uid}: ${err.message}`);
        }
      }
      ent.userDetails = userDetails;
      console.log(`[engine-session] User account details collected for ${Object.keys(userDetails).length} users`);

    } catch (err: any) {
      ent.errors.push(`getUsersWithSearch: ${err.message}`);
      ent.noAdminAccess = true;
      return ent;
    }

    // getEnterpriseSettings (full set of settings)
    try {
      const settingKeys = [
        'emailDomainVerification', 'cidrRestriction', 'webSessionDuration',
        'mfaPolicy', 'ssoConfig', 'hipaaCompliance', 'ekm', 'dataResidency',
        'sensitivityLabels', 'personalAccessTokenMaxLifetime', 'dataLossPrevention',
        'oauthRestriction', 'sharingRestrictions', 'aiSettings',
        'scimProvisioning', 'inviteRestrictions',
      ];
      const params = JSON.stringify({ settings: settingKeys });
      const data = await this.fetchInternalApi(
        `/v0.3/enterpriseAccount/${entId}/getEnterpriseSettings?stringifiedObjectParams=${encodeURIComponent(params)}`,
      );
      ent.enterpriseSettings = data?.data || data;
      console.log(`[engine-session] Enterprise settings OK`);
    } catch (err: any) {
      ent.errors.push(`getEnterpriseSettings: ${err.message}`);
    }

    // getLicenseSummary
    try {
      const params = JSON.stringify({ includeDescendants: false });
      const data = await this.fetchInternalApi(
        `/v0.3/enterpriseAccount/${entId}/getLicenseSummary?stringifiedObjectParams=${encodeURIComponent(params)}`,
      );
      ent.licenseSummary = data?.data || data;
      console.log(`[engine-session] License summary OK`);
    } catch (err: any) {
      ent.errors.push(`getLicenseSummary: ${err.message}`);
    }

    // getRoles
    try {
      const params = JSON.stringify({ shouldIncludeDescendantEnterpriseAccounts: false });
      const data = await this.fetchInternalApi(
        `/v0.3/enterpriseAccount/${entId}/getRoles?stringifiedObjectParams=${encodeURIComponent(params)}`,
      );
      ent.roles = data?.data || data;
      console.log(`[engine-session] Roles OK`);
    } catch (err: any) {
      ent.errors.push(`getRoles: ${err.message}`);
    }

    // getPendingInviteesInfo
    try {
      const params = JSON.stringify({ membershipCaptureType: 'none', shouldIncludeDescendantEnterpriseAccountsPendingInvites: false, shouldExcludeClaimListUserGroups: false });
      const data = await this.fetchInternalApi(
        `/v0.3/enterpriseAccount/${entId}/getPendingInviteesInfo?stringifiedObjectParams=${encodeURIComponent(params)}`,
      );
      ent.pendingInvites = data?.data || data;
      console.log(`[engine-session] Pending invites OK`);
    } catch (err: any) {
      ent.errors.push(`getPendingInviteesInfo: ${err.message}`);
    }

    // getWorkspaces (includes workspace ownership and AI settings)
    try {
      const params = JSON.stringify({ shouldIncludeDescendantEnterpriseAccounts: false, shouldIncludeInternalWorkspaces: true });
      const data = await this.fetchInternalApi(
        `/v0.3/enterpriseAccount/${entId}/getWorkspaces?stringifiedObjectParams=${encodeURIComponent(params)}`,
      );
      ent.workspaces = data?.data || data;
      console.log(`[engine-session] Workspaces OK`);
    } catch (err: any) {
      ent.errors.push(`getWorkspaces: ${err.message}`);
    }

    // getMemberOwnedNonEnterpriseWorkspaces (shadow/personal workspaces outside the org)
    try {
      const params = JSON.stringify({ includeDescendantEnterpriseAccounts: false });
      const data = await this.fetchInternalApi(
        `/v0.3/enterpriseAccount/${entId}/getMemberOwnedNonEnterpriseWorkspaces?stringifiedObjectParams=${encodeURIComponent(params)}`,
      );
      ent.shadowWorkspaces = data?.data || data;
      console.log(`[engine-session] Shadow workspaces OK`);
    } catch (err: any) {
      ent.errors.push(`getMemberOwnedNonEnterpriseWorkspaces: ${err.message}`);
    }

    // getUserGroupsWithMembers
    try {
      const params = JSON.stringify({ shouldFetchGroupMembers: true });
      const data = await this.fetchInternalApi(
        `/v0.3/enterpriseAccount/${entId}/getUserGroupsWithMembers?stringifiedObjectParams=${encodeURIComponent(params)}`,
      );
      ent.userGroups = data?.data || data;
      console.log(`[engine-session] User groups OK`);
    } catch (err: any) {
      ent.errors.push(`getUserGroupsWithMembers: ${err.message}`);
    }

    // getApplications (all bases with record counts and creation dates)
    try {
      const params = JSON.stringify({ shouldIncludeDescendantEnterpriseAccounts: false });
      const data = await this.fetchInternalApi(
        `/v0.3/enterpriseAccount/${entId}/getApplications?stringifiedObjectParams=${encodeURIComponent(params)}`,
      );
      ent.bases = data?.data || data;
      console.log(`[engine-session] Applications (bases) OK`);
    } catch (err: any) {
      ent.errors.push(`getApplications: ${err.message}`);
    }

    // getPageBundles (interfaces)
    try {
      const params = JSON.stringify({ shouldIncludeDescendantEnterpriseAccounts: false });
      const data = await this.fetchInternalApi(
        `/v0.3/enterpriseAccount/${entId}/getPageBundles?stringifiedObjectParams=${encodeURIComponent(params)}`,
      );
      ent.interfaces = data?.data || data;
      console.log(`[engine-session] Page bundles (interfaces) OK`);
    } catch (err: any) {
      ent.errors.push(`getPageBundles: ${err.message}`);
    }

    // getEnterpriseBillingInfoForAdminPanel
    try {
      const params = JSON.stringify({});
      const data = await this.fetchInternalApi(
        `/v0.3/enterpriseAccount/${entId}/getEnterpriseBillingInfoForAdminPanel?stringifiedObjectParams=${encodeURIComponent(params)}`,
      );
      ent.billing = data?.data || data;
      console.log(`[engine-session] Billing info OK`);
    } catch (err: any) {
      ent.errors.push(`getEnterpriseBillingInfoForAdminPanel: ${err.message}`);
    }

    return ent;
  }

  private extractEnterpriseId(wsSettings: any): string | null {
    if (!wsSettings) return null;
    // Check billingPlansForPricingPage for enterpriseAccounts
    const plans = wsSettings.workspaceData?.billingPlansForPricingPage || [];
    for (const plan of plans) {
      const accounts = plan.enterpriseAccounts || [];
      for (const acc of accounts) {
        if (acc.enterpriseAccountId) return acc.enterpriseAccountId;
      }
    }
    // Also check the main billing plan
    const mainPlan = wsSettings.workspaceData?.billingPlan;
    if (mainPlan?.enterpriseAccountId) return mainPlan.enterpriseAccountId;
    return null;
  }

  // ---------------------------------------------------------------------------
  // Private: shared helpers
  // ---------------------------------------------------------------------------

  /** Resolve workspace ID from the current page's HTML */
  private async resolveWorkspaceId(baseId: string): Promise<string | null> {
    // Return cached result immediately -- no navigation needed
    if (this.workspaceCache.has(baseId)) {
      const cached = this.workspaceCache.get(baseId)!;
      console.log(`[engine-session] Workspace ID from cache: ${cached}`);
      return cached;
    }

    // Also check if any cached workspace already knows this base
    // (won't happen here but defensive)

    // Navigate to the automations page (known to fully bootstrap the app shell)
    await this.page.goto(`https://airtable.com/${baseId}/automations`, {
      waitUntil: 'domcontentloaded',
      timeout: 90_000,
    });
    await new Promise((r) => setTimeout(r, 5000));

    let wspId = await this.page.evaluate((targetBaseId: string) => {
      const html = document.documentElement.innerHTML;

      // Strategy 1: find workspaceId JSON key near the base's applicationId
      // This is the most reliable as it finds the workspace specifically for this base
      const baseIdx = html.indexOf(targetBaseId);
      if (baseIdx !== -1) {
        // Search in a window around the base ID for the associated workspace
        const chunk = html.substring(Math.max(0, baseIdx - 3000), Math.min(html.length, baseIdx + 3000));
        const wspMatch = chunk.match(/"workspaceId"\s*:\s*"(wsp[a-zA-Z0-9]+)"/);
        if (wspMatch && wspMatch[1] !== 'wspSHARED00000000') {
          return wspMatch[1];
        }
      }

      // Strategy 2: look for workspaceId in JSON context (not just raw regex)
      const jsonMatches = html.matchAll(/"workspaceId"\s*:\s*"(wsp[a-zA-Z0-9]+)"/g);
      const candidates: string[] = [];
      for (const m of jsonMatches) {
        if (m[1] !== 'wspSHARED00000000') candidates.push(m[1]);
      }
      // If all JSON-based workspaceId values point to the same workspace, use it
      const unique = [...new Set(candidates)];
      if (unique.length === 1) return unique[0];

      // Strategy 3: find the workspace ID that appears most often (likely the current one)
      if (unique.length > 1) {
        const counts: Record<string, number> = {};
        for (const c of candidates) { counts[c] = (counts[c] || 0) + 1; }
        const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
        return sorted[0][0];
      }

      // Strategy 4: brute force - find all wsp IDs, pick the most frequent non-SHARED one
      const allMatches = html.match(/wsp[a-zA-Z0-9]{10,}/g) || [];
      const real = allMatches.filter(m => m !== 'wspSHARED00000000');
      if (real.length > 0) {
        const freq: Record<string, number> = {};
        for (const w of real) { freq[w] = (freq[w] || 0) + 1; }
        const sorted = Object.entries(freq).sort((a, b) => b[1] - a[1]);
        return sorted[0][0];
      }

      return null;
    }, baseId);

    if (wspId) {
      console.log(`[engine-session] Workspace ID resolved: ${wspId}`);
      this.workspaceCache.set(baseId, wspId);
      return wspId;
    }

    // Last resort: home page
    console.log('[engine-session] Trying home page...');
    await this.page.goto('https://airtable.com/', { waitUntil: 'networkidle', timeout: 30_000 });
    await new Promise((r) => setTimeout(r, 3000));
    wspId = await this.page.evaluate((bid: string) => {
      const html = document.documentElement.innerHTML;
      const idx = html.indexOf(bid);
      if (idx === -1) return null;
      const chunk = html.substring(Math.max(0, idx - 2000), Math.min(html.length, idx + 2000));
      const m = chunk.match(/(wsp[a-zA-Z0-9]{10,})/);
      return m && m[1] !== 'wspSHARED00000000' ? m[1] : null;
    }, baseId);

    if (wspId) {
      console.log(`[engine-session] Workspace ID from home page: ${wspId}`);
      this.workspaceCache.set(baseId, wspId);
    } else {
      console.log('[engine-session] Could not resolve workspace ID from any page');
    }
    return wspId;
  }

  /** Generic internal API fetcher via page.evaluate (same-origin, session cookies) */
  private async fetchInternalApi(path: string, appId?: string, timeoutMs = 90_000): Promise<any> {
    console.log(`[engine-session] fetchInternalApi: ${path.substring(0, 80)}...`);
    const arg = JSON.stringify({ url: path, aid: appId || "" });

    const fetchPromise = this.page.evaluate(async (argStr) => {
      var parsed = JSON.parse(argStr);
      try {
        var res = await fetch(parsed.url, {
          headers: {
            'x-airtable-inter-service-client': 'webClient',
            'x-requested-with': 'XMLHttpRequest',
            'x-time-zone': 'UTC',
            'accept': 'application/json',
            ...(parsed.aid ? {'x-airtable-application-id': parsed.aid} : {}),
          },
        });
        if (!res.ok) {
          var errBody = ''; try { errBody = await res.text(); } catch(e) {} return { __error: true, status: res.status, body: errBody.slice(0,300), url: parsed.url };
        }
        return await res.json();
      } catch (e: any) {
        return { __error: true, message: e.message, url: parsed.url };
      }
    }, arg);

    const timeoutPromise = new Promise<{ __error: true; message: string; url: string }>((resolve) =>
      setTimeout(() => resolve({ __error: true, message: `fetchInternalApi timed out after ${timeoutMs / 1000}s`, url: path }), timeoutMs),
    );

    const result = await Promise.race([fetchPromise, timeoutPromise]);

    if (result?.__error) {
      console.error(`[engine-session] fetchInternalApi FAILED: ${JSON.stringify(result)}`);
      return null;
    }
    return result;
  }

  // ---------------------------------------------------------------------------
  // Public
  // ---------------------------------------------------------------------------

  async collectBase(appId: string): Promise<CollectedBase> {
    // Navigate to the automations tab so Airtable bootstraps its full app
    // context -- required before the internal API will respond correctly.
    await this.page.goto(`https://airtable.com/${appId}/automations`, {
      waitUntil: 'domcontentloaded',
      timeout: 90_000,
    });
    await new Promise((r) => setTimeout(r, 3000));

    const workflows = await this.fetchListWorkflows(appId);
    const automations: CollectedAutomation[] = [];

    for (const wf of workflows) {
      automations.push(await this.processWorkflow(wf, appId));
    }

    return { appId, collectedAt: new Date().toISOString(), automations };
  }

  // ---------------------------------------------------------------------------
  // Private: API calls
  // ---------------------------------------------------------------------------

  private makeHeaders(appId: string): Record<string, string> {
    return {
      'x-airtable-inter-service-client':              'webClient',
      'x-airtable-application-id':                    appId,
      'x-requested-with':                             'XMLHttpRequest',
      'x-user-locale':                                'en',
      'x-time-zone':                                  'Europe/Brussels',
      'accept':                                       'application/json, text/javascript, */*; q=0.01',
    };
  }

  private async fetchListWorkflows(appId: string): Promise<any[]> {
    const result = await this.page.evaluate(
      async ({ appId, headers }: { appId: string; headers: Record<string, string> }) => {
        const res = await fetch(
          `/v0.3/application/${appId}/listWorkflows?stringifiedObjectParams=%7B%7D`,
          { credentials: 'include', headers },
        );
        if (!res.ok) {
          const body = await res.text().catch(() => '');
          throw new Error(`listWorkflows HTTP ${res.status}: ${body.slice(0, 200)}`);
        }
        return res.json();
      },
      { appId, headers: this.makeHeaders(appId) },
    );
    return result?.data?.workflows ?? [];
  }

  private async fetchDeployment(wfdId: string, appId: string): Promise<any | null> {
    const raw = await this.fetchRawDeployment(wfdId, appId);
    return raw?.workflowDefinition ?? null;
  }

  private async fetchRawDeployment(wfdId: string, appId: string): Promise<any | null> {
    const result = await this.page.evaluate(
      async ({ wfdId, headers }: { wfdId: string; headers: Record<string, string> }) => {
        const res = await fetch(
          `/v0.3/workflowDeployment/${wfdId}/read?stringifiedObjectParams=%7B%7D`,
          { credentials: 'include', headers },
        );
        if (!res.ok) throw new Error(`workflowDeployment/read HTTP ${res.status}`);
        return res.json();
      },
      { wfdId, headers: this.makeHeaders(appId) },
    );
    return result?.data?.workflowDeployment ?? null;
  }

  // ---------------------------------------------------------------------------
  // Private: parsing
  // ---------------------------------------------------------------------------

  private async processWorkflow(wf: any, appId: string): Promise<CollectedAutomation> {
    const deploymentId: string | null = wf.targetWorkflowDeploymentId ?? null;
    const triggerTypeId: string        = wf.trigger?.workflowTriggerTypeId ?? '';
    const allNodes                     = this.walkAllActions(wf.graph ?? {});
    const scriptNodes                  = allNodes.filter(
      (n) => n.workflowActionTypeId === 'watCUSTOMSCRIPT00',
    );
    const actionTypes = [
      ...new Set(
        allNodes.map((n) =>
          this.labelAction(n.workflowActionTypeId ?? n.workflowDecisionTypeId ?? ''),
        ),
      ),
    ];

    const result: CollectedAutomation = {
      workflowId:       wf.id ?? null,
      deploymentId,
      name:             wf.name ?? null,
      deploymentStatus: wf.deploymentStatus ?? null,
      triggerTypeId,
      trigger:          this.triggerLabel(triggerTypeId),
      triggerConfig:    this.extractTriggerConfig(wf.trigger),
      stepCount:        allNodes.length,
      actionTypes,
      scriptSources:    [],
      createdByUserId:  null,
      deploymentCreatedTime: null,
    };

    // Fetch script bodies + authorship -- one deployment read per automation
    if (deploymentId) {
      try {
        const rawDeployment = await this.fetchRawDeployment(deploymentId, appId);
        // Authorship from the deployment wrapper
        result.createdByUserId = rawDeployment?.createdByUserId ?? null;
        result.deploymentCreatedTime = rawDeployment?.createdTime ?? null;

        const definition = rawDeployment?.workflowDefinition ?? null;
        if (definition && scriptNodes.length > 0) {
          const deployedById: Record<string, any> = definition?.graph?.actionsById ?? {};

          scriptNodes.forEach((node, i) => {
            const deployed =
              deployedById[node.id] ??
              Object.values(deployedById).find(
                (a: any) => a.workflowActionTypeId === 'watCUSTOMSCRIPT00',
              );
            const code: string = deployed?.inputExpressions?.script?.value ?? '';
            result.scriptSources.push({
              actionId:   node.id,
              stepIndex:  i,
              actionType: node.workflowActionTypeId ?? 'unknown',
              lines:      code ? code.split('\n').length : 0,
              code,
            });
          });
        }
      } catch (err: any) {
        result.error = `deployment fetch failed: ${err.message}`;
      }
    }

    // DOM scrape fallback for undeployed automations with script actions
    if (scriptNodes.length > 0 && !deploymentId && wf.id) {
      try {
        const code = await scrapeUndeployedScript(this.page, appId, wf.id, wf.name ?? wf.id);
        if (code) {
          result.scriptSources.push({
            actionId:   scriptNodes[0].id,
            stepIndex:  0,
            actionType: 'watCUSTOMSCRIPT00',
            lines:      code.split('\n').length,
            code,
          });
        }
      } catch (err: any) {
        console.error(`[engine-session] DOM scrape failed for ${wf.name}: ${err.message}`);
      }
    }

    return result;
  }

  // BFS walk -- visits all branches, not just the linear chain
  private walkAllActions(graph: any): any[] {
    const byId: Record<string, any> = graph?.actionsById ?? {};
    const visited = new Set<string>();
    const queue: string[] = [graph?.entryWorkflowActionId].filter(Boolean);
    const nodes: any[] = [];

    while (queue.length) {
      const id = queue.shift()!;
      if (!id || visited.has(id)) continue;
      visited.add(id);
      const node = byId[id];
      if (!node) continue;
      nodes.push(node);
      if (node.nextWorkflowNodeIds?.length) queue.push(...node.nextWorkflowNodeIds);
      if (node.nextWorkflowActionId) queue.push(node.nextWorkflowActionId);
    }

    // Append any orphans not reachable from entry (defensive)
    for (const id of Object.keys(byId)) {
      if (!visited.has(id)) nodes.push(byId[id]);
    }

    return nodes;
  }

  triggerLabel(typeId: string | null): string {
    return typeId ? (TRIGGER_LABELS[typeId] ?? typeId) : 'unknown';
  }

  /** Extract useful config from the trigger object (connection name, table, schedule, etc.) */
  private extractTriggerConfig(trigger: any): Record<string, any> | null {
    if (!trigger) return null;
    const cfg: Record<string, any> = {};
    // Connection/app info (for connected app triggers and actions)
    if (trigger.connectionId)   cfg.connectionId   = trigger.connectionId;
    if (trigger.connectionName) cfg.connectionName  = trigger.connectionName;
    if (trigger.appName)        cfg.appName         = trigger.appName;
    // Table reference
    if (trigger.tableId)        cfg.tableId         = trigger.tableId;
    // Cron/schedule
    if (trigger.cronExpression) cfg.cronExpression  = trigger.cronExpression;
    if (trigger.timezone)       cfg.timezone        = trigger.timezone;
    // Webhook
    if (trigger.webhookUrl)     cfg.webhookUrl      = trigger.webhookUrl;
    // Capture any inputExpressions keys (field names used in trigger config)
    if (trigger.inputExpressions && typeof trigger.inputExpressions === 'object') {
      cfg.inputExpressionKeys = Object.keys(trigger.inputExpressions);
    }
    // If no specific keys matched, capture all top-level keys for discovery
    if (Object.keys(cfg).length === 0) {
      const topKeys = Object.keys(trigger).filter(k =>
        k !== 'workflowTriggerTypeId' && trigger[k] !== null && trigger[k] !== undefined,
      );
      if (topKeys.length > 0) {
        cfg._rawKeys = topKeys;
        // Capture scalar values for discovery (skip large objects)
        for (const k of topKeys) {
          const v = trigger[k];
          if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') {
            cfg[k] = v;
          }
        }
      }
    }
    return Object.keys(cfg).length > 0 ? cfg : null;
  }

  actionLabel(typeId: string): string {
    return ACTION_LABELS[typeId] ?? typeId;
  }

  private labelAction(typeId: string): string {
    return ACTION_LABELS[typeId] ?? typeId;
  }
}
