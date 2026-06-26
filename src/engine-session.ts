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
  stepCount:        number;
  actionTypes:      string[];
  scriptSources:    ScriptSource[];
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

  /**
   * Start using a persistent browser profile.
   * If the profile is already logged in, continues immediately.
   * If not, opens headful and waits for the operator to log in (up to 5 min).
   */
  async start(profileDir: string, headless = false): Promise<void> {
    this.context = await chromium.launchPersistentContext(profileDir, { headless: false });
    this.page = await this.context.newPage();
    await this.page.goto('https://airtable.com/login', { waitUntil: 'domcontentloaded' });
    await this.ensureLoggedIn();
    // If headless was requested and we're already logged in, relaunch headless
    if (headless) {
      await this.context.close();
      this.context = await chromium.launchPersistentContext(profileDir, { headless: true });
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


  // Start headless using an already-logged-in persistent profile (no login wait)
  async startHeadless(profileDir: string): Promise<void> {
    this.context = await chromium.launchPersistentContext(profileDir, { headless: true });
    this.page    = await this.context.newPage();
  }

  async stop(): Promise<void> {
    await this.context?.close();
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
      // Step 1: resolve workspace ID (navigates to base page internally)
      console.log(`[engine-session] Resolving workspace for base ${baseId}...`);
      const wspId = await this.resolveWorkspaceId(baseId);

      if (!wspId) {
        result.error = 'Could not resolve workspace ID for base';
        return result;
      }
      result.workspaceId = wspId;
      console.log(`[engine-session] Resolved workspace: ${result.workspaceId}`);

      // Step 3: call the internal workspaceSettings API via page.evaluate
      const wsData = await this.fetchInternalApi(`/v0.3/${wspId}/workspace/workspaceSettings`);
      if (!wsData) {
        result.error = 'workspaceSettings API returned no data';
        return result;
      }

      // Step 4: parse the response
      result.workspaceName = wsData.workspaceData?.workspaceName || null;

      const breakdown = wsData.workspaceData?.billableUserBreakdown;
      if (!breakdown) {
        result.error = 'No billableUserBreakdown in workspaceSettings response';
        return result;
      }

      const profiles: Record<string, { id: string; name: string; email: string }> =
        breakdown.billableUserProfileInfoById || {};

      const wsPerms: Record<string, string> = {};
      for (const wc of breakdown.workspaceCollaborators || []) {
        wsPerms[wc.userId] = wc.permissionLevel;
      }

      const appPerms: Record<string, Array<{ applicationId: string; permissionLevel: string }>> = {};
      for (const ac of breakdown.applicationCollaborators || []) {
        if (!appPerms[ac.userId]) appPerms[ac.userId] = [];
        appPerms[ac.userId].push({ applicationId: ac.applicationId, permissionLevel: ac.permissionLevel });
      }

      for (const [userId, profile] of Object.entries(profiles)) {
        const wspPerm = wsPerms[userId] || null;
        const baseAccess = (appPerms[userId] || [])
          .filter((a) => a.applicationId === baseId)
          .map((a) => a.permissionLevel);

        result.collaborators.push({
          userId,
          email:           profile.email,
          name:            profile.name,
          permissionLevel: wspPerm || baseAccess[0] || null,
          source:          wspPerm ? 'workspace' : 'base',
        });
      }

      (result as any).workspacePlan = wsData.workspaceData?.billingPlan?.name || null;
      (result as any).workspacePlanGrouping = wsData.workspaceData?.billingPlan?.grouping || null;
      (result as any).totalBillable = breakdown.numTotalBillableCollaborators || 0;
      (result as any).totalNonBillable = breakdown.numTotalNonBillableCollaborators || 0;

      console.log(`[engine-session] Found ${result.collaborators.length} collaborator(s) via workspaceSettings API`);
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

        // workspaceSettings (full response, not just collaborator breakdown)
        const wsSettings = await this.fetchInternalApi(`/v0.3/${wspId}/workspace/workspaceSettings`);
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
        waitUntil: 'networkidle',
        timeout: 60_000,
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
      return data?.data?.executions || data?.executions || [];
    } catch {
      return [];
    }
  }

  // ---------------------------------------------------------------------------
  // Private: enterprise data collection
  // ---------------------------------------------------------------------------

  private async collectEnterpriseData(entId: string): Promise<Record<string, any>> {
    const ent: Record<string, any> = {
      enterpriseAccountId: entId,
      users:               null,
      enterpriseSettings:  null,
      licenseSummary:      null,
      roles:               null,
      pendingInvites:      null,
      workspaces:          null,
      errors:              [] as string[],
    };

    // getUsersWithSearch (paginated, get all active users)
    try {
      const allUsers: any[] = [];
      let offset = 0;
      const limit = 50;
      let hasMore = true;
      while (hasMore) {
        const params = JSON.stringify({ includeDescendantEnterpriseAccounts: false, filters: { state: 'active' }, offset, limit });
        const data = await this.fetchInternalApi(
          `/v0.3/enterpriseAccount/${entId}/getUsersWithSearch?stringifiedObjectParams=${encodeURIComponent(params)}`,
        );
        const users = data?.data?.userAccounts || [];
        allUsers.push(...users);
        // Also capture aggregate data from first page
        if (offset === 0 && data?.data) {
          ent.userAggregates = {
            totalBasicUsersCount: data.data.totalBasicUsersCount,
            aggregateUserLicenseCount: data.data.aggregateUserLicenseCount,
            enterpriseAccountBillingModelType: data.data.enterpriseAccountBillingModelType,
            enterpriseAccountEmailDomainInfos: data.data.enterpriseAccountEmailDomainInfos,
          };
        }
        hasMore = users.length === limit;
        offset += limit;
      }
      ent.users = allUsers;
      console.log(`[engine-session] Enterprise users: ${allUsers.length}`);
    } catch (err: any) {
      ent.errors.push(`getUsersWithSearch: ${err.message}`);
    }

    // getEnterpriseSettings
    try {
      const params = JSON.stringify({});
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

    // getWorkspaces
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
    // Navigate to the automations page (known to fully bootstrap the app shell)
    await this.page.goto(`https://airtable.com/${baseId}/automations`, {
      waitUntil: 'networkidle',
      timeout: 60_000,
    });
    await new Promise((r) => setTimeout(r, 5000));

    let wspId = await this.page.evaluate(() => {
      const html = document.documentElement.innerHTML;
      // Find all wsp IDs, filter out the shared placeholder
      const matches = html.match(/wsp[a-zA-Z0-9]{10,}/g) || [];
      const real = matches.filter(m => m !== 'wspSHARED00000000');
      return real.length > 0 ? real[0] : null;
    });

    if (wspId) {
      console.log(`[engine-session] Workspace ID from automations page: ${wspId}`);
      return wspId;
    }

    // Fallback: try the base page directly
    console.log('[engine-session] No workspace ID on automations page, trying base page...');
    await this.page.goto(`https://airtable.com/${baseId}`, {
      waitUntil: 'networkidle',
      timeout: 30_000,
    });
    await new Promise((r) => setTimeout(r, 5000));

    wspId = await this.page.evaluate(() => {
      const html = document.documentElement.innerHTML;
      const matches = html.match(/wsp[a-zA-Z0-9]{10,}/g) || [];
      const real = matches.filter(m => m !== 'wspSHARED00000000');
      return real.length > 0 ? real[0] : null;
    });

    if (wspId) {
      console.log(`[engine-session] Workspace ID from base page: ${wspId}`);
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
      return m ? m[1] : null;
    }, baseId);

    if (wspId) console.log(`[engine-session] Workspace ID from home page: ${wspId}`);
    else console.log('[engine-session] Could not resolve workspace ID from any page');

    return wspId;
  }

  /** Generic internal API fetcher via page.evaluate (same-origin, session cookies) */
  private async fetchInternalApi(path: string): Promise<any> {
    const result = await this.page.evaluate(async (url: string) => {
      try {
        const res = await fetch(url, {
          headers: {
            'x-airtable-inter-service-client': 'webClient',
            'x-requested-with': 'XMLHttpRequest',
          },
        });
        if (!res.ok) return null;
        return await res.json();
      } catch {
        return null;
      }
    }, path);
    return result;
  }

  // ---------------------------------------------------------------------------
  // Public
  // ---------------------------------------------------------------------------

  async collectBase(appId: string): Promise<CollectedBase> {
    // Navigate to the automations tab so Airtable bootstraps its full app
    // context -- required before the internal API will respond correctly.
    await this.page.goto(`https://airtable.com/${appId}/automations`, {
      waitUntil: 'networkidle',
      timeout: 60_000,
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
    // Confirmed shape: data.workflowDeployment.workflowDefinition
    return result?.data?.workflowDeployment?.workflowDefinition ?? null;
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
      stepCount:        allNodes.length,
      actionTypes,
      scriptSources:    [],
    };

    // Fetch script bodies -- one deployment read per automation
    if (scriptNodes.length > 0 && deploymentId) {
      try {
        const definition = await this.fetchDeployment(deploymentId, appId);
        const deployedById: Record<string, any> = definition?.graph?.actionsById ?? {};

        scriptNodes.forEach((node, i) => {
          // Match by ID; fall back to first script action found in deployment
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
      } catch (err: any) {
        result.error = `script fetch failed: ${err.message}`;
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

  actionLabel(typeId: string): string {
    return ACTION_LABELS[typeId] ?? typeId;
  }

  private labelAction(typeId: string): string {
    return ACTION_LABELS[typeId] ?? typeId;
  }
}
