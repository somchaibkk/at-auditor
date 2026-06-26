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
  // Collaborator scraping (browser session, works on all plans)
  // ---------------------------------------------------------------------------

  /**
   * Scrape collaborators for a base by navigating to its share/manage UI.
   * Strategy:
   *   1. Navigate to the base (bootstraps the app shell)
   *   2. Use internal API to get the workspace ID for this base
   *   3. Navigate to workspace settings and scrape collaborator list from DOM
   *   4. Fall back to base share dialog if workspace settings are inaccessible
   */
  async scrapeCollaborators(baseId: string): Promise<CollaboratorsResult> {
    const result: CollaboratorsResult = {
      workspaceId:   null,
      workspaceName: null,
      collaborators: [],
    };

    try {
      // Ensure we're on an Airtable page so internal fetches work
      const currentUrl = this.page.url();
      if (!currentUrl.includes('airtable.com') || currentUrl === 'about:blank') {
        await this.page.goto(`https://airtable.com/${baseId}`, {
          waitUntil: 'networkidle',
          timeout: 30_000,
        });
        await new Promise((r) => setTimeout(r, 2000));
      }

      // Step 1: resolve workspace ID via internal API
      const wsInfo = await this.resolveWorkspace(baseId);
      result.workspaceId   = wsInfo.workspaceId;
      result.workspaceName = wsInfo.workspaceName;

      if (!wsInfo.workspaceId) {
        result.error = 'Could not determine workspace ID for base';
        return result;
      }

      // Step 2: try scraping workspace settings page
      const wsCollabs = await this.scrapeWorkspaceSettings(wsInfo.workspaceId);
      if (wsCollabs.length > 0) {
        result.collaborators = wsCollabs.map((c) => ({ ...c, source: 'workspace' as const }));
        console.log(`[engine-session] Found ${wsCollabs.length} workspace collaborator(s)`);
        return result;
      }

      // Step 3: fall back to base share dialog
      console.log('[engine-session] Workspace settings not accessible, trying base share dialog');
      const baseCollabs = await this.scrapeBaseShareDialog(baseId);
      result.collaborators = baseCollabs.map((c) => ({ ...c, source: 'base' as const }));
      console.log(`[engine-session] Found ${baseCollabs.length} base collaborator(s) from share dialog`);

      if (result.collaborators.length === 0) {
        result.error = 'No collaborators found (may lack owner/admin access)';
      }
    } catch (err: any) {
      result.error = `Collaborator scraping failed: ${err.message}`;
      console.error(`[engine-session] ${result.error}`);
    }

    return result;
  }

  private async resolveWorkspace(baseId: string): Promise<{ workspaceId: string | null; workspaceName: string | null }> {
    try {
      // The app shell provides application metadata once we navigate to a base.
      // We can fetch /v0.3/application/{appId}/readForHomepage or similar,
      // but the simplest approach: read from the page's __appConfig or global state.
      await this.page.goto(`https://airtable.com/${baseId}`, {
        waitUntil: 'networkidle',
        timeout: 30_000,
      });
      await new Promise((r) => setTimeout(r, 2000));

      // Try to extract workspace ID from Airtable's client-side state
      const wsInfo = await this.page.evaluate(() => {
        // Airtable stores app state in various global objects.
        // The workspace ID is often in the URL or the sidebar DOM.
        // Check the home/workspace breadcrumb or the sidebar links.
        const links = Array.from(document.querySelectorAll('a[href*="/workspace"]'));
        for (const link of links) {
          const href = (link as HTMLAnchorElement).href || '';
          const match = href.match(/(wsp[a-zA-Z0-9]+)/);
          if (match) {
            return { workspaceId: match[1], workspaceName: (link as HTMLElement).textContent?.trim() || null };
          }
        }

        // Also check the settings gear link pattern
        const settingsLinks = Array.from(document.querySelectorAll('a[href*="workspace/"]'));
        for (const link of settingsLinks) {
          const href = (link as HTMLAnchorElement).href || '';
          const match = href.match(/(wsp[a-zA-Z0-9]+)/);
          if (match) {
            return { workspaceId: match[1], workspaceName: null };
          }
        }

        // Try reading from the page's script tags or inline JSON
        const scripts = Array.from(document.querySelectorAll('script'));
        for (const script of scripts) {
          const text = script.textContent || '';
          const match = text.match(/"workspaceId"\s*:\s*"(wsp[a-zA-Z0-9]+)"/);
          if (match) {
            const nameMatch = text.match(/"workspaceName"\s*:\s*"([^"]+)"/);
            return { workspaceId: match[1], workspaceName: nameMatch?.[1] || null };
          }
        }

        return { workspaceId: null, workspaceName: null };
      });

      if (wsInfo.workspaceId) {
        console.log(`[engine-session] Resolved workspace: ${wsInfo.workspaceId} (${wsInfo.workspaceName || 'unnamed'})`);
        return wsInfo;
      }

      // Last resort: try the account overview page which lists workspaces + bases
      console.log('[engine-session] Trying account overview to find workspace...');
      await this.page.goto('https://airtable.com/account', {
        waitUntil: 'networkidle',
        timeout: 30_000,
      });
      await new Promise((r) => setTimeout(r, 2000));

      const fromAccount = await this.page.evaluate((targetBaseId: string) => {
        // The account page lists workspaces with their bases
        const pageText = document.body.innerText || '';
        const links = Array.from(document.querySelectorAll('a'));
        for (const link of links) {
          const href = link.href || '';
          if (href.includes('/workspace') && href.match(/wsp[a-zA-Z0-9]+/)) {
            // Check if this workspace section contains our base ID
            const section = link.closest('[class*="workspace"], section, div[data-workspace]');
            if (section?.textContent?.includes(targetBaseId) || section?.innerHTML?.includes(targetBaseId)) {
              const match = href.match(/(wsp[a-zA-Z0-9]+)/);
              if (match) return { workspaceId: match[1], workspaceName: link.textContent?.trim() || null };
            }
          }
        }
        return { workspaceId: null, workspaceName: null };
      }, baseId);

      return fromAccount;
    } catch (err: any) {
      console.error(`[engine-session] resolveWorkspace failed: ${err.message}`);
      return { workspaceId: null, workspaceName: null };
    }
  }

  private async scrapeWorkspaceSettings(workspaceId: string): Promise<Omit<CollaboratorInfo, 'source'>[]> {
    try {
      // Navigate to workspace settings page (collaborators section)
      await this.page.goto(`https://airtable.com/${workspaceId}/workspace`, {
        waitUntil: 'networkidle',
        timeout: 30_000,
      });
      await new Promise((r) => setTimeout(r, 3000));

      // Check if we got redirected or blocked (non-owner)
      const url = this.page.url();
      if (url.includes('/login') || url.includes('/signup')) {
        console.log('[engine-session] Redirected to login from workspace settings');
        return [];
      }

      // Look for the "Collaborators" or "Billable collaborators" section
      // and click into it to expand the collaborator list
      const clickedCollabs = await this.page.evaluate(() => {
        const buttons = Array.from(document.querySelectorAll('a, button, [role="button"]'));
        const target = buttons.find((el) => {
          const text = ((el as HTMLElement).textContent || '').toLowerCase();
          return text.includes('collaborator') || text.includes('manage workspace collaborator');
        }) as HTMLElement | undefined;
        if (target) { target.click(); return true; }
        return false;
      });

      if (clickedCollabs) {
        await new Promise((r) => setTimeout(r, 2000));
      }

      // Scrape collaborator entries from the page
      const collabs = await this.page.evaluate(() => {
        const results: Array<{ userId: string | null; email: string | null; name: string | null; permissionLevel: string | null }> = [];

        // Strategy 1: Look for a structured list of collaborators
        // Workspace settings shows collaborators with name, email, and permission
        // in a table-like structure or card layout
        const rows = Array.from(document.querySelectorAll(
          '[data-testid*="collaborator"], [class*="collaborator"], tr, [role="row"]'
        ));

        for (const row of rows) {
          const text = (row as HTMLElement).innerText || '';
          const lines = text.split('\n').map((l: string) => l.trim()).filter(Boolean);

          // Look for email pattern in the row
          const emailMatch = text.match(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/);
          if (!emailMatch) continue;

          // Permission level keywords
          const permLevels = ['owner', 'creator', 'editor', 'commenter', 'read only', 'read-only'];
          let perm: string | null = null;
          for (const level of permLevels) {
            if (text.toLowerCase().includes(level)) {
              perm = level.replace('read only', 'read-only');
              break;
            }
          }

          // Name: first non-email, non-permission line that looks like a name
          let name: string | null = null;
          for (const line of lines) {
            if (line.includes('@')) continue;
            if (permLevels.some((p) => line.toLowerCase() === p)) continue;
            if (line.length > 1 && line.length < 80) { name = line; break; }
          }

          results.push({
            userId: null,
            email:  emailMatch[0],
            name,
            permissionLevel: perm,
          });
        }

        // Strategy 2: if structured selectors didn't work, try full page text
        if (results.length === 0) {
          const fullText = document.body.innerText || '';
          const emails = fullText.match(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g) || [];
          const unique = [...new Set(emails)];
          for (const email of unique) {
            // Skip obvious non-collaborator emails
            if (email.includes('airtable.com') || email.includes('noreply')) continue;
            results.push({ userId: null, email, name: null, permissionLevel: null });
          }
        }

        return results;
      });

      return collabs;
    } catch (err: any) {
      console.error(`[engine-session] scrapeWorkspaceSettings failed: ${err.message}`);
      return [];
    }
  }

  private async scrapeBaseShareDialog(baseId: string): Promise<Omit<CollaboratorInfo, 'source'>[]> {
    try {
      // Navigate to the base
      await this.page.goto(`https://airtable.com/${baseId}`, {
        waitUntil: 'networkidle',
        timeout: 30_000,
      });
      await new Promise((r) => setTimeout(r, 2000));

      // Click the "Share" button to open the share dialog
      const clickedShare = await this.page.evaluate(() => {
        // Share button is typically in the top-right area
        const buttons = Array.from(document.querySelectorAll('button, [role="button"]'));
        const shareBtn = buttons.find((el) => {
          const text = ((el as HTMLElement).textContent || '').trim().toLowerCase();
          return text === 'share' || text === 'share base';
        }) as HTMLElement | undefined;
        if (shareBtn) { shareBtn.click(); return true; }
        return false;
      });

      if (!clickedShare) {
        console.log('[engine-session] Share button not found');
        return [];
      }

      await new Promise((r) => setTimeout(r, 2000));

      // Expand "People with access" section if collapsed
      await this.page.evaluate(() => {
        const expandButtons = Array.from(document.querySelectorAll('button, [role="button"], [class*="expand"]'));
        const accessBtn = expandButtons.find((el) => {
          const text = ((el as HTMLElement).textContent || '').toLowerCase();
          return text.includes('people with access') || text.includes('manage access');
        }) as HTMLElement | undefined;
        if (accessBtn) accessBtn.click();
      });

      await new Promise((r) => setTimeout(r, 1500));

      // Scrape collaborators from the share dialog
      const collabs = await this.page.evaluate(() => {
        const results: Array<{ userId: string | null; email: string | null; name: string | null; permissionLevel: string | null }> = [];

        // The share dialog shows collaborators in a list with name, email, role
        // Look for the dialog/modal
        const dialogs = document.querySelectorAll(
          '[role="dialog"], [class*="modal"], [class*="dialog"], [class*="share"], [class*="ShareDialog"]'
        );

        const container = dialogs.length > 0 ? dialogs[dialogs.length - 1] as HTMLElement : document.body;
        const text = container.innerText || '';

        // Find email addresses in the dialog
        const emailRegex = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g;
        const emails = text.match(emailRegex) || [];
        const unique = [...new Set(emails)];

        const permLevels = ['owner', 'creator', 'editor', 'commenter', 'read only', 'read-only'];

        for (const email of unique) {
          if (email.includes('airtable.com') || email.includes('noreply')) continue;

          // Try to find the name and permission near this email in the text
          const idx = text.indexOf(email);
          const context = text.substring(Math.max(0, idx - 150), Math.min(text.length, idx + 150));
          const contextLines = context.split('\n').map((l: string) => l.trim()).filter(Boolean);

          let name: string | null = null;
          let perm: string | null = null;

          for (const line of contextLines) {
            if (line.includes('@')) continue;
            if (!perm) {
              for (const level of permLevels) {
                if (line.toLowerCase().includes(level)) {
                  perm = level.replace('read only', 'read-only');
                  break;
                }
              }
            }
            if (!name && !permLevels.some((p) => line.toLowerCase() === p) && line.length > 1 && line.length < 80) {
              name = line;
            }
          }

          results.push({ userId: null, email, name, permissionLevel: perm });
        }

        return results;
      });

      // Close the dialog
      await this.page.keyboard.press('Escape').catch(() => {});
      await new Promise((r) => setTimeout(r, 500));

      return collabs;
    } catch (err: any) {
      console.error(`[engine-session] scrapeBaseShareDialog failed: ${err.message}`);
      return [];
    }
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
