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
   * Scrape collaborators for a base.
   * Strategy (in order of reliability):
   *   1. Navigate to workspace settings > Collaborators tab, scrape the
   *      "Billable collaborators" list (name + email + per-base roles)
   *   2. Fall back to full-page email extraction from workspace settings
   *
   * Workspace ID resolution: navigate to the base page first, then extract
   * the workspace ID from the page's HTML/script tags or sidebar links.
   */
  async scrapeCollaborators(baseId: string): Promise<CollaboratorsResult> {
    const result: CollaboratorsResult = {
      workspaceId:   null,
      workspaceName: null,
      collaborators: [],
    };

    try {
      // Step 1: navigate to the base to bootstrap the app shell
      console.log(`[engine-session] Navigating to base ${baseId} to resolve workspace...`);
      await this.page.goto(`https://airtable.com/${baseId}`, {
        waitUntil: 'networkidle',
        timeout: 60_000,
      });
      await new Promise((r) => setTimeout(r, 3000));

      // Step 2: resolve workspace ID
      const wsInfo = await this.resolveWorkspace(baseId);
      result.workspaceId   = wsInfo.workspaceId;
      result.workspaceName = wsInfo.workspaceName;
      console.log(`[engine-session] Workspace resolved: ${wsInfo.workspaceId} "${wsInfo.workspaceName || ''}"`);

      if (!wsInfo.workspaceId) {
        result.error = 'Could not determine workspace ID for base';
        return result;
      }

      // Step 3: navigate to workspace settings Collaborators tab
      const collabs = await this.scrapeWorkspaceCollaboratorsTab(wsInfo.workspaceId);
      if (collabs.length > 0) {
        result.collaborators = collabs.map((c) => ({ ...c, source: 'workspace' as const }));
        console.log(`[engine-session] Found ${collabs.length} collaborator(s) from workspace settings`);
      } else {
        result.error = 'No collaborators found on workspace settings page';
      }
    } catch (err: any) {
      result.error = `Collaborator scraping failed: ${err.message}`;
      console.error(`[engine-session] ${result.error}`);
    }

    return result;
  }

  /**
   * Resolve the workspace ID for a base. Tries multiple strategies:
   *   - Scan all <a> hrefs on the base page for wsp* patterns
   *   - Scan <script> tags for JSON containing workspaceId
   *   - Scan full page HTML source for wsp* patterns near the base ID
   */
  private async resolveWorkspace(baseId: string): Promise<{ workspaceId: string | null; workspaceName: string | null }> {
    try {
      const wsInfo = await this.page.evaluate(() => {
        // Strategy A: scan all anchor hrefs for workspace links
        const allAnchors = Array.from(document.querySelectorAll('a'));
        for (const a of allAnchors) {
          const href = a.href || '';
          const match = href.match(/(wsp[a-zA-Z0-9]{10,})/);
          if (match) {
            return { workspaceId: match[1], workspaceName: a.textContent?.trim() || null };
          }
        }

        // Strategy B: scan script tags and inline JSON for workspaceId
        const html = document.documentElement.innerHTML;
        const jsonMatch = html.match(/"workspaceId"\s*:\s*"(wsp[a-zA-Z0-9]+)"/);
        if (jsonMatch) {
          const nameMatch = html.match(/"workspaceName"\s*:\s*"([^"]+)"/);
          return { workspaceId: jsonMatch[1], workspaceName: nameMatch?.[1] || null };
        }

        // Strategy C: brute-force scan HTML for any wsp* token
        const wspMatch = html.match(/wsp[a-zA-Z0-9]{10,}/);
        if (wspMatch) {
          return { workspaceId: wspMatch[0], workspaceName: null };
        }

        return { workspaceId: null, workspaceName: null };
      });

      if (wsInfo.workspaceId) return wsInfo;

      // Strategy D: go to the home page and find which workspace contains this base
      console.log('[engine-session] Trying home page to resolve workspace...');
      await this.page.goto('https://airtable.com/', {
        waitUntil: 'networkidle',
        timeout: 30_000,
      });
      await new Promise((r) => setTimeout(r, 3000));

      const fromHome = await this.page.evaluate((targetBaseId: string) => {
        const html = document.documentElement.innerHTML;
        // Look for the base ID near a workspace ID in the HTML
        const idx = html.indexOf(targetBaseId);
        if (idx === -1) return { workspaceId: null, workspaceName: null };

        // Search in a window around the base ID
        const window = html.substring(Math.max(0, idx - 2000), Math.min(html.length, idx + 2000));
        const match = window.match(/(wsp[a-zA-Z0-9]{10,})/);
        if (match) return { workspaceId: match[1], workspaceName: null };

        return { workspaceId: null, workspaceName: null };
      }, baseId);

      return fromHome;
    } catch (err: any) {
      console.error(`[engine-session] resolveWorkspace failed: ${err.message}`);
      return { workspaceId: null, workspaceName: null };
    }
  }

  /**
   * Navigate to workspace settings > Collaborators tab and scrape the list.
   * The page shows "Billable collaborators" with each entry containing:
   *   - Name (e.g. "Janhvi Gaikwad")
   *   - Email below the name (e.g. "janhvi.gaikwad@phoebephilo.com")
   *   - Per-base role labels (e.g. "Editor" next to base icons)
   */
  private async scrapeWorkspaceCollaboratorsTab(workspaceId: string): Promise<Omit<CollaboratorInfo, 'source'>[]> {
    try {
      // Navigate to workspace settings
      const settingsUrl = `https://airtable.com/${workspaceId}/workspace`;
      console.log(`[engine-session] Navigating to workspace settings: ${settingsUrl}`);
      await this.page.goto(settingsUrl, {
        waitUntil: 'networkidle',
        timeout: 30_000,
      });
      await new Promise((r) => setTimeout(r, 3000));

      // Check for redirect to login
      if (this.page.url().includes('/login')) {
        console.log('[engine-session] Redirected to login, no access to workspace settings');
        return [];
      }

      // Click the "Collaborators" tab
      const clickedTab = await this.page.evaluate(() => {
        const tabs = Array.from(document.querySelectorAll('a, button, [role="tab"]'));
        for (const tab of tabs) {
          const text = ((tab as HTMLElement).textContent || '').trim().toLowerCase();
          if (text === 'collaborators') {
            (tab as HTMLElement).click();
            return true;
          }
        }
        return false;
      });

      if (clickedTab) {
        console.log('[engine-session] Clicked Collaborators tab');
        await new Promise((r) => setTimeout(r, 3000));
      } else {
        console.log('[engine-session] Collaborators tab not found, scraping current page');
      }

      // Scrape: extract all emails from the page with nearby name context
      const collabs = await this.page.evaluate(() => {
        const results: Array<{ userId: string | null; email: string | null; name: string | null; permissionLevel: string | null }> = [];
        const seen = new Set<string>();
        const fullText = document.body.innerText || '';

        // Find all email addresses on the page
        const emailRegex = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g;
        let match;
        while ((match = emailRegex.exec(fullText)) !== null) {
          const email = match[0].toLowerCase();
          if (seen.has(email)) continue;
          if (email.includes('airtable.com') || email.includes('noreply')) continue;
          seen.add(email);

          // The workspace settings page renders each collaborator as:
          //   Name
          //   email@domain.com
          //   [base icons with roles]
          // So the name is on the line ABOVE the email
          const idx = fullText.indexOf(match[0]);
          const before = fullText.substring(Math.max(0, idx - 200), idx);
          const lines = before.split('\n').map(l => l.trim()).filter(Boolean);

          // Name: last non-empty line before the email that looks like a name
          let name: string | null = null;
          for (let i = lines.length - 1; i >= 0; i--) {
            const line = lines[i];
            // Skip lines that look like role labels or base names
            if (line.includes('@')) continue;
            if (line.length < 2 || line.length > 60) continue;
            // Skip obvious non-name strings
            if (/^(editor|owner|creator|commenter|read.only|admin|external|settings|billing|usage|collaborator|billable|workspace|add or manage)/i.test(line)) continue;
            name = line;
            break;
          }

          // Look for role/permission near the email (after it)
          const after = fullText.substring(idx, Math.min(fullText.length, idx + 200));
          const afterLines = after.split('\n').map(l => l.trim()).filter(Boolean);
          let perm: string | null = null;
          for (const line of afterLines) {
            const lower = line.toLowerCase();
            if (lower === 'owner' || lower === 'creator' || lower === 'editor' || lower === 'commenter' || lower === 'read only' || lower === 'read-only' || lower === 'admin' || lower === 'external') {
              perm = lower;
              break;
            }
          }

          results.push({ userId: null, email, name, permissionLevel: perm });
        }

        return results;
      });

      return collabs;
    } catch (err: any) {
      console.error(`[engine-session] scrapeWorkspaceCollaboratorsTab failed: ${err.message}`);
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
