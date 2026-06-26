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
