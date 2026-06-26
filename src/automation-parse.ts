// automation-parse.ts
// ---------------------------------------------------------------------------
// Pure parser for Airtable automation data. No browser, no API calls.
// Takes the raw objects from engine-session and returns structured output.
// Tested against real listWorkflows + workflowDeployment/read responses.
// ---------------------------------------------------------------------------

export interface ParsedTrigger {
  typeId: string;
  label: string;
  tableId: string | null;
  config: unknown;
}

export interface ParsedAction {
  id: string;
  typeId: string;
  label: string;
  hasScript: boolean;
  scriptLines: number;
  scriptBody: string;
  branchCount: number;
}

export interface ParsedAutomation {
  workflowId: string;
  deploymentId: string | null;
  name: string;
  deploymentStatus: string;
  trigger: ParsedTrigger;
  actions: ParsedAction[];
  stepCount: number;
  hasScripts: boolean;
  isUndeployed: boolean;
}

// ---------------------------------------------------------------------------
// Label maps
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

function labelTrigger(typeId: string): string {
  return TRIGGER_LABELS[typeId] ?? typeId;
}

function labelAction(typeId: string): string {
  return ACTION_LABELS[typeId] ?? typeId;
}

// ---------------------------------------------------------------------------
// Graph walker -- BFS across all branches
// ---------------------------------------------------------------------------

function walkAllNodes(actionsById: Record<string, any>, entryId: string): any[] {
  const visited = new Set<string>();
  const queue: string[] = [entryId];
  const nodes: any[] = [];

  while (queue.length) {
    const id = queue.shift()!;
    if (!id || visited.has(id)) continue;
    visited.add(id);
    const node = actionsById?.[id];
    if (!node) continue;
    nodes.push(node);
    if (node.nextWorkflowNodeIds?.length) queue.push(...node.nextWorkflowNodeIds);
    if (node.nextWorkflowActionId) queue.push(node.nextWorkflowActionId);
  }

  // Append orphans (defensive -- should not happen in valid graphs)
  for (const id of Object.keys(actionsById ?? {})) {
    if (!visited.has(id)) nodes.push(actionsById[id]);
  }

  return nodes;
}

// ---------------------------------------------------------------------------
// Parse a single workflow object from listWorkflows
// (graph + trigger already present; script bodies come from deploymentActionsById)
// ---------------------------------------------------------------------------

export function parseWorkflow(
  wf: any,
  deploymentActionsById?: Record<string, any>,
): ParsedAutomation {
  const triggerTypeId: string = wf.trigger?.workflowTriggerTypeId ?? '';
  const tableId: string | null =
    wf.trigger?.inputExpressions?.tableId?.value ??
    wf.trigger?.inputExpressions?.tableId ??
    null;

  const actionsById: Record<string, any> = wf.graph?.actionsById ?? {};
  const entryId: string = wf.graph?.entryWorkflowActionId ?? '';
  const allNodes = walkAllNodes(actionsById, entryId);

  const actions: ParsedAction[] = allNodes.map((node) => {
    const typeId: string = node.workflowActionTypeId ?? node.workflowDecisionTypeId ?? '';
    const isScript = typeId === 'watCUSTOMSCRIPT00';
    let scriptBody = '';
    let scriptLines = 0;

    if (isScript && deploymentActionsById) {
      // Match by ID; fall back to first script node in deployment
      const deployed =
        deploymentActionsById[node.id] ??
        Object.values(deploymentActionsById).find(
          (a: any) => a.workflowActionTypeId === 'watCUSTOMSCRIPT00',
        );
      scriptBody = deployed?.inputExpressions?.script?.value ?? '';
      scriptLines = scriptBody ? scriptBody.split('\n').length : 0;
    }

    return {
      id: node.id,
      typeId,
      label: labelAction(typeId),
      hasScript: isScript && scriptLines > 0,
      scriptLines,
      scriptBody,
      branchCount: node.nextWorkflowNodeIds?.length ?? 0,
    };
  });

  const hasScripts = actions.some((a) => a.hasScript);

  return {
    workflowId:       wf.id ?? '',
    deploymentId:     wf.targetWorkflowDeploymentId ?? null,
    name:             wf.name ?? '',
    deploymentStatus: wf.deploymentStatus ?? 'unknown',
    trigger: {
      typeId:  triggerTypeId,
      label:   labelTrigger(triggerTypeId),
      tableId,
      config:  wf.trigger?.inputExpressions ?? null,
    },
    actions,
    stepCount:   actions.length,
    hasScripts,
    isUndeployed: !wf.targetWorkflowDeploymentId,
  };
}

// ---------------------------------------------------------------------------
// Parse a full collection result (array of raw workflow objects)
// deploymentDefinitions: map of deploymentId -> workflowDefinition from /read
// ---------------------------------------------------------------------------

export function parseCollection(
  workflows: any[],
  deploymentDefinitions: Map<string, any>,
): ParsedAutomation[] {
  return workflows.map((wf) => {
    const deploymentId: string | null = wf.targetWorkflowDeploymentId ?? null;
    const definition = deploymentId ? deploymentDefinitions.get(deploymentId) : undefined;
    const deploymentActionsById = definition?.graph?.actionsById;
    return parseWorkflow(wf, deploymentActionsById);
  });
}
