// store.ts
// ---------------------------------------------------------------------------
// Writes collection results to the control-plane Supabase project using the
// service role key (bypasses RLS). Also emits job_events for live UI progress.
// ---------------------------------------------------------------------------

import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import type { WorkerConfig } from './config.js';
import type { CollectedAutomation } from './engine-session.js';

export class Store {
  private db: ReturnType<typeof createClient>;

  constructor(private cfg: WorkerConfig) {
    this.db = createClient(cfg.supabaseUrl, cfg.supabaseServiceRoleKey, {
      auth: { persistSession: false },
      db: { schema: 'audit' },
    });
  }

  // ---------------------------------------------------------------------------
  // Progress events
  // ---------------------------------------------------------------------------

  async event(
    phase: string,
    message: string,
    level: 'info' | 'warn' | 'error' = 'info',
    meta?: unknown,
  ) {
    await this.db.from('job_events').insert({
      audit_id: this.cfg.auditId,
      phase,
      message,
      level,
      meta: meta ?? null,
    });
    console.log(`[${level}] ${phase}: ${message}`);
  }

  // ---------------------------------------------------------------------------
  // Audit lifecycle
  // ---------------------------------------------------------------------------

  async setAuditStatus(status: string, error?: string) {
    const patch: Record<string, unknown> = { status };
    if (status === 'running')   patch.started_at  = new Date().toISOString();
    if (['complete', 'failed', 'cancelled'].includes(status))
                                patch.finished_at = new Date().toISOString();
    if (error)                  patch.error       = error;
    await this.db.from('audits').update(patch).eq('id', this.cfg.auditId);
  }

  async upsertBaseStatus(baseId: string, status: string, error?: string) {
    await this.db
      .from('audit_bases')
      .update({ collection_status: status, error: error ?? null })
      .eq('audit_id', this.cfg.auditId)
      .eq('airtable_base_id', baseId);
  }

  // ---------------------------------------------------------------------------
  // Schema (Engine 1)
  // ---------------------------------------------------------------------------

  async saveSchema(
    baseId: string,
    tables: any[],
    tableCount: number,
    fieldCount: number,
    collaborators: unknown,
  ) {
    await this.db.from('base_schemas').upsert(
      {
        audit_id:      this.cfg.auditId,
        base_id:       baseId,
        tables,
        table_count:   tableCount,
        field_count:   fieldCount,
        collaborators: collaborators ?? null,
      },
      { onConflict: 'audit_id,base_id' },
    );
  }

  // ---------------------------------------------------------------------------
  // Automations (Engine 2)
  // ---------------------------------------------------------------------------

  async saveAutomations(baseId: string, automations: CollectedAutomation[]) {
    if (!automations.length) return;
    await this.db.from('automations').insert(
      automations.map((a) => ({
        audit_id:         this.cfg.auditId,
        base_id:          baseId,
        workflow_id:      a.workflowId,
        deployment_id:    a.deploymentId,
        name:             a.name,
        deployment_status: a.deploymentStatus,              // "deployed" | "undeployed" | null
        trigger_type_id:  a.triggerTypeId,
        trigger:          a.trigger,                        // human label
        step_count:       a.stepCount,
        action_types:     a.actionTypes,                    // string[]
        script_sources:   a.scriptSources,                  // { actionId, stepIndex, actionType, lines, code }[]
        has_scripts:      a.scriptSources.length > 0,
        error:            a.error ?? null,
      })),
    );
  }

  // ---------------------------------------------------------------------------
  // Record samples (Engine 1)
  // ---------------------------------------------------------------------------

  async saveRecordSample(
    baseId: string,
    tableId: string,
    tableName: string,
    sample: any[],
    count: number,
    hasMore: boolean,
  ) {
    await this.db.from('record_samples').upsert(
      {
        audit_id:      this.cfg.auditId,
        base_id:       baseId,
        table_id:      tableId,
        table_name:    tableName,
        sample,
        sampled_count: count,
        has_more:      hasMore,
      },
      { onConflict: 'audit_id,base_id,table_id' },
    );
  }

  // ---------------------------------------------------------------------------
  // Environment data (Engine 2: workspace + enterprise + usage)
  // ---------------------------------------------------------------------------

  async saveEnvironmentData(data: Record<string, any>) {
    await this.db.from('environment_data').upsert(
      {
        audit_id: this.cfg.auditId,
        data,
      },
      { onConflict: 'audit_id' },
    );
  }

  async saveAutomationStats(baseId: string, stats: Record<string, any>) {
    // Store automation stats alongside the base schema
    await this.db.from('base_schemas').update({
      automation_stats: stats,
    }).eq('audit_id', this.cfg.auditId).eq('base_id', baseId);
  }

  // ---------------------------------------------------------------------------
  // Query
  // ---------------------------------------------------------------------------

  async getTargetBases(): Promise<Array<{ baseId: string; baseName: string | null }>> {
    const { data, error } = await this.db
      .from('audit_bases')
      .select('airtable_base_id, base_name')
      .eq('audit_id', this.cfg.auditId)
      .eq('include', true);
    if (error) throw error;
    return (data ?? []).map((r) => ({ baseId: r.airtable_base_id, baseName: r.base_name }));
  }
}
