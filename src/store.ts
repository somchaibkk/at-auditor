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
        trigger_config:   a.triggerConfig,                  // connection/app/schedule details
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

  async saveUsageStats(usageData: Record<string, any>) {
    // Merge usage stats into environment_data
    const { data: existing } = await this.db
      .from('environment_data')
      .select('data')
      .eq('audit_id', this.cfg.auditId)
      .limit(1)
      .maybeSingle();

    const envData = existing?.data ?? {};
    envData.allUsageStats = usageData;

    await this.db.from('environment_data').upsert(
      { audit_id: this.cfg.auditId, data: envData },
      { onConflict: 'audit_id' },
    );
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

  // ---------------------------------------------------------------------------
  // Full JSON export (runs on worker, no size limits)
  // ---------------------------------------------------------------------------

  async generateAndUploadExport(): Promise<string | null> {
    console.log('[export] Generating full audit export...');
    const auditId = this.cfg.auditId;

    // Fetch all data
    const [auditRes, basesRes, schemasRes, automationsRes, findingsRes, samplesRes, envRes] = await Promise.all([
      this.db.from('audits').select('*').eq('id', auditId).single(),
      this.db.from('audit_bases').select('*').eq('audit_id', auditId),
      this.db.from('base_schemas').select('base_id,table_count,field_count,tables,collaborators,automation_stats').eq('audit_id', auditId),
      this.db.from('automations').select('*').eq('audit_id', auditId),
      this.db.from('findings').select('severity,category,base_id,title,detail,recommendation').eq('audit_id', auditId).order('severity'),
      this.db.from('record_samples').select('*').eq('audit_id', auditId),
      this.db.from('environment_data').select('data').eq('audit_id', auditId).limit(1),
    ]);

    const audit = auditRes.data;
    if (!audit) throw new Error('Audit not found');

    // Get client info
    let clientInfo: any = null;
    if (audit.client_id) {
      const pubDb = createClient(this.cfg.supabaseUrl, this.cfg.supabaseServiceRoleKey);
      const { data: cl } = await pubDb.from('clients').select('code,name,logo_url').eq('id', audit.client_id).single();
      clientInfo = cl;
    }

    const envData = envRes.data?.[0]?.data ?? null;

    // Strip attachment blobs from cell values
    const stripAttachments = (records: any[]): any[] => {
      if (!Array.isArray(records)) return records;
      return records.map((r: any) => {
        if (!r?.fields) return r;
        const cleaned: Record<string, any> = {};
        for (const [key, val] of Object.entries(r.fields)) {
          if (Array.isArray(val) && (val as any[]).length > 0 && (val as any[])[0]?.url && (val as any[])[0]?.filename) {
            cleaned[key] = {
              _type: 'attachments',
              count: (val as any[]).length,
              filenames: (val as any[]).map((a: any) => a.filename).filter(Boolean),
              totalSizeBytes: (val as any[]).reduce((s: number, a: any) => s + (a.size || 0), 0),
            };
          } else {
            cleaned[key] = val;
          }
        }
        return { ...r, fields: cleaned };
      });
    };

    // Build per-base data
    const bases = (basesRes.data ?? []).map((b: any) => {
      const schema = (schemasRes.data ?? []).find((s: any) => s.base_id === b.airtable_base_id);
      const autos = (automationsRes.data ?? []).filter((a: any) => a.base_id === b.airtable_base_id);
      const samples = (samplesRes.data ?? []).filter((s: any) => s.base_id === b.airtable_base_id);

      return {
        id: b.airtable_base_id,
        name: b.base_name,
        schema: schema ? {
          table_count: schema.table_count,
          field_count: schema.field_count,
          tables: (schema.tables ?? []).map((t: any) => ({
            id: t.id, name: t.name,
            field_count: t.fields?.length ?? 0,
            fields: (t.fields ?? []).map((f: any) => ({ id: f.id, name: f.name, type: f.type, options: f.type === 'multipleRecordLinks' ? f.options : undefined })),
            view_count: t.views?.length ?? 0,
          })),
        } : null,
        collaborators: schema?.collaborators ?? null,
        automation_stats: schema?.automation_stats ?? null,
        automations: autos.map((a: any) => ({
          name: a.name, deployment_status: a.deployment_status,
          trigger: a.trigger, trigger_type_id: a.trigger_type_id,
          trigger_config: a.trigger_config ?? null,
          step_count: a.step_count, action_types: a.action_types,
          has_scripts: a.has_scripts,
          scripts: (a.script_sources ?? []).map((s: any) => ({ lines: s.lines, code: s.code })),
          error: a.error,
        })),
        record_samples: samples.map((s: any) => ({
          table_name: s.table_name, table_id: s.table_id,
          sampled_count: s.sampled_count, has_more: s.has_more,
          sample: s.sample ? stripAttachments(s.sample) : null,
        })),
      };
    });

    const exportData = {
      meta: {
        prospect: clientInfo?.name ?? audit.prospect_name,
        client_code: clientInfo?.code ?? null,
        audit_id: auditId,
        status: audit.status,
        created_at: audit.created_at,
        started_at: audit.started_at,
        finished_at: audit.finished_at,
        config: audit.config,
        exported_at: new Date().toISOString(),
        tool: 'Quivvy AT Auditor',
      },
      summary: {
        base_count: bases.length,
        total_tables: bases.reduce((n: number, b: any) => n + (b.schema?.table_count ?? 0), 0),
        total_fields: bases.reduce((n: number, b: any) => n + (b.schema?.field_count ?? 0), 0),
        total_automations: bases.reduce((n: number, b: any) => n + b.automations.length, 0),
        total_scripts: bases.reduce((n: number, b: any) => n + b.automations.filter((a: any) => a.has_scripts).length, 0),
        finding_counts: {
          critical: (findingsRes.data ?? []).filter((f: any) => f.severity === 'critical').length,
          high: (findingsRes.data ?? []).filter((f: any) => f.severity === 'high').length,
          medium: (findingsRes.data ?? []).filter((f: any) => f.severity === 'medium').length,
          low: (findingsRes.data ?? []).filter((f: any) => f.severity === 'low').length,
          info: (findingsRes.data ?? []).filter((f: any) => f.severity === 'info').length,
        },
      },
      environment: envData,
      findings: findingsRes.data ?? [],
      bases,
    };

    // Serialize
    const jsonStr = JSON.stringify(exportData, null, 2);
    const code = clientInfo?.code ?? 'export';
    const dateStr = new Date().toISOString().slice(0, 10);
    const filename = `${code.toLowerCase()}-${dateStr}-${auditId.slice(0, 8)}.json`;

    console.log(`[export] JSON size: ${(jsonStr.length / 1024 / 1024).toFixed(1)}MB, uploading as ${filename}...`);

    // Upload to Supabase Storage
    const pubDb = createClient(this.cfg.supabaseUrl, this.cfg.supabaseServiceRoleKey);
    const { error: uploadErr } = await pubDb.storage
      .from('audit-exports')
      .upload(filename, Buffer.from(jsonStr), {
        contentType: 'application/json',
        upsert: true,
      });

    if (uploadErr) {
      console.error('[export] Upload failed:', uploadErr.message);
      return null;
    }

    const exportUrl = `${this.cfg.supabaseUrl}/storage/v1/object/public/audit-exports/${filename}`;
    console.log(`[export] Uploaded: ${exportUrl}`);

    // Save URL on audit
    await this.db.from('audits').update({ export_url: exportUrl }).eq('id', auditId);

    return exportUrl;
  }
}
