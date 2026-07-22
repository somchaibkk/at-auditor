// analysis.ts
// ---------------------------------------------------------------------------
// Analysis engine. Runs after collection. Reads from audit.* tables,
// produces findings in audit.findings.
//
// Finding categories:
//   automation  -- issues with individual automations
//   complexity  -- base-level complexity signals
//   hygiene     -- naming, dead code, unused structures
//   security    -- hardcoded IDs/tokens, missing error handling
//   drift       -- undeployed automations, version mismatches
// ---------------------------------------------------------------------------

import { createClient, type SupabaseClient } from '@supabase/supabase-js';

export interface AnalysisConfig {
  supabaseUrl:            string;
  supabaseServiceRoleKey: string;
  auditId:                string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function db(cfg: AnalysisConfig): ReturnType<typeof createClient> {
  return createClient(cfg.supabaseUrl, cfg.supabaseServiceRoleKey, {
    auth: { persistSession: false },
    db:   { schema: 'audit' },
  });
}

type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

interface Finding {
  audit_id:       string;
  severity:       Severity;
  category:       string;
  base_id:        string | null;
  title:          string;
  detail:         string | null;
  recommendation: string | null;
}

// ---------------------------------------------------------------------------
// Script analysis helpers
// ---------------------------------------------------------------------------

function hasErrorHandling(code: string): boolean {
  return /try\s*\{/.test(code) || /\.catch\s*\(/.test(code);
}

function hasHardcodedIds(code: string): string[] {
  const matches: string[] = [];
  // Airtable record IDs: rec[a-zA-Z0-9]{14}
  const recIds = code.match(/["'`]rec[a-zA-Z0-9]{14}["'`]/g) ?? [];
  // Airtable base IDs: app[a-zA-Z0-9]{14}
  const appIds = code.match(/["'`]app[a-zA-Z0-9]{14}["'`]/g) ?? [];
  // Airtable field IDs: fld[a-zA-Z0-9]{14}
  const fldIds = code.match(/["'`]fld[a-zA-Z0-9]{14}["'`]/g) ?? [];
  // PAT tokens
  const pats   = code.match(/pat[A-Za-z0-9]{14,}/g) ?? [];
  matches.push(...recIds, ...appIds, ...fldIds, ...pats);
  return [...new Set(matches)];
}

function hasConsoleLog(code: string): boolean {
  return /console\.(log|warn|error)\s*\(/.test(code);
}

function linesOfCode(code: string): number {
  return code.split('\n').filter(l => l.trim() && !l.trim().startsWith('//')).length;
}

function scriptComplexity(code: string): 'low' | 'medium' | 'high' {
  const loc = linesOfCode(code);
  if (loc < 30)  return 'low';
  if (loc < 100) return 'medium';
  return 'high';
}

// ---------------------------------------------------------------------------
// PII / sensitive data detection
// ---------------------------------------------------------------------------

const SENSITIVE_FIELD_NAMES = /\b(email|e-mail|phone|tel|mobile|ssn|social.security|national.id|passport|credit.card|card.number|iban|bank.account|salary|wage|compensation|dob|date.of.birth|birth.?date|address|zip.?code|postal|national.insurance|tax.id|vat.number|driver.license|licence|sin\b|nin\b|bsn\b|niss\b)/i;

const PII_PATTERNS: Array<{ name: string; pattern: RegExp; excludeFields?: RegExp }> = [
  { name: 'email',        pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/  },
  // Phone: require + prefix OR parenthesized area code OR explicit separators (not bare digit runs)
  { name: 'phone',
    pattern: /(?:\+\d{1,3}[\s-]\d[\d\s-]{6,14}|\(\d{2,4}\)\s?\d{3,4}[\s.-]\d{3,4}|\b\d{2,4}[\s-]\d{3,4}[\s-]\d{3,4}\b)/,
    excludeFields: /barcode|upc|ean|sku|hts|hs.code|intrastat|cost|price|rrp|fx[_\s]|currency|image|img|photo|sketch|shareable|label|sticker|docket|bom|code|digit|check|start|number.*ex/i,
  },
  { name: 'IBAN',         pattern: /[A-Z]{2}\d{2}[\s]?[A-Z0-9]{4}[\s]?\d{4}[\s]?\d{4}[\s]?\d{4}/ },
  { name: 'credit card',  pattern: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/ },
  { name: 'SSN',          pattern: /\b\d{3}-\d{2}-\d{4}\b/ },
  { name: 'BE NISS',
    pattern: /\b\d{2}[.\s]\d{2}[.\s]\d{2}[.\s-]\d{3}[.\s-]\d{2}\b/,
    excludeFields: /barcode|upc|ean|sku|hts|hs.code|intrastat|cost|price|rrp|fx[_\s]|currency|code|digit/i,
  },
];

interface PiiHit {
  tableName:  string;
  fieldName:  string;
  piiType:    string;
  source:     'field_name' | 'cell_value';
  sampleCount: number;  // how many sampled records had this pattern
}

/** Scan a table's record samples for PII patterns in actual cell values. */
function scanSampleForPii(tableName: string, records: any[]): PiiHit[] {
  const hits = new Map<string, PiiHit>(); // key: tableName.fieldName.piiType

  for (const record of records) {
    const fields = record.fields || {};
    for (const [fieldName, value] of Object.entries(fields)) {
      if (value === null || value === undefined) continue;
      const strValue = typeof value === 'string' ? value : JSON.stringify(value);
      if (!strValue || strValue.length < 3) continue;

      for (const { name: piiType, pattern, excludeFields } of PII_PATTERNS) {
        if (excludeFields && excludeFields.test(fieldName)) continue;
        if (pattern.test(strValue)) {
          const key = `${tableName}.${fieldName}.${piiType}`;
          const existing = hits.get(key);
          if (existing) {
            existing.sampleCount++;
          } else {
            hits.set(key, { tableName, fieldName, piiType, source: 'cell_value', sampleCount: 1 });
          }
        }
      }
    }
  }
  return Array.from(hits.values());
}

/** Check field names for sensitive-sounding patterns (no cell values needed). */
function scanFieldNamesForPii(tableName: string, fields: any[]): PiiHit[] {
  const hits: PiiHit[] = [];
  for (const field of fields) {
    if (SENSITIVE_FIELD_NAMES.test(field.name)) {
      hits.push({
        tableName,
        fieldName: field.name,
        piiType:   field.name.toLowerCase(),
        source:    'field_name',
        sampleCount: 0,
      });
    }
  }
  return hits;
}

// ---------------------------------------------------------------------------
// Link-field dependency helpers
// ---------------------------------------------------------------------------

interface LinkEdge {
  sourceTableId:   string;
  sourceTableName: string;
  fieldId:         string;
  fieldName:       string;
  targetTableId:   string;
  targetTableName: string | null;   // null if target not found in schema
  isSelfLink:      boolean;
  prefersSingle:   boolean;
}

/** Build table-to-table link edges from the raw schema tables array. */
function extractLinkEdges(tables: any[]): LinkEdge[] {
  const tableNameById = new Map<string, string>();
  for (const t of tables) {
    if (t.id && t.name) tableNameById.set(t.id, t.name);
  }

  const edges: LinkEdge[] = [];
  for (const table of tables) {
    for (const field of table.fields ?? []) {
      if (field.type !== 'multipleRecordLinks') continue;
      const targetId: string | undefined = field.options?.linkedTableId;
      if (!targetId) continue;
      edges.push({
        sourceTableId:   table.id,
        sourceTableName: table.name,
        fieldId:         field.id,
        fieldName:       field.name,
        targetTableId:   targetId,
        targetTableName: tableNameById.get(targetId) ?? null,
        isSelfLink:      targetId === table.id,
        prefersSingle:   field.options?.prefersSingleRecordLink === true,
      });
    }
  }
  return edges;
}

// ---------------------------------------------------------------------------
// Main analysis
// ---------------------------------------------------------------------------

export async function runAnalysis(cfg: AnalysisConfig): Promise<void> {
  const client = db(cfg);
  const findings: Finding[] = [];

  // Fetch all automations for this audit
  const { data: automations } = await client
    .from('automations')
    .select('*')
    .eq('audit_id', cfg.auditId);

  // Fetch all base schemas
  const { data: schemas } = await client
    .from('base_schemas')
    .select('*')
    .eq('audit_id', cfg.auditId);

  // Fetch audit_bases
  const { data: auditBases } = await client
    .from('audit_bases')
    .select('*')
    .eq('audit_id', cfg.auditId);

  // Fetch record samples
  const { data: recordSamples } = await client
    .from('record_samples')
    .select('*')
    .eq('audit_id', cfg.auditId);

  // Fetch new capture-gap tables
  const { data: syncLinks } = await client.from('sync_links').select('*').eq('audit_id', cfg.auditId);
  const { data: interfaces } = await client.from('interfaces').select('*').eq('audit_id', cfg.auditId);
  const { data: automationRuns } = await client.from('automation_runs').select('*').eq('audit_id', cfg.auditId);
  const { data: shareLinks } = await client.from('share_links').select('*').eq('audit_id', cfg.auditId);
  const { data: integrationEndpoints } = await client.from('integration_endpoints').select('*').eq('audit_id', cfg.auditId);
  const { data: tableStats } = await client.from('table_stats').select('*').eq('audit_id', cfg.auditId);
  const { data: fieldStats } = await client.from('field_stats').select('*').eq('audit_id', cfg.auditId);
  const { data: adminUsers } = await client.from('admin_users').select('*').eq('audit_id', cfg.auditId);
  const { data: billingSnapshots } = await client.from('billing_snapshots').select('*').eq('audit_id', cfg.auditId);

  const baseIds = (auditBases ?? []).map((b: any) => b.airtable_base_id as string);

  // Fetch environment data
  const { data: envRows } = await client
    .from('environment_data')
    .select('data')
    .eq('audit_id', cfg.auditId)
    .limit(1);
  const envData = envRows?.[0]?.data ?? null;

  // ---------------------------------------------------------------------------
  // Environment-level findings
  // ---------------------------------------------------------------------------

  if (envData?.enterprise?.noAdminAccess || envData?.enterprise?.errors?.some((e: string) => e.includes('pre-flight failed'))) {
    findings.push({
      audit_id:       cfg.auditId,
      severity:       'medium',
      category:       'security',
      base_id:        null,
      title:          'Enterprise admin data unavailable: session lacks admin scope',
      detail:         'The audit session credential does not have enterprise admin privileges. All enterprise-level data (user directory, licence counts, roles, security settings, workspaces) is absent from this audit. Totals showing zero are not real counts.',
      recommendation: 'To collect enterprise data, run the audit with a session from an account that has enterprise admin access in Airtable.',
    });
  } else if (envData?.enterprise === null && envData?.errors?.some((e: string) => e.includes('enterprise'))) {
    findings.push({
      audit_id:       cfg.auditId,
      severity:       'info',
      category:       'security',
      base_id:        null,
      title:          'No enterprise account detected',
      detail:         'This workspace does not appear to be part of an Airtable Enterprise plan. Enterprise-level audit data is not applicable.',
      recommendation: null,
    });
  }

  // Usage stats coverage
  const allUsageStats = envData?.allUsageStats;
  if (allUsageStats) {
    const totalBases = baseIds.length;
    const coveredBases = Object.keys(allUsageStats.byBase || {}).length;
    const workspaceCount = Object.keys(allUsageStats.byWorkspace || {}).length;

    if (coveredBases === 0) {
      findings.push({
        audit_id:       cfg.auditId,
        severity:       'medium',
        category:       'complexity',
        base_id:        null,
        title:          'No per-base usage statistics available',
        detail:         `Usage stats were requested from ${workspaceCount} workspace(s) but no per-base data was returned. Row counts, attachment sizes, and last-activity dates are unknown for all ${totalBases} bases.`,
        recommendation: 'The workspaceUsageStats response may require a different access level or the endpoint may not return per-base breakdowns for this plan. Check worker logs for the response shape.',
      });
    } else if (coveredBases < totalBases) {
      const missing = totalBases - coveredBases;
      findings.push({
        audit_id:       cfg.auditId,
        severity:       'low',
        category:       'complexity',
        base_id:        null,
        title:          `Usage statistics incomplete: ${coveredBases}/${totalBases} bases covered`,
        detail:         `Per-base usage data is missing for ${missing} base(s). These bases may be in workspaces where stats could not be fetched, or their IDs may not match the stats response keys.`,
        recommendation: 'Review worker logs for workspace resolution failures. Bases without usage data cannot be assessed for row-count proximity to plan limits.',
      });
    }

    if (allUsageStats.errors?.length > 0) {
      findings.push({
        audit_id:       cfg.auditId,
        severity:       'info',
        category:       'complexity',
        base_id:        null,
        title:          `Usage stats collection had ${allUsageStats.errors.length} warning(s)`,
        detail:         allUsageStats.errors.join('\n'),
        recommendation: null,
      });
    }
  } else if (!envData) {
    // No environment data at all
  } else {
    findings.push({
      audit_id:       cfg.auditId,
      severity:       'low',
      category:       'complexity',
      base_id:        null,
      title:          'Usage statistics not collected',
      detail:         'No usage stats data found in environment data. This may mean the collection step was skipped or disabled.',
      recommendation: 'Ensure collect_environment or collect_collaborators is enabled in audit config to trigger usage stats collection.',
    });
  }

  // ---------------------------------------------------------------------------
  // Per-base analysis
  // ---------------------------------------------------------------------------
  for (const baseId of baseIds) {
    const baseAutomations = (automations ?? []).filter((a: any) => a.base_id === baseId);
    const schema          = (schemas ?? []).find((s: any) => s.base_id === baseId);
    const baseName        = (auditBases ?? []).find((b: any) => b.airtable_base_id === baseId)?.base_name ?? baseId;

    // -- DRIFT: undeployed automations ----------------------------------------
    const undeployed = baseAutomations.filter((a: any) => a.deployment_status === 'undeployed');
    if (undeployed.length > 0) {
      findings.push({
        audit_id:       cfg.auditId,
        severity:       'medium',
        category:       'drift',
        base_id:        baseId,
        title:          `${undeployed.length} undeployed automation(s) in ${baseName}`,
        detail:         `Automations exist in draft state but are not deployed: ${undeployed.map((a: any) => a.name).join(', ')}`,
        recommendation: 'Review whether these automations are intentionally disabled or forgotten work in progress.',
      });
    }

    // -- COMPLEXITY: automation count ----------------------------------------
    if (baseAutomations.length > 20) {
      findings.push({
        audit_id:       cfg.auditId,
        severity:       'low',
        category:       'complexity',
        base_id:        baseId,
        title:          `High automation count in ${baseName} (${baseAutomations.length})`,
        detail:         `Bases with many automations are harder to maintain and debug.`,
        recommendation: 'Consider consolidating automations or documenting their purpose clearly.',
      });
    }

    // -- COMPLEXITY: schema size ---------------------------------------------
    if (schema) {
      if (schema.table_count > 20) {
        findings.push({
          audit_id:       cfg.auditId,
          severity:       'low',
          category:       'complexity',
          base_id:        baseId,
          title:          `Large base structure in ${baseName} (${schema.table_count} tables, ${schema.field_count} fields)`,
          detail:         null,
          recommendation: 'Evaluate whether all tables are actively used or if some could be archived.',
        });
      }

      // Check for tables with excessive fields
      const tables = schema.tables ?? [];
      for (const table of tables) {
        const fieldCount = table.fields?.length ?? 0;
        if (fieldCount > 50) {
          findings.push({
            audit_id:       cfg.auditId,
            severity:       'low',
            category:       'complexity',
            base_id:        baseId,
            title:          `Table "${table.name}" has ${fieldCount} fields`,
            detail:         `Excessive fields can indicate scope creep or missing relational design.`,
            recommendation: 'Review whether all fields are actively used. Consider splitting into linked tables.',
          });
        }
      }

      // -- COMPLEXITY: link field dependency graph ------------------------------
      const edges = extractLinkEdges(tables);

      if (edges.length > 0) {
        // Count inbound + outbound links per table
        const connectivity = new Map<string, { name: string; outbound: number; inbound: number }>();
        for (const t of tables) {
          connectivity.set(t.id, { name: t.name, outbound: 0, inbound: 0 });
        }
        for (const e of edges) {
          const src = connectivity.get(e.sourceTableId);
          if (src) src.outbound++;
          const tgt = connectivity.get(e.targetTableId);
          if (tgt) tgt.inbound++;
        }

        // Hub tables (>= 12 total connections)
        for (const [tableId, c] of connectivity) {
          const total = c.outbound + c.inbound;
          if (total >= 12) {
            findings.push({
              audit_id:       cfg.auditId,
              severity:       'medium',
              category:       'complexity',
              base_id:        baseId,
              title:          `Table "${c.name}" is a hub (${total} link fields: ${c.outbound} outbound, ${c.inbound} inbound)`,
              detail:         `Highly connected tables become single points of failure. Changes to "${c.name}" cascade to many other tables.`,
              recommendation: 'Document the role of this hub table. Consider whether some relationships could be simplified or moved to lookup/rollup fields.',
            });
          }
        }

        // Orphan tables (no links at all)
        for (const [tableId, c] of connectivity) {
          if (c.outbound === 0 && c.inbound === 0 && tables.length > 3) {
            findings.push({
              audit_id:       cfg.auditId,
              severity:       'info',
              category:       'hygiene',
              base_id:        baseId,
              title:          `Table "${c.name}" is isolated (no link fields)`,
              detail:         `This table has no link relationships with other tables in the base.`,
              recommendation: 'Verify this table is intentionally standalone. It may be unused or could benefit from relationships.',
            });
          }
        }

        // Self-referencing tables
        const selfLinks = edges.filter(e => e.isSelfLink);
        for (const sl of selfLinks) {
          findings.push({
            audit_id:       cfg.auditId,
            severity:       'info',
            category:       'complexity',
            base_id:        baseId,
            title:          `Self-referencing link "${sl.fieldName}" in table "${sl.sourceTableName}"`,
            detail:         `The table links to itself, creating a hierarchical or recursive structure.`,
            recommendation: 'Self-links are valid for hierarchies (parent/child). Verify the use case is intentional and that views/filters handle potential circular references.',
          });
        }

        // Broken links (target table not found in base schema)
        const brokenLinks = edges.filter(e => e.targetTableName === null);
        for (const bl of brokenLinks) {
          findings.push({
            audit_id:       cfg.auditId,
            severity:       'high',
            category:       'hygiene',
            base_id:        baseId,
            title:          `Link field "${bl.fieldName}" in "${bl.sourceTableName}" points to unknown table ${bl.targetTableId}`,
            detail:         `The target table ID was not found in this base's schema. It may have been deleted or this could be a sync/cross-base link.`,
            recommendation: 'Check whether the target table still exists. If the table was deleted, this link field is dead weight.',
          });
        }
      }

      // Summary finding: dependency map overview
      if (edges.length > 0) {
        const depMap = edges.map(e =>
          `${e.sourceTableName}.${e.fieldName} -> ${e.targetTableName ?? e.targetTableId}${e.isSelfLink ? ' (self)' : ''}`
        );
        findings.push({
          audit_id:       cfg.auditId,
          severity:       'info',
          category:       'complexity',
          base_id:        baseId,
          title:          `Table dependency map for ${baseName} (${edges.length} link fields)`,
          detail:         depMap.join('\n'),
          recommendation: null,
        });
      }
    }

    // -- SECURITY: sensitive data detection -----------------------------------
    if (schema) {
      const tables = schema.tables ?? [];
      const baseSamples = (recordSamples ?? []).filter((s: any) => s.base_id === baseId);
      const allPiiHits: PiiHit[] = [];

      for (const table of tables) {
        // Scan field names (always available from schema)
        allPiiHits.push(...scanFieldNamesForPii(table.name, table.fields ?? []));

        // Scan actual cell values (only if samples contain fields, not stripped metadata)
        const tableSample = baseSamples.find((s: any) => s.table_id === table.id);
        if (tableSample?.sample?.length > 0 && tableSample.sample[0]?.fields) {
          allPiiHits.push(...scanSampleForPii(table.name, tableSample.sample));
        }
      }

      // Deduplicate and group: value-confirmed hits are stronger than name-only
      const confirmedHits = allPiiHits.filter(h => h.source === 'cell_value');
      const nameOnlyHits  = allPiiHits.filter(h =>
        h.source === 'field_name' &&
        !confirmedHits.some(c => c.tableName === h.tableName && c.fieldName === h.fieldName),
      );

      if (confirmedHits.length > 0) {
        const detail = confirmedHits.map(h =>
          `${h.tableName}.${h.fieldName}: ${h.piiType} detected in ${h.sampleCount} sampled record(s)`,
        ).join('\n');
        findings.push({
          audit_id:       cfg.auditId,
          severity:       'high',
          category:       'security',
          base_id:        baseId,
          title:          `PII detected in cell values in ${baseName} (${confirmedHits.length} field(s))`,
          detail,
          recommendation: 'Review these fields and confirm whether personal data handling complies with GDPR/privacy requirements. Consider field-level permissions or masking.',
        });
      }

      if (nameOnlyHits.length > 0) {
        const detail = nameOnlyHits.map(h =>
          `${h.tableName}.${h.fieldName} (${h.piiType})`,
        ).join('\n');
        findings.push({
          audit_id:       cfg.auditId,
          severity:       'medium',
          category:       'security',
          base_id:        baseId,
          title:          `Potentially sensitive fields in ${baseName} (${nameOnlyHits.length} field(s), name-based detection only)`,
          detail,
          recommendation: 'Field names suggest personal data. Enable include_cell_values in audit config to confirm with actual content scanning.',
        });
      }
    }

    // -- SECURITY: collaborator permission coverage ---------------------------
    if (schema?.collaborators) {
      const collabs: any[] = schema.collaborators.collaborators || [];
      if (collabs.length > 0) {
        const nullPerms = collabs.filter((c: any) => !c.permissionLevel);
        const nullRate  = nullPerms.length / collabs.length;

        if (nullPerms.length > 0 && nullRate > 0.5 && collabs.length > 30) {
          findings.push({
            audit_id:       cfg.auditId,
            severity:       'medium',
            category:       'security',
            base_id:        baseId,
            title:          `${nullPerms.length}/${collabs.length} collaborators have unknown permission level in ${baseName}`,
            detail:         `${Math.round(nullRate * 100)}% of collaborators for this base have no resolved permission level. These users appear in the billable user list but have neither an explicit workspace-level nor base-level permission entry. They may have access through groups, shared links, or inherited org settings.`,
            recommendation: 'Verify actual access levels directly in Airtable\'s share settings for this base. Consider removing users who should no longer have access.',
          });
        }

        // Flag any base with more than 30 collaborators
        if (collabs.length > 30) {
          findings.push({
            audit_id:       cfg.auditId,
            severity:       'low',
            category:       'security',
            base_id:        baseId,
            title:          `${baseName} has ${collabs.length} collaborators`,
            detail:         'Bases with many collaborators are harder to manage and audit for access control.',
            recommendation: 'Review whether all collaborators still need access. Consider using workspace-level permissions for simpler management.',
          });
        }
      }
    }

    // -- Per-automation script analysis --------------------------------------
    for (const auto of baseAutomations) {
      const scripts: any[] = auto.script_sources ?? [];

      for (const script of scripts) {
        const code: string = script.code ?? '';
        if (!code) continue;

        const loc = linesOfCode(code);

        // SECURITY: no error handling
        if (!hasErrorHandling(code)) {
          findings.push({
            audit_id:       cfg.auditId,
            severity:       'high',
            category:       'security',
            base_id:        baseId,
            title:          `Script in "${auto.name}" has no error handling`,
            detail:         `Scripts without try/catch will silently fail or show generic errors to users.`,
            recommendation: 'Wrap the main logic in a try/catch block and use output.set() to surface errors.',
          });
        }

        // SECURITY: hardcoded IDs
        const hardcoded = hasHardcodedIds(code);
        if (hardcoded.length > 0) {
          const hasPat = hardcoded.some(h => h.includes('pat'));
          findings.push({
            audit_id:       cfg.auditId,
            severity:       hasPat ? 'critical' : 'medium',
            category:       'security',
            base_id:        baseId,
            title:          hasPat
              ? `Possible hardcoded PAT token in "${auto.name}" script`
              : `Hardcoded Airtable IDs in "${auto.name}" script`,
            detail:         `Found ${hardcoded.length} hardcoded identifier(s). ${hasPat ? 'A PAT token in script code is a serious security risk.' : 'Hardcoded IDs break when records are deleted or the base is duplicated.'}`,
            recommendation: hasPat
              ? 'Remove the PAT immediately. Use input.config() or environment-level secrets instead.'
              : 'Use input.config() to pass IDs dynamically instead of hardcoding them.',
          });
        }

        // HYGIENE: console.log left in
        if (hasConsoleLog(code)) {
          findings.push({
            audit_id:       cfg.auditId,
            severity:       'info',
            category:       'hygiene',
            base_id:        baseId,
            title:          `Debug console.log() found in "${auto.name}" script`,
            detail:         'console.log statements are likely leftover from development.',
            recommendation: 'Remove or comment out debug logging before considering the automation production-ready.',
          });
        }

        // COMPLEXITY: large script
        const complexity = scriptComplexity(code);
        if (complexity === 'high') {
          findings.push({
            audit_id:       cfg.auditId,
            severity:       'low',
            category:       'complexity',
            base_id:        baseId,
            title:          `Large script in "${auto.name}" (${loc} non-comment lines)`,
            detail:         'Very large scripts are hard to maintain and test.',
            recommendation: 'Consider breaking the script into smaller focused automations, or extracting reusable logic into input.config() driven modules.',
          });
        }
      }

      // AUTOMATION: no script but high step count
      if (!auto.has_scripts && auto.step_count > 8) {
        findings.push({
          audit_id:       cfg.auditId,
          severity:       'info',
          category:       'complexity',
          base_id:        baseId,
          title:          `Complex no-code automation "${auto.name}" (${auto.step_count} steps)`,
          detail:         `Automations with many steps without scripts can be hard to debug.`,
          recommendation: 'Document the purpose of each step. Consider splitting into smaller automations.',
        });
      }

      // HYGIENE: unnamed automation
      if (!auto.name || auto.name.trim() === '' || auto.name === 'Untitled Automation') {
        findings.push({
          audit_id:       cfg.auditId,
          severity:       'info',
          category:       'hygiene',
          base_id:        baseId,
          title:          `Unnamed automation in ${baseName}`,
          detail:         'Automations without meaningful names are hard to manage.',
          recommendation: 'Give every automation a clear, descriptive name.',
        });
      }

      // AUTOMATION: unmapped trigger type
      const trigId = auto.trigger_type_id ?? '';
      if (trigId && auto.trigger === trigId) {
        // trigger label fell through to raw ID - it's unmapped
        findings.push({
          audit_id:       cfg.auditId,
          severity:       'low',
          category:       'automation',
          base_id:        baseId,
          title:          `Unrecognised trigger type "${trigId}" in "${auto.name}"`,
          detail:         `The automation uses a trigger type ID that the auditor does not recognise. Check the automation in the Airtable UI to identify the actual trigger.`,
          recommendation: 'Manually verify this trigger in the Airtable automation editor and report the type ID so it can be added to the mapping.',
        });
      }

      // AUTOMATION: connected app trigger without identified app
      if (auto.trigger === 'connected app') {
        const cfg_ = auto.trigger_config as Record<string, any> | null;
        const appName = cfg_?.connectionName || cfg_?.appName || null;
        if (appName) {
          findings.push({
            audit_id:       cfg.auditId,
            severity:       'info',
            category:       'automation',
            base_id:        baseId,
            title:          `Connected app trigger in "${auto.name}": ${appName}`,
            detail:         `This automation is triggered by the connected app "${appName}".`,
            recommendation: null,
          });
        } else {
          findings.push({
            audit_id:       cfg.auditId,
            severity:       'low',
            category:       'automation',
            base_id:        baseId,
            title:          `Connected app trigger in "${auto.name}" (app not identified)`,
            detail:         `This automation uses a marketplace app trigger but the app name could not be extracted from the config. Check the automation in the Airtable UI.`,
            recommendation: 'Open this automation in Airtable to identify which marketplace app is connected.',
          });
        }
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Capture-gap findings: sync, shares, runs, integrations, row counts, users
  // ---------------------------------------------------------------------------

  // -- SYNC: failure and complexity -------------------------------------------
  if (syncLinks && syncLinks.length > 0) {
    const failedSyncs = syncLinks.filter((s: any) => s.last_failure_time && !s.last_success_time);
    const staleSyncs = syncLinks.filter((s: any) => {
      if (!s.last_success_time) return false;
      const age = Date.now() - new Date(s.last_success_time).getTime();
      return age > 7 * 24 * 60 * 60 * 1000; // > 7 days
    });
    const multiSource = syncLinks.filter((s: any) => s.is_multi_source);

    if (failedSyncs.length > 0) {
      findings.push({
        audit_id: cfg.auditId, severity: 'high', category: 'drift', base_id: null,
        title: `${failedSyncs.length} sync link(s) in failure state`,
        detail: failedSyncs.map((s: any) => `Table ${s.dest_table_id} in base ${s.dest_base_id}: last failure ${s.last_failure_time}`).join('\n'),
        recommendation: 'Check the source bases/views for these syncs. The shared view or source table may have been deleted or permissions revoked.',
      });
    }

    if (staleSyncs.length > 0) {
      findings.push({
        audit_id: cfg.auditId, severity: 'medium', category: 'drift', base_id: null,
        title: `${staleSyncs.length} sync link(s) have not synced in over 7 days`,
        detail: staleSyncs.map((s: any) => `Table ${s.dest_table_id}: last success ${s.last_success_time}`).join('\n'),
        recommendation: 'Stale syncs may indicate a broken source. Verify the sync is still needed and that the source view is accessible.',
      });
    }

    if (multiSource.length > 0) {
      findings.push({
        audit_id: cfg.auditId, severity: 'info', category: 'complexity', base_id: null,
        title: `${multiSource.length} multi-source synced table(s) detected`,
        detail: 'Tables syncing from multiple sources are harder to debug when data conflicts arise.',
        recommendation: null,
      });
    }

    findings.push({
      audit_id: cfg.auditId, severity: 'info', category: 'complexity', base_id: null,
      title: `Sync topology: ${syncLinks.length} sync link(s) across the environment`,
      detail: `Sources: ${[...new Set(syncLinks.map((s: any) => s.source_type))].join(', ')}`,
      recommendation: null,
    });
  }

  // -- SHARE LINKS: unprotected shares ----------------------------------------
  if (shareLinks && shareLinks.length > 0) {
    const unprotected = shareLinks.filter((s: any) => !s.is_password_protected && !s.is_domain_restricted);
    if (unprotected.length > 0) {
      findings.push({
        audit_id: cfg.auditId, severity: 'high', category: 'security', base_id: null,
        title: `${unprotected.length} publicly shared link(s) without password or domain restriction`,
        detail: unprotected.map((s: any) => `Base ${s.base_id}: ${s.kind || 'unknown type'} share ${s.share_id}`).join('\n'),
        recommendation: 'Add password protection or domain restrictions to shared links, especially for bases containing product data or financials.',
      });
    }
    findings.push({
      audit_id: cfg.auditId, severity: 'info', category: 'security', base_id: null,
      title: `${shareLinks.length} shared link(s) found across the environment`,
      detail: `Protected: ${shareLinks.length - unprotected.length}, Unprotected: ${unprotected.length}`,
      recommendation: null,
    });
  }

  // -- AUTOMATION RUNS: kill-list, watch-list, protect-list -------------------
  if (automationRuns && automationRuns.length > 0) {
    const allAutos = automations ?? [];
    const neverRan = automationRuns.filter((r: any) =>
      r.total_runs_sampled === 0 && r.runs_current_month === 0
    );
    const failing = automationRuns.filter((r: any) => r.failure_count > 0);
    const highFreq = automationRuns.filter((r: any) => r.runs_current_month > 100);

    // Kill-list: undeployed AND never ran
    const undeployedIds = new Set(allAutos.filter((a: any) => a.deployment_status === 'undeployed').map((a: any) => a.workflow_id));
    const killCandidates = neverRan.filter((r: any) => undeployedIds.has(r.workflow_id));
    if (killCandidates.length > 0) {
      const names = killCandidates.map((r: any) => {
        const auto = allAutos.find((a: any) => a.workflow_id === r.workflow_id);
        return auto?.name || r.workflow_id;
      });
      findings.push({
        audit_id: cfg.auditId, severity: 'medium', category: 'hygiene', base_id: null,
        title: `${killCandidates.length} automation(s) are undeployed and have never run (kill candidates)`,
        detail: names.join('\n'),
        recommendation: 'These automations appear to be abandoned drafts. Delete them to reduce clutter.',
      });
    }

    if (failing.length > 0) {
      const details = failing.map((r: any) => {
        const auto = allAutos.find((a: any) => a.workflow_id === r.workflow_id);
        return `${auto?.name || r.workflow_id}: ${r.failure_count}/${r.total_runs_sampled} failures (last run: ${r.last_run_status} at ${r.last_run_at})`;
      });
      findings.push({
        audit_id: cfg.auditId, severity: 'high', category: 'automation', base_id: null,
        title: `${failing.length} automation(s) have recent failures (watch-list)`,
        detail: details.join('\n'),
        recommendation: 'Review failing automations in the Airtable automation run history. Fix or disable automations with persistent errors.',
      });
    }

    if (highFreq.length > 0) {
      const details = highFreq.map((r: any) => {
        const auto = allAutos.find((a: any) => a.workflow_id === r.workflow_id);
        return `${auto?.name || r.workflow_id}: ${r.runs_current_month} runs this month`;
      });
      findings.push({
        audit_id: cfg.auditId, severity: 'info', category: 'automation', base_id: null,
        title: `${highFreq.length} high-frequency automation(s) (>100 runs/month, protect-list)`,
        detail: details.join('\n'),
        recommendation: 'These are critical automations. Document their purpose and ensure they have error handling.',
      });
    }
  }

  // -- INTEGRATION ENDPOINTS: inventory ---------------------------------------
  if (integrationEndpoints && integrationEndpoints.length > 0) {
    const byDomain: Record<string, number> = {};
    for (const ep of integrationEndpoints) {
      byDomain[ep.domain] = (byDomain[ep.domain] || 0) + 1;
    }
    const domainList = Object.entries(byDomain).sort((a, b) => b[1] - a[1])
      .map(([d, n]) => `${d} (${n})`).join(', ');

    findings.push({
      audit_id: cfg.auditId, severity: 'medium', category: 'security', base_id: null,
      title: `${integrationEndpoints.length} external integration endpoint(s) discovered across ${Object.keys(byDomain).length} domain(s)`,
      detail: domainList,
      recommendation: 'Verify all external integrations are authorized and documented. Unknown domains may indicate shadow integrations built by individual users.',
    });
  }

  // -- ROW COUNTS: approaching limits -----------------------------------------
  if (tableStats && tableStats.length > 0) {
    const ROW_LIMIT = 125_000; // Business plan limit per table
    const WARNING_THRESHOLD = 0.8;
    const nearLimit = tableStats.filter((ts: any) => ts.row_count && ts.row_count >= ROW_LIMIT * WARNING_THRESHOLD);
    if (nearLimit.length > 0) {
      findings.push({
        audit_id: cfg.auditId, severity: 'high', category: 'complexity', base_id: null,
        title: `${nearLimit.length} table(s) approaching or exceeding the ${ROW_LIMIT.toLocaleString()} row limit`,
        detail: nearLimit.map((ts: any) => `${ts.table_name || ts.table_id} in base ${ts.base_id}: ${ts.row_count?.toLocaleString()} rows (${Math.round((ts.row_count / ROW_LIMIT) * 100)}%)`).join('\n'),
        recommendation: 'Archive old records or split tables before hitting the limit. Row-cap breaches block new record creation.',
      });
    }
  }

  // -- FIELD FILL RATES: dead fields ------------------------------------------
  if (fieldStats && fieldStats.length > 0) {
    const deadFields = fieldStats.filter((fs: any) => fs.fill_rate !== null && fs.fill_rate < 5 && fs.sample_n >= 10);
    if (deadFields.length > 20) {
      // Group by base for readability
      const byBase: Record<string, number> = {};
      for (const df of deadFields) {
        byBase[df.base_id] = (byBase[df.base_id] || 0) + 1;
      }
      findings.push({
        audit_id: cfg.auditId, severity: 'low', category: 'hygiene', base_id: null,
        title: `${deadFields.length} field(s) with <5% fill rate (dead field candidates)`,
        detail: Object.entries(byBase).map(([bid, n]) => {
          const bn = (auditBases ?? []).find((b: any) => b.airtable_base_id === bid)?.base_name || bid;
          return `${bn}: ${n} near-empty field(s)`;
        }).join('\n'),
        recommendation: 'Review near-empty fields for cleanup. Fields that were never populated are safe to remove. Fields with very low usage may indicate abandoned features.',
      });
    }
  }

  // -- ADMIN USERS: ghost seats, 2FA gaps -------------------------------------
  if (adminUsers && adminUsers.length > 0) {
    // Ghost seats: status is not active
    const ghostSeats = adminUsers.filter((u: any) => u.status && u.status !== 'active');
    if (ghostSeats.length > 0) {
      findings.push({
        audit_id: cfg.auditId, severity: 'medium', category: 'security', base_id: null,
        title: `${ghostSeats.length} user(s) are not in active status`,
        detail: ghostSeats.map((u: any) => `${u.email || u.user_id}: status="${u.status}"`).join('\n'),
        recommendation: 'Review inactive users for potential seat savings. Deactivated users still count toward billing if not fully removed.',
      });
    }

    // 2FA gaps
    const no2fa = adminUsers.filter((u: any) => u.two_fa === false && u.status === 'active');
    if (no2fa.length > 0) {
      findings.push({
        audit_id: cfg.auditId, severity: 'medium', category: 'security', base_id: null,
        title: `${no2fa.length} active user(s) without two-factor authentication`,
        detail: no2fa.length <= 10 ? no2fa.map((u: any) => u.email || u.user_id).join('\n') : `${no2fa.length} users (list too long to show)`,
        recommendation: 'Enable 2FA enforcement at the enterprise level to protect against credential theft.',
      });
    }
  }

  // -- BILLING: seat utilization ----------------------------------------------
  if (billingSnapshots && billingSnapshots.length > 0) {
    const snap = billingSnapshots[0];
    if (snap.paid_seats && adminUsers && adminUsers.length > 0) {
      const activeUsers = adminUsers.filter((u: any) => u.status === 'active').length;
      const utilization = activeUsers / snap.paid_seats;
      if (utilization < 0.7) {
        findings.push({
          audit_id: cfg.auditId, severity: 'medium', category: 'security', base_id: null,
          title: `Seat utilization at ${Math.round(utilization * 100)}% (${activeUsers} active / ${snap.paid_seats} paid)`,
          detail: `${snap.paid_seats - activeUsers} paid seat(s) are not being used by active users.`,
          recommendation: 'Review whether paid seats can be reduced at next renewal to match actual active user count.',
        });
      }
    }
  }

  // -- INTERFACES: summary ----------------------------------------------------
  if (interfaces && interfaces.length > 0) {
    // Count per base
    const ifByBase: Record<string, number> = {};
    for (const iface of interfaces) {
      ifByBase[iface.base_id] = (ifByBase[iface.base_id] || 0) + 1;
    }
    findings.push({
      audit_id: cfg.auditId, severity: 'info', category: 'complexity', base_id: null,
      title: `${interfaces.length} interface(s) across ${Object.keys(ifByBase).length} base(s)`,
      detail: Object.entries(ifByBase).sort((a, b) => b[1] - a[1]).slice(0, 10)
        .map(([bid, n]) => {
          const bn = (auditBases ?? []).find((b: any) => b.airtable_base_id === bid)?.base_name || bid;
          return `${bn}: ${n}`;
        }).join('\n'),
      recommendation: null,
    });
  }

  // -- PORTAL GUESTS: from admin users with portal/guest seat type -----------
  if (adminUsers && adminUsers.length > 0) {
    const portalUsers = adminUsers.filter((u: any) =>
      u.role && (u.role.toLowerCase().includes('portal') || u.role.toLowerCase().includes('guest'))
    );
    if (portalUsers.length > 0) {
      findings.push({
        audit_id: cfg.auditId, severity: 'info', category: 'security', base_id: null,
        title: `${portalUsers.length} portal/guest user(s) detected`,
        detail: portalUsers.length <= 20
          ? portalUsers.map((u: any) => `${u.email || u.user_id} (${u.role})`).join('\n')
          : `${portalUsers.length} portal/guest users (too many to list)`,
        recommendation: 'Review portal guest access against active interface usage. Unused portal slots are billable.',
      });
    }
  }

  // -- AI FIELDS: count aiText fields from schema (DERIVE 2.6) ---------------
  {
    let aiFieldCount = 0;
    const aiFieldBases: string[] = [];
    for (const schema of (schemas ?? [])) {
      const tables = schema.tables ?? [];
      let baseHasAi = false;
      for (const table of tables) {
        for (const field of (table.fields ?? [])) {
          if (field.type === 'aiText') {
            aiFieldCount++;
            baseHasAi = true;
          }
        }
      }
      if (baseHasAi) {
        const bn = (auditBases ?? []).find((b: any) => b.airtable_base_id === schema.base_id)?.base_name || schema.base_id;
        aiFieldBases.push(bn);
      }
    }
    if (aiFieldCount > 0) {
      findings.push({
        audit_id: cfg.auditId, severity: 'info', category: 'complexity', base_id: null,
        title: `${aiFieldCount} AI text field(s) across ${aiFieldBases.length} base(s)`,
        detail: `Bases with AI fields: ${aiFieldBases.join(', ')}`,
        recommendation: 'AI fields consume credits from the Airtable AI add-on. Verify usage is intentional and concentrated where it adds value.',
      });
    }
  }

  // -- RECORD STALENESS: zombie tables from sample timestamps (3.3) ----------
  if (recordSamples && recordSamples.length > 0) {
    const ninetyDaysAgo = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);
    const zombieTables: string[] = [];

    for (const sample of recordSamples) {
      const records = sample.sample || [];
      if (records.length < 5) continue; // skip tiny samples

      // Check if all sampled records are older than 90 days
      const timestamps = records
        .map((r: any) => r.createdTime)
        .filter(Boolean)
        .map((t: string) => new Date(t));

      if (timestamps.length === 0) continue;

      const newest = new Date(Math.max(...timestamps.map((d: Date) => d.getTime())));
      if (newest < ninetyDaysAgo) {
        const baseName = (auditBases ?? []).find((b: any) => b.airtable_base_id === sample.base_id)?.base_name || sample.base_id;
        const tableName = sample.table_name || sample.table_id;
        const ageInDays = Math.round((Date.now() - newest.getTime()) / (24 * 60 * 60 * 1000));
        zombieTables.push(`${baseName} / ${tableName}: newest record is ${ageInDays} days old`);
      }
    }

    if (zombieTables.length > 0) {
      findings.push({
        audit_id: cfg.auditId, severity: 'low', category: 'hygiene', base_id: null,
        title: `${zombieTables.length} table(s) with no new records in 90+ days (potential zombie tables)`,
        detail: zombieTables.slice(0, 20).join('\n') + (zombieTables.length > 20 ? `\n...and ${zombieTables.length - 20} more` : ''),
        recommendation: 'Tables with no recent activity may be candidates for archiving. Verify with stakeholders before removing.',
      });
    }
  }

  // -- AUTOMATION AUTHORSHIP: knowledge concentration (2.2) -------------------
  if (automations && automations.length > 0) {
    const deployedWithAuthor = (automations ?? []).filter((a: any) => a.created_by_user_id);
    if (deployedWithAuthor.length > 0) {
      const authorCounts: Record<string, number> = {};
      for (const a of deployedWithAuthor) {
        authorCounts[a.created_by_user_id] = (authorCounts[a.created_by_user_id] || 0) + 1;
      }
      const sorted = Object.entries(authorCounts).sort((a, b) => b[1] - a[1]);
      const topAuthor = sorted[0];
      const topPct = Math.round((topAuthor[1] / deployedWithAuthor.length) * 100);

      if (topPct >= 60 && deployedWithAuthor.length >= 5) {
        const authorUser = (adminUsers ?? []).find((u: any) => u.user_id === topAuthor[0]);
        const authorName = authorUser?.email || authorUser?.display_name || topAuthor[0];
        findings.push({
          audit_id: cfg.auditId, severity: 'medium', category: 'security', base_id: null,
          title: `Knowledge concentration: ${topPct}% of automations created by a single user`,
          detail: `${authorName} created ${topAuthor[1]} of ${deployedWithAuthor.length} deployed automations.`,
          recommendation: 'Cross-train team members on automation maintenance. A single point of failure for automation knowledge is a business risk.',
        });
      }
    }
  }

  // -- AI CONSUMPTION: per-base credit usage (2.6) ----------------------------
  {
    const basesWithAi = (schemas ?? []).filter((s: any) => s.ai_credits_month && s.ai_credits_month > 0);
    if (basesWithAi.length > 0) {
      const totalCredits = basesWithAi.reduce((sum: number, s: any) => sum + (s.ai_credits_month || 0), 0);
      findings.push({
        audit_id: cfg.auditId, severity: 'info', category: 'complexity', base_id: null,
        title: `AI credit consumption: ${totalCredits} credits this month across ${basesWithAi.length} base(s)`,
        detail: basesWithAi.sort((a: any, b: any) => (b.ai_credits_month || 0) - (a.ai_credits_month || 0))
          .map((s: any) => { const bn = (auditBases ?? []).find((b: any) => b.airtable_base_id === s.base_id)?.base_name || s.base_id; return `${bn}: ${s.ai_credits_month} credits`; }).join('\n'),
        recommendation: 'Review which bases consume AI credits. Concentrated usage may allow scoping down the add-on.',
      });
    }
  }

  // -- EXTENSIONS: inventory from DOM scrape + flag (2.3) ----------------------
  const { data: extensions } = await client.from('extensions').select('*').eq('audit_id', cfg.auditId);
  {
    if (extensions && extensions.length > 0) {
      const byBase: Record<string, string[]> = {};
      for (const ext of extensions) {
        const bn = (auditBases ?? []).find((b: any) => b.airtable_base_id === ext.base_id)?.base_name || ext.base_id;
        if (!byBase[bn]) byBase[bn] = [];
        byBase[bn].push(ext.extension_name || 'unnamed');
      }
      const scriptExts = extensions.filter((e: any) => e.is_scripting);
      findings.push({
        audit_id: cfg.auditId, severity: scriptExts.length > 0 ? 'medium' : 'info', category: 'complexity', base_id: null,
        title: `${extensions.length} extension(s) found across ${Object.keys(byBase).length} base(s)${scriptExts.length > 0 ? `, including ${scriptExts.length} scripting extension(s)` : ''}`,
        detail: Object.entries(byBase).map(([bn, names]) => `${bn}: ${names.join(', ')}`).join('\n'),
        recommendation: scriptExts.length > 0
          ? 'Scripting extensions contain custom code that should be reviewed for security, API usage, and maintainability alongside automation scripts.'
          : 'Extensions can contain third-party integrations. Verify all installed extensions are authorized.',
      });
    } else {
      // Fall back to boolean flag
      const basesWithExt = (schemas ?? []).filter((s: any) => s.has_extensions === true);
      if (basesWithExt.length > 0) {
        findings.push({
          audit_id: cfg.auditId, severity: 'info', category: 'complexity', base_id: null,
          title: `${basesWithExt.length} base(s) have extensions/blocks installed`,
          detail: basesWithExt.map((s: any) => (auditBases ?? []).find((b: any) => b.airtable_base_id === s.base_id)?.base_name || s.base_id).join(', '),
          recommendation: 'Extensions can contain custom code and third-party integrations. Inventory installed extensions for security awareness.',
        });
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Write findings (delete old ones first)
  // ---------------------------------------------------------------------------
  await client.from('findings').delete().eq('audit_id', cfg.auditId);

  if (findings.length > 0) {
    await client.from('findings').insert(findings);
  }

  console.log(`[analysis] ${findings.length} finding(s) written for audit ${cfg.auditId}`);
}
