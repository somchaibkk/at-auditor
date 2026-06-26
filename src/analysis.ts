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

function db(cfg: AnalysisConfig): SupabaseClient {
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

  const baseIds = (auditBases ?? []).map((b: any) => b.airtable_base_id as string);

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
