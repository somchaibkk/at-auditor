// config.ts
// ---------------------------------------------------------------------------
// Worker configuration and the credential-handling contract.
//
// CREDENTIAL RULE: prospect credentials (PAT and browser session) exist only
// in memory for the lifetime of one audit run. Never written to the DB.
// ---------------------------------------------------------------------------

export interface WorkerConfig {
  // Control-plane Supabase (QQapp project, audit schema).
  supabaseUrl:            string;
  supabaseServiceRoleKey: string;

  // The audit this worker run is servicing.
  auditId: string;

  // Collection tuning.
  recordSampleSize:      number;  // cap per table; default 25
  patRequestsPerSecond:  number;  // official API hard limit is 5/s
  enterpriseModule:      boolean; // pull collaborators if scope allows
}

// Prospect credentials -- held in memory only, never persisted.
export interface ProspectCredentials {
  // Engine 1 (official API).
  pat: string;

  // Engine 2 (session). Operator logs in once via the persistent browser
  // profile; the profile is reused for subsequent runs. No raw cookie strings.
  browserProfileDir: string;  // e.g. C:/audi/browser-profile
}

export function loadConfig(): WorkerConfig {
  const required = (name: string): string => {
    const v = process.env[name];
    if (!v) throw new Error(`Missing required env var: ${name}`);
    return v;
  };

  return {
    supabaseUrl:            required('SUPABASE_URL'),
    supabaseServiceRoleKey: required('SUPABASE_SERVICE_ROLE_KEY'),
    auditId:                required('AUDIT_ID'),
    recordSampleSize:       Number(process.env.RECORD_SAMPLE_SIZE ?? 25),
    patRequestsPerSecond:   Number(process.env.PAT_RPS ?? 5),
    enterpriseModule:       process.env.ENTERPRISE_MODULE === 'true',
  };
}
