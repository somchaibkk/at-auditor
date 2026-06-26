// engine-pat.ts
// ---------------------------------------------------------------------------
// Engine 1: the PAT backbone. Uses the OFFICIAL, documented Airtable API.
// Runs fully unattended in plain Node. CORS is irrelevant server-side.
// Works on every plan, not just enterprise. This is the reliable backbone.
//
// Endpoints used (all official & documented):
//   GET /v0/meta/bases                          -> list bases (paginated, offset)
//   GET /v0/meta/bases/{baseId}/tables          -> schema: tables, fields, views
//   GET /v0/{baseId}/{tableIdOrName}?pageSize=N  -> records (we sample, not pull all)
//
// Enterprise-only extras (collaborators, users, audit log) live behind the
// enterprise flag and degrade gracefully to null when the token lacks scope.
// ---------------------------------------------------------------------------

import { RateLimiter } from './rate-limiter.js';

const API = 'https://api.airtable.com';

export interface BaseSummary {
  id: string;
  name: string;
  permissionLevel?: string;
}

export class PatEngine {
  constructor(
    private readonly pat: string,
    private readonly limiter: RateLimiter,
  ) {}

  private async get(path: string): Promise<any> {
    await this.limiter.acquire();
    const res = await fetch(`${API}${path}`, {
      headers: { Authorization: `Bearer ${this.pat}` },
    });
    if (res.status === 429) {
      // Backoff and retry once. The limiter should prevent this, but bases
      // can share token budget under load.
      await new Promise((r) => setTimeout(r, 1500));
      return this.get(path);
    }
    if (!res.ok) {
      throw new Error(`Airtable API ${res.status} on ${path}: ${await res.text()}`);
    }
    return res.json();
  }

  // ---- discovery -----------------------------------------------------------
  async listAllBases(): Promise<BaseSummary[]> {
    const bases: BaseSummary[] = [];
    let offset: string | undefined;
    do {
      const q = offset ? `?offset=${offset}` : '';
      const page = await this.get(`/v0/meta/bases${q}`);
      for (const b of page.bases ?? []) {
        bases.push({ id: b.id, name: b.name, permissionLevel: b.permissionLevel });
      }
      offset = page.offset;
    } while (offset);
    return bases;
  }

  // ---- schema --------------------------------------------------------------
  async getBaseSchema(baseId: string): Promise<{ tables: any[]; tableCount: number; fieldCount: number }> {
    const tables: any[] = [];
    let offset: string | undefined;
    do {
      const q = offset ? `?offset=${offset}` : '';
      const page = await this.get(`/v0/meta/bases/${baseId}/tables${q}`);
      tables.push(...(page.tables ?? []));
      offset = page.offset;
    } while (offset);

    const fieldCount = tables.reduce((n, t) => n + (t.fields?.length ?? 0), 0);
    return { tables, tableCount: tables.length, fieldCount };
  }

  // ---- record sampling (capped, never a full pull) -------------------------
  async sampleTable(
    baseId: string,
    tableId: string,
    sampleSize: number,
  ): Promise<{ sample: any[]; sampledCount: number; hasMore: boolean }> {
    // One page up to sampleSize. The presence of an offset on the response
    // tells us the table has more rows than we sampled -> has_more flag.
    const size = Math.min(Math.max(sampleSize, 1), 100); // API page cap is 100
    const page = await this.get(`/v0/${baseId}/${encodeURIComponent(tableId)}?pageSize=${size}`);
    const sample = page.records ?? [];
    return {
      sample,
      sampledCount: sample.length,
      hasMore: Boolean(page.offset),
    };
  }

  // ---- enterprise extras (optional, scope-gated) ---------------------------
  async getBaseCollaborators(baseId: string): Promise<any | null> {
    try {
      // Documented field via ?include=collaborators on the base meta.
      const data = await this.get(`/v0/meta/bases/${baseId}?include=collaborators`);
      return data.collaborators ?? null;
    } catch {
      // Token lacks enterprise scope, or not an enterprise base. Degrade quietly.
      return null;
    }
  }
}
