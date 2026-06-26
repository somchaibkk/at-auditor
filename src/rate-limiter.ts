// rate-limiter.ts
// ---------------------------------------------------------------------------
// Minimal token-bucket pacer. The official Airtable API caps at 5 req/s
// (per token on the free/team tier; higher on pro/enterprise). We pace to the
// configured ceiling and add small jitter so bursts across many bases don't
// line up and trip the limiter. Same lesson as the QQapp probe jitter fix.
// ---------------------------------------------------------------------------

export class RateLimiter {
  private queue: Array<() => void> = [];
  private tokens: number;
  private readonly max: number;
  private readonly refillMs: number;

  constructor(requestsPerSecond: number) {
    this.max = requestsPerSecond;
    this.tokens = requestsPerSecond;
    this.refillMs = 1000 / requestsPerSecond;
    setInterval(() => {
      this.tokens = Math.min(this.max, this.tokens + 1);
      this.drain();
    }, this.refillMs);
  }

  private drain() {
    while (this.tokens > 0 && this.queue.length > 0) {
      this.tokens--;
      const next = this.queue.shift();
      next?.();
    }
  }

  async acquire(): Promise<void> {
    const jitter = Math.random() * 40; // 0-40ms
    await new Promise<void>((resolve) => {
      this.queue.push(resolve);
      this.drain();
    });
    await new Promise((r) => setTimeout(r, jitter));
  }
}
