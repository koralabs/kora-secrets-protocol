// Process-wide HTTP gate: a later call, including from another provider instance,
// must honor the wait already stated by this host. Requests are never retried here.
const blockedUntil = new Map<string, number>();

export class RateLimitedError extends Error {
  readonly retryAfterMs: number;

  constructor(retryAfterMs: number) {
    super(Number.isFinite(retryAfterMs)
      ? `HTTP rate limit: retry after ${Math.ceil(retryAfterMs / 1000)}s`
      : 'HTTP rate limit without a stated wait; stop requests');
    this.name = 'RateLimitedError';
    this.retryAfterMs = retryAfterMs;
  }
}

const seconds = (raw: unknown): number | null => {
  if (raw == null || String(raw).trim() === '') return null;
  const value = Number(String(raw).replace(/s$/, ''));
  return Number.isFinite(value) && value >= 0 ? value * 1000 : null;
};

const resetDelay = (raw: string | null, now: number): number | null => {
  const ms = seconds(raw);
  if (ms === null) return null;
  const value = ms / 1000;
  return value > 1e12 ? Math.max(0, value - now)
    : value > 1e9 ? Math.max(0, ms - now) : ms;
};

export async function statedWaitMs(response: Response, now = Date.now()): Promise<number | null> {
  const h = response.headers;
  const retry = h.get('retry-after');
  const numericRetry = seconds(retry);
  const dateRetry = retry && Number.isFinite(Date.parse(retry)) ? Math.max(0, Date.parse(retry) - now) : null;
  const waits: (number | null)[] = [numericRetry ?? dateRetry];
  for (const [reset, remaining, relative] of [
    ['x-ratelimit-reset-after', 'x-ratelimit-remaining', true],
    ['x-ratelimit-reset', 'x-ratelimit-remaining', false],
    ['ratelimit-reset', 'ratelimit-remaining', false]
  ] as const) {
    const quota = h.get(remaining);
    if (response.status !== 429 && (quota === null || Number(quota) !== 0)) continue;
    waits.push(relative ? seconds(h.get(reset)) : resetDelay(h.get(reset), now));
  }
  if (!response.ok) {
    try {
      const body: unknown = await response.clone().json();
      for (const item of Array.isArray(body) ? body : [body]) {
        if (!item || typeof item !== 'object') continue;
        const record = item as { retry_after?: unknown; error?: { details?: unknown } };
        waits.push(seconds(record.retry_after));
        if (!Array.isArray(record.error?.details)) continue;
        for (const detail of record.error.details) {
          if (detail && typeof detail === 'object' && String(detail['@type'] ?? '').endsWith('RetryInfo')) {
            waits.push(seconds(detail.retryDelay));
          }
        }
      }
    } catch { /* A non-JSON error body carries no structured wait. */ }
  }
  const known = waits.filter((wait): wait is number => wait !== null);
  return known.length ? Math.max(...known) : response.status === 429 ? Infinity : null;
}

export async function rateLimitedFetch(
  url: string,
  init: RequestInit,
  fetchFn: typeof fetch = fetch
): Promise<Response> {
  const key = new URL(url).origin;
  for (let wait = (blockedUntil.get(key) ?? 0) - Date.now(); wait > 0; wait = (blockedUntil.get(key) ?? 0) - Date.now()) {
    if (wait > 5000) throw new RateLimitedError(wait);
    await new Promise((resolve) => setTimeout(resolve, wait));
  }
  const response = await fetchFn(url, init);
  const wait = await statedWaitMs(response);
  if (wait !== null) blockedUntil.set(key, Math.max(blockedUntil.get(key) ?? 0, Date.now() + wait));
  if (response.status === 429) throw new RateLimitedError(wait ?? Infinity);
  return response;
}
