import assert from 'node:assert/strict';
import test from 'node:test';
import { RateLimitedError, rateLimitedFetch, statedWaitMs } from './rate-limited-fetch.ts';

test('separate callers wait for the same host deadline and never retry a 429 automatically', async () => {
  const times: number[] = [];
  const fetchFn = (async () => {
    times.push(Date.now());
    return times.length === 1
      ? new Response('', { status: 429, headers: { 'retry-after': '0.04' } })
      : Response.json({ accepted: true });
  }) as typeof fetch;
  await assert.rejects(rateLimitedFetch('https://shared-quota.invalid/first', {}, fetchFn), RateLimitedError);
  assert.equal(times.length, 1);
  const result = await rateLimitedFetch('https://shared-quota.invalid/second', {}, fetchFn);
  assert.deepEqual(await result.json(), { accepted: true });
  assert.equal(times.length, 2);
  assert.ok(times[1]! - times[0]! >= 40, 'removing the shared wait must fail this timing assertion');
});

test('successful exhausted-quota responses prevent the next request when the wait is too long', async () => {
  let requests = 0;
  const fetchFn = (async () => {
    requests++;
    return new Response('page one', { headers: { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset-after': '120' } });
  }) as typeof fetch;
  const first = await rateLimitedFetch('https://exhausted-quota.invalid/first', {}, fetchFn);
  assert.equal(await first.text(), 'page one');
  await assert.rejects(rateLimitedFetch('https://exhausted-quota.invalid/second', {}, fetchFn), (error: unknown) => {
    assert.ok(error instanceof RateLimitedError);
    assert.ok(error.retryAfterMs > 119000);
    return true;
  });
  assert.equal(requests, 1);
});

test('429 without a stated wait stops further calls rather than hammering the host', async () => {
  let requests = 0;
  const fetchFn = (async () => { requests++; return new Response('', { status: 429 }); }) as typeof fetch;
  await assert.rejects(rateLimitedFetch('https://unknown-quota.invalid/first', {}, fetchFn), RateLimitedError);
  await assert.rejects(rateLimitedFetch('https://unknown-quota.invalid/second', {}, fetchFn), RateLimitedError);
  assert.equal(requests, 1);
});

test('HTTP dates, epoch resets, relative resets and structured body delays preserve the longest wait', async () => {
  const now = Date.UTC(2026, 9, 5, 0, 0, 0);
  assert.equal(await statedWaitMs(new Response('', { headers: { 'retry-after': new Date(now + 60000).toUTCString() } }), now), 60000);
  assert.equal(await statedWaitMs(new Response('', { headers: { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': String((now + 20000) / 1000) } }), now), 20000);
  assert.equal(await statedWaitMs(new Response('', { headers: { 'ratelimit-remaining': '0', 'ratelimit-reset': '2.5' } }), now), 2500);
  const error = Response.json({ retry_after: 3, error: { details: [{ '@type': 'type.googleapis.com/google.rpc.RetryInfo', retryDelay: '4.5s' }] } }, { status: 429, headers: { 'retry-after': '1' } });
  assert.equal(await statedWaitMs(error, now), 4500);
});

test('reset headers with positive remaining quota do not block healthy responses', async () => {
  const response = new Response('', { headers: { 'x-ratelimit-remaining': '10', 'x-ratelimit-reset': '120', 'x-ratelimit-reset-after': '120', 'ratelimit-remaining': '5', 'ratelimit-reset': '60' } });
  assert.equal(await statedWaitMs(response), null);
});

test('healthy responses with reset windows but no exhausted quota do not block callers', async () => {
  assert.equal(await statedWaitMs(new Response('', { headers: { 'x-ratelimit-reset-after': '120', 'ratelimit-reset': '60' } })), null);
  assert.equal(await statedWaitMs(new Response('', { status: 429, headers: { 'x-ratelimit-reset-after': '120' } })), 120000);
});
