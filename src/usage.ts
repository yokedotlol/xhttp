// Usage tracking — simple scan counter (matches certs-lol pattern)

import type { Env } from './worker';

export async function trackScan(env: Env, target: string, ctx: ExecutionContext): Promise<void> {
  const date = new Date().toISOString().slice(0, 10);
  const key = `usage:${date}`;

  ctx.waitUntil(
    (async () => {
      try {
        const current = await env.CACHE.get(key);
        const count = current ? parseInt(current, 10) + 1 : 1;
        await env.CACHE.put(key, String(count), { expirationTtl: 86400 * 7 }); // 7-day retention
      } catch {
        // Non-critical — don't fail the request
      }
    })()
  );
}

export async function handleUsage(env: Env): Promise<Response> {
  const today = new Date().toISOString().slice(0, 10);
  const days: { date: string; scans: number }[] = [];

  for (let i = 0; i < 7; i++) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    const date = d.toISOString().slice(0, 10);
    const count = await env.CACHE.get(`usage:${date}`);
    days.push({ date, scans: count ? parseInt(count, 10) : 0 });
  }

  return new Response(JSON.stringify({ days, generated: today }, null, 2), {
    headers: { 'Content-Type': 'application/json' },
  });
}
