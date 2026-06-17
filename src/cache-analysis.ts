// Cache behavior analysis — Cache-Control, Vary, CDN detection

import type { CacheResult, Finding } from './types';

/** Analyze cache behavior from response headers */
export function analyzeCacheBehavior(headers: Headers): CacheResult {
  const issues: Finding[] = [];

  // ── Cache-Control ─────────────────────────────────────────────────
  const ccRaw = headers.get('Cache-Control');
  const parsed = parseCC(ccRaw);
  const effectiveTTL = computeTTL(parsed, headers);
  const explanation = explainCC(parsed, effectiveTTL);

  // ── Vary ──────────────────────────────────────────────────────────
  const varyRaw = headers.get('Vary');
  const vary = varyRaw ? varyRaw.split(',').map(v => v.trim()).filter(Boolean) : [];

  if (vary.includes('*')) {
    issues.push({
      severity: 'warning',
      code: 'VARY_STAR',
      message: 'Vary: * makes the response uncacheable. Every request is treated as unique.',
      fix: 'Replace Vary: * with the specific headers that affect the response (e.g., Vary: Accept-Encoding, Accept).',
      mdn: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Vary',
    });
  }

  // ── CDN detection ─────────────────────────────────────────────────
  const { status: cdnStatus, provider: cdnProvider } = detectCDN(headers);

  // ── Issues ────────────────────────────────────────────────────────
  if (!ccRaw) {
    issues.push({
      severity: 'info',
      code: 'NO_CACHE_CONTROL',
      message: 'No Cache-Control header. Browsers and CDNs will use heuristic caching based on Last-Modified.',
      fix: 'Set an explicit Cache-Control header. For static assets: public, max-age=31536000, immutable. For HTML: no-cache or public, max-age=0, must-revalidate.',
      mdn: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control',
    });
  }

  if (parsed['no-store'] && parsed['max-age'] !== undefined) {
    issues.push({
      severity: 'warning',
      code: 'CONFLICTING_DIRECTIVES',
      message: 'Cache-Control has both no-store and max-age. no-store takes precedence — the max-age is ignored.',
      fix: 'Remove max-age if you intend no-store, or remove no-store if you want caching.',
    });
  }

  if (parsed['public'] && parsed['no-store']) {
    issues.push({
      severity: 'warning',
      code: 'PUBLIC_NO_STORE',
      message: 'Cache-Control has both public and no-store. These conflict — no-store wins.',
      fix: 'Remove public if you intend no-store.',
    });
  }

  return {
    cache_control: ccRaw,
    parsed,
    effective_ttl: effectiveTTL,
    vary,
    cdn_status: cdnStatus,
    cdn_provider: cdnProvider,
    issues,
    explanation,
  };
}

// ── Cache-Control parser ────────────────────────────────────────────

function parseCC(raw: string | null): Record<string, string | boolean | number> {
  const result: Record<string, string | boolean | number> = {};
  if (!raw) return result;

  const directives = raw.split(',').map(d => d.trim()).filter(Boolean);
  for (const d of directives) {
    const eqIdx = d.indexOf('=');
    if (eqIdx === -1) {
      result[d.toLowerCase()] = true;
    } else {
      const key = d.slice(0, eqIdx).trim().toLowerCase();
      const val = d.slice(eqIdx + 1).trim().replace(/^"|"$/g, '');
      const num = parseInt(val, 10);
      result[key] = isNaN(num) ? val : num;
    }
  }

  return result;
}

// ── TTL computation ─────────────────────────────────────────────────

function computeTTL(parsed: Record<string, string | boolean | number>, headers: Headers): number | null {
  if (parsed['no-store']) return 0;
  if (parsed['no-cache']) return 0;

  // s-maxage takes precedence for shared caches
  if (typeof parsed['s-maxage'] === 'number') return parsed['s-maxage'];
  if (typeof parsed['max-age'] === 'number') return parsed['max-age'];

  // Fall back to Expires header
  const expires = headers.get('Expires');
  if (expires) {
    const expDate = new Date(expires).getTime();
    const date = new Date(headers.get('Date') || Date.now()).getTime();
    if (!isNaN(expDate)) {
      return Math.max(0, Math.round((expDate - date) / 1000));
    }
  }

  return null; // Unknown — heuristic caching applies
}

// ── Human-readable explanation ──────────────────────────────────────

function explainCC(parsed: Record<string, string | boolean | number>, ttl: number | null): string {
  const parts: string[] = [];

  if (parsed['no-store']) {
    parts.push('Not cached anywhere — every request goes to the server.');
  } else if (parsed['no-cache']) {
    parts.push('Cached but always revalidated with the server before use.');
  } else if (parsed['private']) {
    parts.push('Cached by the browser only (not shared caches like CDNs).');
  } else if (parsed['public']) {
    parts.push('Cacheable by browsers and CDNs.');
  }

  if (ttl !== null && ttl > 0) {
    parts.push(`Fresh for ${formatDuration(ttl)}.`);
  }

  if (parsed['must-revalidate']) {
    parts.push('Must revalidate with the server once stale.');
  }

  if (parsed['immutable']) {
    parts.push('Marked immutable — browsers won\'t revalidate even on reload.');
  }

  if (parsed['stale-while-revalidate']) {
    parts.push(`Can serve stale content for ${formatDuration(parsed['stale-while-revalidate'] as number)} while revalidating in the background.`);
  }

  if (parts.length === 0) {
    return 'No explicit cache policy. Browsers will use heuristic caching.';
  }

  return parts.join(' ');
}

function formatDuration(seconds: number): string {
  if (seconds >= 86400) {
    const days = Math.round(seconds / 86400);
    return `${days} day${days !== 1 ? 's' : ''}`;
  }
  if (seconds >= 3600) {
    const hours = Math.round(seconds / 3600);
    return `${hours} hour${hours !== 1 ? 's' : ''}`;
  }
  if (seconds >= 60) {
    const mins = Math.round(seconds / 60);
    return `${mins} minute${mins !== 1 ? 's' : ''}`;
  }
  return `${seconds} second${seconds !== 1 ? 's' : ''}`;
}

// ── CDN detection ───────────────────────────────────────────────────

function detectCDN(headers: Headers): { status: string | null; provider: string | null } {
  // Cloudflare
  const cfCacheStatus = headers.get('CF-Cache-Status');
  if (cfCacheStatus) return { status: cfCacheStatus, provider: 'Cloudflare' };
  if (headers.get('CF-Ray')) return { status: null, provider: 'Cloudflare' };

  // AWS CloudFront
  const xCache = headers.get('X-Cache');
  if (headers.get('X-Amz-Cf-Id') || headers.get('X-Amz-Cf-Pop')) {
    return { status: xCache, provider: 'CloudFront' };
  }

  // Fastly
  if (headers.get('X-Served-By')?.includes('cache-')) {
    return { status: headers.get('X-Cache'), provider: 'Fastly' };
  }

  // Vercel
  if (headers.get('X-Vercel-Id') || headers.get('X-Vercel-Cache')) {
    return { status: headers.get('X-Vercel-Cache'), provider: 'Vercel' };
  }

  // Netlify
  if (headers.get('X-NF-Request-ID') || headers.get('X-Netlify-Request-ID')) {
    return { status: headers.get('X-Cache'), provider: 'Netlify' };
  }

  // Akamai
  if (headers.get('X-Akamai-Transformed')) {
    return { status: xCache, provider: 'Akamai' };
  }

  // Generic X-Cache header
  if (xCache) {
    return { status: xCache, provider: null };
  }

  const age = headers.get('Age');
  if (age) {
    return { status: `Age: ${age}s`, provider: null };
  }

  return { status: null, provider: null };
}
