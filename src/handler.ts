// Main request handler — routing, rate limiting, security headers, caching

import type { Env } from './worker';
import type { ScanResult, CORSSimulationRequest, CORSErrorDecodeRequest, CSPEvaluateRequest } from './types';
import { USER_AGENT } from './constants';
import { analyzeCORS, simulateCORS } from './cors';
import { evaluateCSP, evaluateCSPString } from './csp';
import { analyzeSecurityHeaders } from './headers';
import { followRedirects } from './redirect';
import { analyzeCacheBehavior } from './cache-analysis';
import { decodeCORSError } from './cors-error-decoder';
import { trackScan, handleUsage } from './usage';
import { fetchDomainSignals } from './services/domain-intel';

const VERSION = '1.0.0';
const CACHE_TTL = 3600; // 1 hour
const RATE_LIMIT = 60;

const SECURITY_HEADERS: Record<string, string> = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '0',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Embedder-Policy': 'credentialless',
};

function cspWithNonce(nonce: string): string {
  return `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self'; img-src 'self' data: https://yoke.lol; frame-ancestors 'none'; base-uri 'self'`;
}

function secHeaders(nonce: string): Record<string, string> {
  return {
    ...SECURITY_HEADERS,
    'Content-Security-Policy': cspWithNonce(nonce),
  };
}

function jsonResponse(data: unknown, status = 200, extra?: Record<string, string>): Response {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'public, max-age=300',
    ...SECURITY_HEADERS,
    'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
    ...(extra || {}),
  };
  return new Response(JSON.stringify(data, null, 2), { status, headers });
}

function isIP(s: string): boolean {
  return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(s) || s.includes(':');
}

function normalizeDomain(raw: string): string | null {
  let d = raw.toLowerCase().trim();
  d = d.replace(/^https?:\/\//, '');
  d = d.replace(/\/.*$/, '');
  d = d.replace(/:\d+$/, '');
  if (!d || d.length > 253) return null;
  if (!/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/.test(d)) return null;
  return d;
}

export async function handleRequest(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  // ── Static routes ──────────────────────────────────────────────
  if (path === '/health') return jsonResponse({ status: 'ok', version: VERSION });
  if (path === '/robots.txt') return new Response(robotsTxt(), { headers: { 'Content-Type': 'text/plain' } });
  if (path === '/sitemap.xml') return new Response(sitemapXml(), { headers: { 'Content-Type': 'application/xml' } });
  if (path === '/security.txt' || path === '/.well-known/security.txt') return new Response(securityTxt(), { headers: { 'Content-Type': 'text/plain' } });
  if (path === '/llms.txt') return new Response(llmsTxt(), { headers: { 'Content-Type': 'text/plain' } });
  if (path === '/favicon.svg') return new Response(faviconSvg(), { headers: { 'Content-Type': 'image/svg+xml', 'Cache-Control': 'public, max-age=604800' } });
  if (path === '/.well-known/mta-sts.txt') return new Response(mtaSts(), { headers: { 'Content-Type': 'text/plain' } });
  if (path === '/install.sh') return Response.redirect('https://raw.githubusercontent.com/yokedotlol/preflight/main/cli/install.sh', 302);
  if (path === '/usage' && request.headers.get('Authorization') === `Bearer ${env.ADMIN_KEY}`) return handleUsage(env);

  // ── POST endpoints ─────────────────────────────────────────────
  if (method === 'POST') {
    // Rate limit
    const rl = await checkRateLimit(request, env);
    if (rl) return rl;

    if (path === '/cors') return handleCORSSimulation(request);
    if (path === '/error') return handleCORSErrorDecode(request);
    if (path === '/csp/evaluate') return handleCSPEvaluate(request);
    return jsonResponse({ error: 'Not found' }, 404);
  }

  // ── GET: landing or domain scan ────────────────────────────────
  if (method !== 'GET' && method !== 'HEAD') {
    return jsonResponse({ error: 'Method not allowed' }, 405);
  }

  // Landing page
  if (path === '/' || path === '/about' || path === '/privacy' || path === '/terms' || path === '/cli' || path === '/api/docs') {
    const nonce = crypto.randomUUID();
    const { html } = await import('./spa');
    return new Response(html(path, nonce), {
      headers: { 'Content-Type': 'text/html; charset=utf-8', ...secHeaders(nonce) },
    });
  }

  // ── Domain scan routes ─────────────────────────────────────────
  const segments = path.slice(1).split('/');
  const rawDomain = segments[0];
  const subRoute = segments[1] || null; // cors, csp, headers, chain, cache

  const domain = normalizeDomain(rawDomain);
  if (!domain) {
    if (rawDomain) return jsonResponse({ error: 'Invalid domain', input: rawDomain }, 400);
    return jsonResponse({ error: 'Not found' }, 404);
  }

  // Rate limit
  const rl = await checkRateLimit(request, env);
  if (rl) return rl;

  // Check if browser wants HTML
  const wantsHtml = (request.headers.get('Accept') || '').includes('text/html');

  // Check cache
  const cacheKey = `scan:${domain}:${subRoute || 'full'}`;
  const cached = await env.CACHE.get(cacheKey, 'json') as ScanResult | null;

  let result: ScanResult | Partial<ScanResult>;

  if (cached) {
    result = cached;
    if (result._meta) result._meta.cache_hit = true;
  } else {
    result = await runScan(domain, subRoute, env);
    // Cache the result
    ctx.waitUntil(env.CACHE.put(cacheKey, JSON.stringify(result), { expirationTtl: CACHE_TTL }));
  }

  // Track usage
  trackScan(env, domain, ctx);

  // Return appropriate format
  if (wantsHtml) {
    const nonce = crypto.randomUUID();
    const { html } = await import('./spa');
    return new Response(html(`/${domain}`, nonce, result), {
      headers: { 'Content-Type': 'text/html; charset=utf-8', ...secHeaders(nonce) },
    });
  }

  // Apply sub-route filtering
  if (subRoute && result) {
    const filtered = filterResult(result as ScanResult, subRoute);
    if (!filtered) return jsonResponse({ error: `Unknown sub-route: ${subRoute}` }, 400);
    return jsonResponse(filtered, 200, rateLimitHeaders(request, env));
  }

  return jsonResponse(result, 200, rateLimitHeaders(request, env));
}

async function runScan(domain: string, _subRoute: string | null, env: Env): Promise<ScanResult> {
  const start = performance.now();
  const targetUrl = `https://${domain}`;

  // Run all analyses in parallel
  const [redirectResult, corsResult, tlsVersion, yokeSignals] = await Promise.all([
    followRedirects(targetUrl),
    analyzeCORS(targetUrl),
    fetchTLSVersion(domain, env),
    fetchDomainSignals(domain, env).catch(() => null),
  ]);

  // Fetch the final destination's FULL response headers for analysis
  // The redirect chain only captures a summary — we need ALL headers
  const finalUrl = redirectResult.chain.length > 0
    ? redirectResult.chain[redirectResult.chain.length - 1].url
    : targetUrl;

  let headersObj: Headers;
  try {
    const finalResp = await fetch(finalUrl, {
      method: 'GET',
      redirect: 'manual',
      headers: {
        'User-Agent': USER_AGENT,
        'Accept': 'text/html,application/xhtml+xml,*/*',
      },
      signal: AbortSignal.timeout(10_000),
    });
    headersObj = finalResp.headers;
  } catch {
    // Fallback to sparse summary if direct fetch fails
    const sparse = redirectResult.chain.length > 0
      ? redirectResult.chain[redirectResult.chain.length - 1].headers_summary
      : {};
    headersObj = new Headers(sparse);
  }

  const [cspResult, secHeadersResult, cacheResult] = await Promise.all([
    Promise.resolve(evaluateCSP(headersObj.get('content-security-policy'), headersObj)),
    Promise.resolve(analyzeSecurityHeaders(headersObj)),
    Promise.resolve(analyzeCacheBehavior(headersObj)),
  ]);

  // Compute overall grade
  const grade = computeOverallGrade(secHeadersResult.grade, cspResult.grade, corsResult, redirectResult);

  const scanTime = Math.round(performance.now() - start);

  return {
    url: targetUrl,
    scanned_at: new Date().toISOString(),
    grade,
    cors: corsResult,
    csp: cspResult,
    security_headers: secHeadersResult,
    redirect_chain: redirectResult,
    cache: cacheResult,
    tls: {
      version: tlsVersion,
      details: `→ certs.lol/${domain}`,
    },
    ...(yokeSignals ? {
      domain_intel: {
        dnssec: yokeSignals.dnssec,
        email_auth: yokeSignals.email_auth,
      },
    } : {}),
    _meta: {
      version: VERSION,
      scan_time_ms: scanTime,
      cache_hit: false,
      links: {
        full_report: `https://yoke.lol/${domain}`,
        tls_details: `https://certs.lol/${domain}`,
        dns_details: `https://ns.lol/${domain}`,
        email_validation: 'https://vrfy.lol',
      },
    },
  };
}

function filterResult(result: ScanResult, subRoute: string): unknown | null {
  switch (subRoute) {
    case 'cors': return { url: result.url, cors: result.cors, _meta: result._meta };
    case 'csp': return { url: result.url, csp: result.csp, _meta: result._meta };
    case 'headers': return { url: result.url, security_headers: result.security_headers, _meta: result._meta };
    case 'chain': return { url: result.url, redirect_chain: result.redirect_chain, _meta: result._meta };
    case 'cache': return { url: result.url, cache: result.cache, _meta: result._meta };
    default: return null;
  }
}

async function fetchTLSVersion(domain: string, env: Env): Promise<string | null> {
  try {
    const resp = await fetch(`${env.PROBE_URL}/probe-ssl?domain=${domain}`, {
      headers: { 'Authorization': `Bearer ${env.ADMIN_KEY}` },
      signal: AbortSignal.timeout(10_000),
    });
    if (!resp.ok) return null;
    const data = await resp.json() as { protocols?: string[] };
    if (data.protocols?.length) {
      return data.protocols.includes('TLSv1.3') ? 'TLSv1.3' : data.protocols[0];
    }
    return null;
  } catch {
    return null;
  }
}

function computeOverallGrade(
  headersGrade: string,
  cspGrade: string,
  cors: import('./types').CORSResult,
  redirects: import('./types').RedirectChainResult
): string {
  const gradeToNum: Record<string, number> = { 'A+': 97, 'A': 93, 'A-': 90, 'B+': 87, 'B': 83, 'B-': 80, 'C+': 77, 'C': 73, 'C-': 70, 'D': 60, 'F': 40 };
  const numToGrade = (n: number): string => {
    if (n >= 95) return 'A+';
    if (n >= 90) return 'A';
    if (n >= 85) return 'B+';
    if (n >= 80) return 'B';
    if (n >= 75) return 'B-';
    if (n >= 70) return 'C+';
    if (n >= 65) return 'C';
    if (n >= 55) return 'D';
    return 'F';
  };

  let score = 0;
  // Headers: 40%, CSP: 30%, CORS: 15%, Redirects: 15%
  score += (gradeToNum[headersGrade] || 50) * 0.4;
  score += (gradeToNum[cspGrade] || 50) * 0.3;

  // CORS score
  const corsCritical = cors.issues.filter(i => i.severity === 'critical').length;
  const corsHigh = cors.issues.filter(i => i.severity === 'high').length;
  const corsScore = Math.max(40, 100 - corsCritical * 30 - corsHigh * 15);
  score += corsScore * 0.15;

  // Redirect score
  let redirectScore = 100;
  if (redirects.mixed_content) redirectScore -= 40;
  if (redirects.loop_detected) redirectScore -= 50;
  redirectScore -= Math.max(0, (redirects.hops - 2)) * 5; // Penalize >2 hops
  score += Math.max(40, redirectScore) * 0.15;

  return numToGrade(Math.round(score));
}

// ── POST handlers ────────────────────────────────────────────────

async function handleCORSSimulation(request: Request): Promise<Response> {
  let body: CORSSimulationRequest;
  try {
    body = await request.json() as CORSSimulationRequest;
  } catch {
    return jsonResponse({ error: 'Invalid JSON body' }, 400);
  }
  if (!body.target || !body.origin) {
    return jsonResponse({ error: 'Required fields: target, origin' }, 400);
  }
  const result = await simulateCORS(body);
  return jsonResponse(result);
}

async function handleCORSErrorDecode(request: Request): Promise<Response> {
  let body: CORSErrorDecodeRequest;
  try {
    body = await request.json() as CORSErrorDecodeRequest;
  } catch {
    return jsonResponse({ error: 'Invalid JSON body' }, 400);
  }
  if (!body.error) {
    return jsonResponse({ error: 'Required field: error' }, 400);
  }
  const result = decodeCORSError(body.error);
  return jsonResponse(result);
}

async function handleCSPEvaluate(request: Request): Promise<Response> {
  let body: CSPEvaluateRequest;
  try {
    body = await request.json() as CSPEvaluateRequest;
  } catch {
    return jsonResponse({ error: 'Invalid JSON body' }, 400);
  }
  if (!body.policy) {
    return jsonResponse({ error: 'Required field: policy' }, 400);
  }
  const result = evaluateCSPString(body.policy);
  return jsonResponse(result);
}

// ── Rate limiting ────────────────────────────────────────────────

async function checkRateLimit(request: Request, env: Env): Promise<Response | null> {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const id = env.RATE_LIMITER.idFromName(ip);
  const stub = env.RATE_LIMITER.get(id);

  try {
    const resp = await stub.fetch(new Request('https://rl/check', {
      method: 'POST',
      body: JSON.stringify({ limit: RATE_LIMIT, window: 3600 }),
    }));
    const data = await resp.json() as { allowed: boolean; remaining: number; reset: number };
    if (!data.allowed) {
      const retryMin = Math.ceil(data.reset / 60);
      return jsonResponse(
        {
          error: 'Rate limit exceeded',
          limit: RATE_LIMIT,
          window: '1 hour',
          retry_after_seconds: data.reset,
          message: `Rate limited. Try again in ~${retryMin} minute${retryMin === 1 ? '' : 's'}. Install the CLI for unlimited local scans.`,
        },
        429,
        { 'Retry-After': String(data.reset) }
      );
    }
  } catch {
    // Rate limiter failure — allow the request
  }
  return null;
}

function rateLimitHeaders(_request: Request, _env: Env): Record<string, string> {
  // Placeholder — populated from DO response in a real implementation
  return {};
}

// ── Static content ───────────────────────────────────────────────

function robotsTxt(): string {
  return `User-agent: *\nAllow: /\nSitemap: https://xhttp.lol/sitemap.xml\n`;
}

function sitemapXml(): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://xhttp.lol/</loc><changefreq>weekly</changefreq><priority>1.0</priority></url>
  <url><loc>https://xhttp.lol/about</loc><changefreq>monthly</changefreq><priority>0.5</priority></url>
  <url><loc>https://xhttp.lol/api/docs</loc><changefreq>monthly</changefreq><priority>0.7</priority></url>
  <url><loc>https://xhttp.lol/cli</loc><changefreq>monthly</changefreq><priority>0.6</priority></url>
</urlset>`;
}

function securityTxt(): string {
  return `Contact: https://github.com/yokedotlol/xhttp/issues
Expires: 2027-06-18T00:00:00Z
Preferred-Languages: en
Canonical: https://xhttp.lol/.well-known/security.txt
`;
}

function llmsTxt(): string {
  return `# xhttp.lol
> The HTTP response debugger. CORS, CSP, security headers, redirects, cache — one command.

## API
GET /{domain} — Full scan (headers, security, redirect chain, cache, CORS)
GET /{domain}/cors — CORS-focused scan
GET /{domain}/csp — CSP-focused scan
GET /{domain}/headers — Security headers only
GET /{domain}/chain — Redirect chain only
GET /{domain}/cache — Cache behavior only
POST /cors — CORS simulation with custom parameters
POST /error — CORS error message decoder
POST /csp/evaluate — Evaluate a CSP policy string

## Output
JSON by default. All responses include fix suggestions with server config docs.

## Related
- https://yoke.lol — Full domain intelligence
- https://certs.lol — TLS/SSL certificate analysis
- https://ns.lol — DNS toolkit
- https://vrfy.lol — Email validation

## Source
https://github.com/yokedotlol/xhttp (MIT)
`;
}

function faviconSvg(): string {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y=".9em" font-size="90">🛡️</text></svg>`;
}

function mtaSts(): string {
  return `version: STSv1
mode: enforce
mx: feedback-smtp.us-east-1.amazonses.com
max_age: 604800
`;
}
