// Redirect chain follower — manually follows redirects, recording each hop

import type { RedirectChainResult, RedirectHop, Finding } from './types';
import { USER_AGENT, FETCH_TIMEOUT } from './constants';

const MAX_HOPS = 20;

/** Follow a URL's redirect chain, recording per-hop details */
export async function followRedirects(startUrl: string): Promise<RedirectChainResult> {
  const chain: RedirectHop[] = [];
  const issues: Finding[] = [];
  const seen = new Set<string>();
  let current = startUrl;
  let loopDetected = false;
  let mixedContent = false;
  const totalStart = performance.now();

  for (let i = 0; i < MAX_HOPS; i++) {
    if (seen.has(current)) {
      loopDetected = true;
      issues.push({
        severity: 'critical',
        code: 'REDIRECT_LOOP',
        message: `Redirect loop detected: ${current} was already visited`,
        fix: 'Check your server configuration for circular redirects. A common cause is conflicting redirect rules (e.g., www → non-www and non-www → www both active).',
      });
      break;
    }
    seen.add(current);

    const hopStart = performance.now();
    let resp: Response;
    try {
      resp = await fetch(current, {
        method: 'GET',
        redirect: 'manual',
        headers: {
          'User-Agent': USER_AGENT,
          'Accept': 'text/html,application/xhtml+xml,*/*',
        },
        signal: AbortSignal.timeout(FETCH_TIMEOUT),
      });
    } catch (err) {
      issues.push({
        severity: 'critical',
        code: 'FETCH_ERROR',
        message: `Failed to fetch ${current}: ${err instanceof Error ? err.message : 'unknown error'}`,
        fix: 'The server may be down, blocking requests, or the domain may not resolve.',
      });
      break;
    }
    const hopTime = Math.round(performance.now() - hopStart);

    const location = resp.headers.get('Location');
    const status = resp.status;

    // Extract key headers for summary
    const headersSummary: Record<string, string> = {};
    for (const key of [
      'server', 'x-powered-by', 'via', 'alt-svc',
      'strict-transport-security', 'x-frame-options', 'x-content-type-options',
      'referrer-policy', 'permissions-policy', 'content-security-policy',
      'cross-origin-opener-policy', 'cross-origin-embedder-policy',
      'cross-origin-resource-policy', 'cache-control', 'content-type',
      'cf-cache-status', 'x-cache', 'age', 'vary',
    ]) {
      const val = resp.headers.get(key);
      if (val) headersSummary[key] = val;
    }

    const hop: RedirectHop = {
      url: current,
      status,
      location,
      timing_ms: hopTime,
      headers_summary: headersSummary,
      hsts: resp.headers.get('Strict-Transport-Security'),
    };
    chain.push(hop);

    // Check for mixed content (HTTPS → HTTP redirect)
    if (location) {
      const fromHttps = current.startsWith('https://');
      const toHttp = location.startsWith('http://');
      if (fromHttps && toHttp) {
        mixedContent = true;
        issues.push({
          severity: 'critical',
          code: 'MIXED_CONTENT_REDIRECT',
          message: `HTTPS → HTTP downgrade: ${current} redirects to ${location}`,
          fix: 'Never redirect from HTTPS to HTTP. Update the redirect target to use HTTPS.',
          mdn: 'https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content',
        });
      }
    }

    // Classify redirect type
    if (status === 302 || status === 303) {
      issues.push({
        severity: 'info',
        code: 'TEMPORARY_REDIRECT',
        message: `Hop ${i + 1} uses ${status} (temporary). If this is a permanent move, use 301 or 308 for better caching and SEO.`,
        fix: `Change the ${status} response to 301 (permanent) or 308 (permanent, preserves method) if the redirect is permanent.`,
      });
    }

    // Not a redirect — final destination
    if (status < 300 || status >= 400 || !location) {
      break;
    }

    // Resolve relative Location
    try {
      current = new URL(location, current).href;
    } catch {
      issues.push({
        severity: 'high',
        code: 'INVALID_LOCATION',
        message: `Invalid Location header at hop ${i + 1}: "${location}"`,
        fix: 'The Location header contains an invalid URL. Ensure it is a valid absolute or relative URL.',
      });
      break;
    }
  }

  if (chain.length >= MAX_HOPS) {
    issues.push({
      severity: 'critical',
      code: 'TOO_MANY_REDIRECTS',
      message: `Redirect chain exceeded ${MAX_HOPS} hops`,
      fix: 'Reduce the number of redirects. Most browsers give up after 20 hops.',
    });
  }

  // Check for HTTP → HTTPS upgrade (informational)
  if (chain.length >= 2) {
    const first = chain[0];
    if (first.url.startsWith('http://') && first.status >= 300 && first.status < 400 && first.location?.startsWith('https://')) {
      issues.push({
        severity: 'pass',
        code: 'HTTP_TO_HTTPS',
        message: `HTTP → HTTPS redirect in place (${first.status})`,
      });
    }
  }

  const totalTime = Math.round(performance.now() - totalStart);

  return {
    hops: chain.length,
    loop_detected: loopDetected,
    mixed_content: mixedContent,
    chain,
    issues,
    total_time_ms: totalTime,
  };
}
