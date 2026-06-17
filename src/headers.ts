// Security headers analysis — HSTS, XFO, XCTO, Referrer-Policy, Permissions-Policy, etc.

import type { SecurityHeadersResult, HeaderCheck, Finding } from './types';

/** Analyze security headers from a Response's headers */
export function analyzeSecurityHeaders(headers: Headers): SecurityHeadersResult {
  const conflicts: Finding[] = [];
  let score = 0;
  const maxScore = 100;

  // ── HSTS ──────────────────────────────────────────────────────────
  const hsts = analyzeHSTS(headers);
  score += hstsScore(hsts);

  // ── X-Frame-Options ───────────────────────────────────────────────
  const xfo = analyzeXFO(headers);
  score += xfo.present ? 10 : 0;

  // ── X-Content-Type-Options ────────────────────────────────────────
  const xcto = analyzeXCTO(headers);
  score += xcto.present ? 10 : 0;

  // ── Referrer-Policy ───────────────────────────────────────────────
  const referrer = analyzeReferrerPolicy(headers);
  score += referrer.present ? 10 : 0;

  // ── Permissions-Policy ────────────────────────────────────────────
  const permissions = analyzePermissionsPolicy(headers);
  score += permissions.present ? 10 : 0;

  // ── CSP (just presence check here — deep analysis in csp.ts) ─────
  const cspHeader = headers.get('Content-Security-Policy');
  const cspCheck: HeaderCheck = {
    present: !!cspHeader,
    value: cspHeader,
    issues: [],
  };
  if (!cspHeader) {
    cspCheck.issues.push({
      severity: 'high',
      code: 'NO_CSP_HEADER',
      message: 'No Content-Security-Policy header.',
      fix: 'Add a Content-Security-Policy header to control resource loading.',
      mdn: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
    });
    cspCheck.recommendation = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'; base-uri 'self'";
  }
  score += cspHeader ? 15 : 0;

  // ── COOP ──────────────────────────────────────────────────────────
  const coopVal = headers.get('Cross-Origin-Opener-Policy');
  const coop: HeaderCheck = {
    present: !!coopVal,
    value: coopVal,
    issues: [],
  };
  if (!coopVal) {
    coop.recommendation = 'same-origin';
  }
  score += coopVal ? 5 : 0;

  // ── COEP ──────────────────────────────────────────────────────────
  const coepVal = headers.get('Cross-Origin-Embedder-Policy');
  const coep: HeaderCheck = {
    present: !!coepVal,
    value: coepVal,
    issues: [],
  };
  if (!coepVal) {
    coep.recommendation = 'credentialless';
  }
  score += coepVal ? 5 : 0;

  // ── CORP ──────────────────────────────────────────────────────────
  const corpVal = headers.get('Cross-Origin-Resource-Policy');
  const corp: HeaderCheck = {
    present: !!corpVal,
    value: corpVal,
    issues: [],
  };
  if (!corpVal) {
    corp.recommendation = 'same-origin';
  }
  score += corpVal ? 5 : 0;

  // ── Conflicts ─────────────────────────────────────────────────────
  // XFO vs frame-ancestors handled in csp.ts

  // X-XSS-Protection (deprecated but sometimes misconfigured)
  const xxss = headers.get('X-XSS-Protection');
  if (xxss && xxss !== '0') {
    conflicts.push({
      severity: 'info',
      code: 'XXSS_PROTECTION_ENABLED',
      message: `X-XSS-Protection is set to "${xxss}". This header is deprecated and can introduce vulnerabilities in older browsers. Modern browsers ignore it.`,
      fix: 'Set X-XSS-Protection: 0 to explicitly disable it, and rely on CSP for XSS protection.',
      mdn: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection',
    });
  }

  const grade = scoreToGrade(score, maxScore);

  return {
    grade,
    headers: {
      'strict-transport-security': hsts,
      'x-frame-options': xfo,
      'x-content-type-options': xcto,
      'referrer-policy': referrer,
      'permissions-policy': permissions,
      'content-security-policy': cspCheck,
      'cross-origin-opener-policy': coop,
      'cross-origin-embedder-policy': coep,
      'cross-origin-resource-policy': corp,
    },
    conflicts,
    score,
    max_score: maxScore,
  };
}

// ── Individual header analyzers ─────────────────────────────────────

function analyzeHSTS(headers: Headers): HeaderCheck & { preload_eligible?: boolean; preload_listed?: boolean } {
  const raw = headers.get('Strict-Transport-Security');
  const result: HeaderCheck & { preload_eligible?: boolean } = {
    present: !!raw,
    value: raw,
    issues: [],
  };

  if (!raw) {
    result.issues.push({
      severity: 'high',
      code: 'NO_HSTS',
      message: 'No Strict-Transport-Security header. The site can be downgraded to HTTP.',
      fix: 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
      mdn: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security',
    });
    result.recommendation = 'max-age=31536000; includeSubDomains; preload';
    return result;
  }

  // Parse directives
  const lower = raw.toLowerCase();
  const maxAgeMatch = lower.match(/max-age=(\d+)/);
  const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
  const includesSubs = lower.includes('includesubdomains');
  const preload = lower.includes('preload');

  if (maxAge < 31536000) {
    result.issues.push({
      severity: 'warning',
      code: 'HSTS_SHORT_MAX_AGE',
      message: `HSTS max-age is ${maxAge} seconds (${Math.round(maxAge / 86400)} days). Best practice is at least 1 year (31536000).`,
      fix: 'Set max-age=31536000 (1 year) or higher.',
    });
  }

  if (!includesSubs) {
    result.issues.push({
      severity: 'warning',
      code: 'HSTS_NO_SUBDOMAINS',
      message: 'HSTS does not include subdomains. Subdomains can still be accessed over HTTP.',
      fix: 'Add includeSubDomains to enforce HSTS on all subdomains.',
    });
  }

  if (!preload) {
    result.issues.push({
      severity: 'info',
      code: 'HSTS_NO_PRELOAD',
      message: 'HSTS preload directive is missing. The site is not eligible for browser preload lists.',
      fix: 'Add the preload directive and submit to hstspreload.org to be hardcoded into browsers.',
    });
  }

  // Preload eligibility: max-age >= 31536000 + includeSubDomains + preload
  result.preload_eligible = maxAge >= 31536000 && includesSubs && preload;

  return result;
}

function analyzeXFO(headers: Headers): HeaderCheck {
  const raw = headers.get('X-Frame-Options');
  const result: HeaderCheck = {
    present: !!raw,
    value: raw,
    issues: [],
  };

  if (!raw) {
    result.issues.push({
      severity: 'warning',
      code: 'NO_XFO',
      message: 'No X-Frame-Options header. The page can be embedded in iframes (clickjacking risk).',
      fix: 'Add X-Frame-Options: DENY (or SAMEORIGIN if you need self-framing). Better: use CSP frame-ancestors.',
      mdn: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options',
    });
    result.recommendation = 'DENY';
    return result;
  }

  const upper = raw.toUpperCase().trim();
  if (upper !== 'DENY' && upper !== 'SAMEORIGIN') {
    result.issues.push({
      severity: 'warning',
      code: 'XFO_INVALID',
      message: `X-Frame-Options value "${raw}" is not valid. Only DENY and SAMEORIGIN are supported.`,
      fix: 'Set X-Frame-Options to DENY or SAMEORIGIN.',
    });
  }

  if (upper.startsWith('ALLOW-FROM')) {
    result.issues.push({
      severity: 'warning',
      code: 'XFO_ALLOW_FROM_DEPRECATED',
      message: 'ALLOW-FROM is deprecated and not supported by modern browsers. Use CSP frame-ancestors instead.',
      fix: 'Replace X-Frame-Options: ALLOW-FROM with Content-Security-Policy: frame-ancestors <origin>.',
    });
  }

  return result;
}

function analyzeXCTO(headers: Headers): HeaderCheck {
  const raw = headers.get('X-Content-Type-Options');
  const result: HeaderCheck = {
    present: !!raw,
    value: raw,
    issues: [],
  };

  if (!raw) {
    result.issues.push({
      severity: 'warning',
      code: 'NO_XCTO',
      message: 'No X-Content-Type-Options header. Browsers may MIME-sniff responses, enabling attacks.',
      fix: 'Add X-Content-Type-Options: nosniff',
      mdn: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options',
    });
    result.recommendation = 'nosniff';
    return result;
  }

  if (raw.toLowerCase().trim() !== 'nosniff') {
    result.issues.push({
      severity: 'warning',
      code: 'XCTO_INVALID',
      message: `X-Content-Type-Options value "${raw}" is not valid. Only "nosniff" is supported.`,
      fix: 'Set X-Content-Type-Options: nosniff',
    });
  }

  return result;
}

function analyzeReferrerPolicy(headers: Headers): HeaderCheck {
  const raw = headers.get('Referrer-Policy');
  const result: HeaderCheck = {
    present: !!raw,
    value: raw,
    issues: [],
  };

  if (!raw) {
    result.issues.push({
      severity: 'warning',
      code: 'NO_REFERRER_POLICY',
      message: 'No Referrer-Policy header. Browsers default to strict-origin-when-cross-origin, but explicit is better.',
      fix: 'Add Referrer-Policy: strict-origin-when-cross-origin (or no-referrer for maximum privacy).',
      mdn: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy',
    });
    result.recommendation = 'strict-origin-when-cross-origin';
    return result;
  }

  const leaky = ['unsafe-url', 'no-referrer-when-downgrade'];
  if (leaky.includes(raw.toLowerCase().trim())) {
    result.issues.push({
      severity: 'warning',
      code: 'REFERRER_LEAKY',
      message: `Referrer-Policy "${raw}" leaks full URLs to other sites, including paths and query strings.`,
      fix: 'Use strict-origin-when-cross-origin or strict-origin to limit referrer information.',
    });
  }

  return result;
}

function analyzePermissionsPolicy(headers: Headers): HeaderCheck {
  const raw = headers.get('Permissions-Policy') || headers.get('Feature-Policy');
  const isLegacy = !headers.get('Permissions-Policy') && !!headers.get('Feature-Policy');
  const result: HeaderCheck = {
    present: !!raw,
    value: raw,
    issues: [],
  };

  if (!raw) {
    result.issues.push({
      severity: 'info',
      code: 'NO_PERMISSIONS_POLICY',
      message: 'No Permissions-Policy header. Browser features like camera, microphone, and geolocation use default permissions.',
      fix: 'Add Permissions-Policy: camera=(), microphone=(), geolocation=() to restrict sensitive features.',
      mdn: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy',
    });
    result.recommendation = 'camera=(), microphone=(), geolocation=()';
    return result;
  }

  if (isLegacy) {
    result.issues.push({
      severity: 'info',
      code: 'FEATURE_POLICY_LEGACY',
      message: 'Using deprecated Feature-Policy header instead of Permissions-Policy.',
      fix: 'Replace Feature-Policy with Permissions-Policy. Syntax changed: e.g., camera \'none\' → camera=()',
    });
  }

  return result;
}

// ── Scoring / grading ───────────────────────────────────────────────

function hstsScore(hsts: HeaderCheck & { preload_eligible?: boolean }): number {
  if (!hsts.present) return 0;
  const raw = hsts.value?.toLowerCase() || '';
  const maxAgeMatch = raw.match(/max-age=(\d+)/);
  const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;

  let s = 10;
  if (maxAge >= 31536000) s += 5;
  if (raw.includes('includesubdomains')) s += 5;
  if (raw.includes('preload')) s += 5;
  return Math.min(s, 20);
}

function scoreToGrade(score: number, max: number): string {
  const pct = (score / max) * 100;
  if (pct >= 90) return 'A';
  if (pct >= 80) return 'B';
  if (pct >= 65) return 'C';
  if (pct >= 50) return 'D';
  return 'F';
}
