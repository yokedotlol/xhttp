// CSP analysis — parse, evaluate, grade, detect bypasses

import type { CSPResult, CSPDirectiveMap, Finding } from './types';

/** Parse a raw CSP string into a directive map */
export function parseCSP(raw: string): CSPDirectiveMap {
  const directives: CSPDirectiveMap = {};
  if (!raw) return directives;

  // Split on semicolons, trim whitespace
  const parts = raw.split(';').map(p => p.trim()).filter(Boolean);
  for (const part of parts) {
    const tokens = part.split(/\s+/);
    const name = tokens[0].toLowerCase();
    directives[name] = tokens.slice(1);
  }

  return directives;
}

/** Evaluate a parsed CSP for issues */
export function evaluateCSP(raw: string | null, allHeaders: Headers): CSPResult {
  if (!raw) {
    const reportOnly = allHeaders.get('Content-Security-Policy-Report-Only');
    if (reportOnly) {
      const parsed = parseCSP(reportOnly);
      return {
        present: true,
        mode: 'report-only',
        raw: reportOnly,
        parsed,
        grade: 'D',
        issues: [{
          severity: 'warning',
          code: 'CSP_REPORT_ONLY',
          message: 'CSP is in report-only mode — violations are logged but not enforced.',
          fix: 'Once you\'ve verified your CSP isn\'t breaking anything, switch Content-Security-Policy-Report-Only to Content-Security-Policy to enforce it.',
          mdn: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only',
        }],
        missing_directives: findMissingDirectives(parsed),
      };
    }

    return {
      present: false,
      mode: 'none',
      raw: null,
      parsed: {},
      grade: 'F',
      issues: [{
        severity: 'high',
        code: 'NO_CSP',
        message: 'No Content-Security-Policy header. The browser will load resources from any source.',
        fix: 'Add a Content-Security-Policy header. Start with a restrictive policy like: default-src \'self\'; script-src \'self\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data:; font-src \'self\'; connect-src \'self\'; frame-ancestors \'none\'; base-uri \'self\'; form-action \'self\'',
        mdn: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
      }],
      missing_directives: [],
    };
  }

  const parsed = parseCSP(raw);
  const issues: Finding[] = [];

  // ── Dangerous directives ────────────────────────────────────────

  checkUnsafeInline(parsed, issues);
  checkUnsafeEval(parsed, issues);
  checkDataUri(parsed, issues);
  checkBlobUri(parsed, issues);
  checkWildcards(parsed, issues);
  checkBypassPatterns(parsed, issues);

  // ── Missing directives ──────────────────────────────────────────

  const missing = findMissingDirectives(parsed);
  for (const directive of missing) {
    issues.push({
      severity: 'warning',
      code: `MISSING_${directive.toUpperCase().replace(/-/g, '_')}`,
      message: `Missing ${directive} directive. Without it, ${directiveExplanation(directive)}.`,
      fix: `Add ${directive} to your CSP. Recommended: ${directiveRecommendation(directive)}`,
      mdn: `https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/${directive}`,
    });
  }

  // ── Conflict: frame-ancestors vs X-Frame-Options ────────────────

  const xfo = allHeaders.get('X-Frame-Options');
  const frameAncestors = parsed['frame-ancestors'];
  if (xfo && frameAncestors) {
    const xfoNorm = xfo.toUpperCase().trim();
    const faStr = frameAncestors.join(' ');
    let conflict = false;

    if (xfoNorm === 'DENY' && faStr !== "'none'") conflict = true;
    if (xfoNorm === 'SAMEORIGIN' && faStr !== "'self'") conflict = true;

    if (conflict) {
      issues.push({
        severity: 'warning',
        code: 'XFO_CSP_CONFLICT',
        message: `X-Frame-Options (${xfo}) conflicts with CSP frame-ancestors (${faStr}). CSP takes precedence in modern browsers.`,
        fix: 'Remove X-Frame-Options and rely on CSP frame-ancestors. Or align both: DENY ↔ frame-ancestors \'none\', SAMEORIGIN ↔ frame-ancestors \'self\'.',
        mdn: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors',
      });
    }
  }

  const grade = gradeCSP(parsed, issues);

  return {
    present: true,
    mode: 'enforce',
    raw,
    parsed,
    grade,
    issues,
    missing_directives: missing,
  };
}

// ── Issue detection ─────────────────────────────────────────────────

function checkUnsafeInline(parsed: CSPDirectiveMap, issues: Finding[]) {
  for (const directive of ['script-src', 'script-src-elem', 'script-src-attr', 'default-src']) {
    const values = parsed[directive];
    if (!values) continue;
    if (values.includes("'unsafe-inline'")) {
      // Check if nonce or hash is also present (which supersedes unsafe-inline)
      const hasNonceOrHash = values.some(v => v.startsWith("'nonce-") || v.startsWith("'sha256-") || v.startsWith("'sha384-") || v.startsWith("'sha512-"));
      if (hasNonceOrHash) {
        issues.push({
          severity: 'info',
          code: 'UNSAFE_INLINE_WITH_NONCE',
          message: `${directive} includes 'unsafe-inline' alongside nonce/hash values. The 'unsafe-inline' is ignored by modern browsers when nonce/hash is present (kept for backward compatibility).`,
        });
      } else {
        issues.push({
          severity: directive.startsWith('script') || directive === 'default-src' ? 'critical' : 'high',
          code: 'UNSAFE_INLINE',
          message: `${directive} includes 'unsafe-inline', which allows inline scripts and defeats XSS protection.`,
          fix: `Replace 'unsafe-inline' with nonce-based or hash-based script loading. Use 'nonce-{random}' and add the matching nonce attribute to your <script> tags.`,
          mdn: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src#unsafe_inline_script',
        });
      }
    }
  }
}

function checkUnsafeEval(parsed: CSPDirectiveMap, issues: Finding[]) {
  for (const directive of ['script-src', 'script-src-elem', 'default-src']) {
    const values = parsed[directive];
    if (!values) continue;
    if (values.includes("'unsafe-eval'")) {
      issues.push({
        severity: 'high',
        code: 'UNSAFE_EVAL',
        message: `${directive} includes 'unsafe-eval', allowing eval(), Function(), and setTimeout('string'). This enables code injection attacks.`,
        fix: 'Remove \'unsafe-eval\' and refactor code to avoid eval(). Most modern frameworks don\'t need it.',
        mdn: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src#unsafe_eval',
      });
    }
  }
}

function checkDataUri(parsed: CSPDirectiveMap, issues: Finding[]) {
  for (const directive of ['script-src', 'default-src', 'object-src']) {
    const values = parsed[directive];
    if (!values) continue;
    if (values.includes('data:')) {
      const severity = directive.startsWith('script') || directive === 'default-src' ? 'high' : 'warning';
      issues.push({
        severity,
        code: 'DATA_URI',
        message: `${directive} allows data: URIs, which can be used to inject executable content.`,
        fix: `Remove data: from ${directive}. If you need data: URIs for images, add them only to img-src.`,
        mdn: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/Sources#data',
      });
    }
  }
}

function checkBlobUri(parsed: CSPDirectiveMap, issues: Finding[]) {
  for (const directive of ['script-src', 'default-src', 'worker-src']) {
    const values = parsed[directive];
    if (!values) continue;
    if (values.includes('blob:')) {
      issues.push({
        severity: 'warning',
        code: 'BLOB_URI',
        message: `${directive} allows blob: URIs, which can be used to create executable content dynamically.`,
        fix: `Remove blob: from ${directive} unless your application specifically needs it for Web Workers or dynamic scripts.`,
      });
    }
  }
}

function checkWildcards(parsed: CSPDirectiveMap, issues: Finding[]) {
  for (const [directive, values] of Object.entries(parsed)) {
    if (!values) continue;
    if (values.includes('*')) {
      issues.push({
        severity: directive.startsWith('script') || directive === 'default-src' ? 'critical' : 'high',
        code: 'WILDCARD_SOURCE',
        message: `${directive} uses wildcard (*), allowing resources from any host. This provides no meaningful protection.`,
        fix: `Replace * with specific trusted domains in ${directive}.`,
      });
    }

    // Check for overly broad subdomain wildcards like *.googleapis.com
    for (const val of values) {
      if (val.startsWith('*.') && !val.startsWith('*.localhost')) {
        const domain = val.slice(2);
        // Known risky wildcard domains (potential JSONP/Angular/etc. endpoints)
        const riskyDomains = ['googleapis.com', 'gstatic.com', 'cloudflare.com', 'amazonaws.com', 'azurewebsites.net'];
        if (riskyDomains.some(d => domain === d || domain.endsWith('.' + d))) {
          if (directive.startsWith('script') || directive === 'default-src') {
            issues.push({
              severity: 'warning',
              code: 'BROAD_WILDCARD',
              message: `${directive} allows ${val} — this large domain may host JSONP endpoints or user-uploadable content that can bypass CSP.`,
              fix: `Narrow the wildcard to specific subdomains you actually use instead of ${val}.`,
            });
          }
        }
      }
    }
  }
}

function checkBypassPatterns(parsed: CSPDirectiveMap, issues: Finding[]) {
  const scriptSources = [
    ...(parsed['script-src'] || []),
    ...(parsed['script-src-elem'] || []),
    ...(!parsed['script-src'] && !parsed['script-src-elem'] ? (parsed['default-src'] || []) : []),
  ];

  // Known JSONP bypass endpoints
  const jsonpEndpoints = [
    { pattern: /accounts\.google\.com/, name: 'Google Accounts (JSONP)' },
    { pattern: /maps\.googleapis\.com/, name: 'Google Maps (JSONP)' },
    { pattern: /translate\.googleapis\.com/, name: 'Google Translate (JSONP)' },
    { pattern: /cdnjs\.cloudflare\.com/, name: 'cdnjs (hosts Angular, which can bypass CSP)' },
    { pattern: /ajax\.googleapis\.com/, name: 'Google Hosted Libraries (hosts Angular)' },
    { pattern: /cdn\.jsdelivr\.net/, name: 'jsDelivr (arbitrary npm packages)' },
    { pattern: /unpkg\.com/, name: 'unpkg (arbitrary npm packages)' },
  ];

  for (const src of scriptSources) {
    for (const { pattern, name } of jsonpEndpoints) {
      if (pattern.test(src)) {
        issues.push({
          severity: 'high',
          code: 'KNOWN_BYPASS',
          message: `script-src allows ${src} — ${name}. This can be used to bypass CSP.`,
          fix: `Remove ${src} from script-src or use subresource integrity (SRI) hashes. If you need this CDN, pin specific files with their hashes.`,
        });
      }
    }
  }
}

// ── Grading ─────────────────────────────────────────────────────────

function gradeCSP(parsed: CSPDirectiveMap, issues: Finding[]): string {
  const criticals = issues.filter(i => i.severity === 'critical').length;
  const highs = issues.filter(i => i.severity === 'high').length;
  const warnings = issues.filter(i => i.severity === 'warning').length;

  if (criticals > 0) return 'F';
  if (highs > 1) return 'D';
  if (highs === 1) return 'C';
  if (warnings > 2) return 'C';
  if (warnings > 0) return 'B';
  return 'A';
}

// ── Helpers ─────────────────────────────────────────────────────────

const CRITICAL_DIRECTIVES = ['form-action', 'frame-ancestors', 'base-uri'];

function findMissingDirectives(parsed: CSPDirectiveMap): string[] {
  const missing: string[] = [];
  for (const d of CRITICAL_DIRECTIVES) {
    if (!parsed[d]) missing.push(d);
  }

  // object-src should be 'none' or at least present
  if (!parsed['object-src'] && !parsed['default-src']?.includes("'none'")) {
    missing.push('object-src');
  }

  return missing;
}

function directiveExplanation(directive: string): string {
  const explanations: Record<string, string> = {
    'form-action': 'forms can submit to any URL, enabling phishing attacks',
    'frame-ancestors': 'the page can be embedded in iframes on any site (clickjacking)',
    'base-uri': 'attackers can inject <base> tags to redirect relative URLs',
    'object-src': 'plugins like Flash/Java can load from any source',
  };
  return explanations[directive] || 'the default-src fallback applies';
}

function directiveRecommendation(directive: string): string {
  const recs: Record<string, string> = {
    'form-action': "form-action 'self'",
    'frame-ancestors': "frame-ancestors 'none'",
    'base-uri': "base-uri 'self'",
    'object-src': "object-src 'none'",
  };
  return recs[directive] || `${directive} 'self'`;
}

/** Evaluate a standalone CSP string (no live scan needed) */
export function evaluateCSPString(policy: string): CSPResult {
  const emptyHeaders = new Headers();
  return evaluateCSP(policy, emptyHeaders);
}
