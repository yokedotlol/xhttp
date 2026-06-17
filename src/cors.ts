// CORS analysis — simulation, detection, fix generation

import type { CORSResult, CORSSimulationRequest, CORSSimulationResult, Finding } from './types';

const FETCH_TIMEOUT = 10_000;
const DEFAULT_TEST_ORIGIN = 'https://example.com';

const SERVER_DOCS: Record<string, string> = {
  nginx: 'https://nginx.org/en/docs/http/ngx_http_headers_module.html',
  apache: 'https://httpd.apache.org/docs/current/mod/mod_headers.html',
  express: 'https://expressjs.com/en/resources/middleware/cors.html',
  cloudflare_workers: 'https://developers.cloudflare.com/workers/examples/cors-header-proxy/',
  caddy: 'https://caddyserver.com/docs/caddyfile/directives/header',
};

/** Analyze CORS behavior of a URL */
export async function analyzeCORS(targetUrl: string, testOrigin?: string): Promise<CORSResult> {
  const origin = testOrigin || DEFAULT_TEST_ORIGIN;
  const issues: Finding[] = [];

  // Send OPTIONS preflight
  let preflightStatus: number | null = null;
  let preflightHeaders: Headers | null = null;
  try {
    const preflightResp = await fetch(targetUrl, {
      method: 'OPTIONS',
      redirect: 'manual',
      headers: {
        'User-Agent': 'preflight.lol/1.0 (CORS checker; +https://preflight.lol)',
        'Origin': origin,
        'Access-Control-Request-Method': 'GET',
        'Access-Control-Request-Headers': 'Content-Type',
      },
      signal: AbortSignal.timeout(FETCH_TIMEOUT),
    });
    preflightStatus = preflightResp.status;
    preflightHeaders = preflightResp.headers;
  } catch {
    // Preflight failed — server may not handle OPTIONS
  }

  // Send actual GET with Origin header
  let actualHeaders: Headers;
  try {
    const actualResp = await fetch(targetUrl, {
      method: 'GET',
      redirect: 'manual',
      headers: {
        'User-Agent': 'preflight.lol/1.0 (CORS checker; +https://preflight.lol)',
        'Origin': origin,
        'Accept': '*/*',
      },
      signal: AbortSignal.timeout(FETCH_TIMEOUT),
    });
    actualHeaders = actualResp.headers;
  } catch {
    return {
      enabled: false,
      allow_origin: null,
      allow_credentials: false,
      allow_methods: [],
      allow_headers: [],
      expose_headers: [],
      max_age: null,
      preflight_status: preflightStatus,
      vary_origin: false,
      issues: [{
        severity: 'info',
        code: 'CORS_FETCH_FAILED',
        message: 'Could not fetch the target URL to check CORS headers.',
      }],
    };
  }

  // Use preflight headers if available, fall back to actual response
  const corsHeaders = preflightHeaders || actualHeaders;
  const acao = corsHeaders.get('Access-Control-Allow-Origin');
  const acac = corsHeaders.get('Access-Control-Allow-Credentials');
  const acam = corsHeaders.get('Access-Control-Allow-Methods');
  const acah = corsHeaders.get('Access-Control-Allow-Headers');
  const aceh = corsHeaders.get('Access-Control-Expose-Headers');
  const acma = corsHeaders.get('Access-Control-Max-Age');
  const vary = corsHeaders.get('Vary') || '';

  const enabled = acao !== null;
  const allowCredentials = acac?.toLowerCase() === 'true';
  const allowMethods = acam ? acam.split(',').map(m => m.trim()).filter(Boolean) : [];
  const allowHeaders = acah ? acah.split(',').map(h => h.trim()).filter(Boolean) : [];
  const exposeHeaders = aceh ? aceh.split(',').map(h => h.trim()).filter(Boolean) : [];
  const maxAge = acma ? parseInt(acma, 10) : null;
  const varyOrigin = vary.toLowerCase().includes('origin');

  if (!enabled) {
    issues.push({
      severity: 'info',
      code: 'NO_CORS_HEADERS',
      message: 'No CORS headers present. Cross-origin requests from browsers will be blocked.',
      fix: 'If you intend to allow cross-origin access, set the Access-Control-Allow-Origin header.',
      mdn: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS',
    });
  }

  // Wildcard origin
  if (acao === '*') {
    issues.push({
      severity: 'warning',
      code: 'WILDCARD_ORIGIN',
      message: 'Wildcard origin (*) allows any site to read responses.',
      fix: 'If only specific origins need access, set Access-Control-Allow-Origin to your frontend\'s origin instead of *.',
      mdn: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin',
    });
  }

  // Wildcard + credentials
  if (acao === '*' && allowCredentials) {
    issues.push({
      severity: 'critical',
      code: 'WILDCARD_WITH_CREDENTIALS',
      message: 'Wildcard origin (*) combined with Access-Control-Allow-Credentials: true. Browsers will block this.',
      fix: 'When using credentials, the server must echo the specific requesting origin, not *. Set Access-Control-Allow-Origin to the exact origin and add Vary: Origin.',
      mdn: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS/Errors/CORSNotSupportingCredentials',
    });
  }

  // Origin reflection (echoing the request origin — potential vulnerability)
  if (acao === origin && acao !== '*' && enabled) {
    // Send a second request with a different origin to detect reflection
    try {
      const testResp = await fetch(targetUrl, {
        method: 'GET',
        redirect: 'manual',
        headers: {
          'User-Agent': 'preflight.lol/1.0',
          'Origin': 'https://evil.example.com',
          'Accept': '*/*',
        },
        signal: AbortSignal.timeout(FETCH_TIMEOUT),
      });
      const reflectedOrigin = testResp.headers.get('Access-Control-Allow-Origin');
      if (reflectedOrigin === 'https://evil.example.com') {
        issues.push({
          severity: 'critical',
          code: 'ORIGIN_REFLECTION',
          message: 'Server reflects any Origin header as Access-Control-Allow-Origin. This is equivalent to a wildcard but bypasses the credentials restriction.',
          fix: 'Maintain an allowlist of permitted origins and only echo origins that match. Never blindly reflect the Origin header.',
          mdn: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS',
        });
      }
    } catch {
      // Couldn't test — skip
    }
  }

  // Missing Vary: Origin when ACAO is not wildcard
  if (enabled && acao !== '*' && !varyOrigin) {
    issues.push({
      severity: 'warning',
      code: 'MISSING_VARY_ORIGIN',
      message: 'Access-Control-Allow-Origin is origin-specific but Vary: Origin is missing. Caches may serve the wrong origin to different requesters.',
      fix: 'Add Vary: Origin to responses that include Access-Control-Allow-Origin with a specific origin.',
      mdn: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Vary',
    });
  }

  // Preflight returning non-2xx
  if (preflightStatus !== null && (preflightStatus < 200 || preflightStatus >= 300)) {
    issues.push({
      severity: 'high',
      code: 'PREFLIGHT_FAILED',
      message: `Preflight (OPTIONS) returned ${preflightStatus}. Browsers require a 2xx response.`,
      fix: 'Ensure your server responds to OPTIONS requests with a 200 or 204 status and the appropriate CORS headers.',
      mdn: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#preflighted_requests',
    });
  }

  // No max-age on preflight cache
  if (enabled && maxAge === null && preflightStatus !== null) {
    issues.push({
      severity: 'info',
      code: 'NO_PREFLIGHT_CACHE',
      message: 'No Access-Control-Max-Age set. Browsers will re-send preflight OPTIONS requests frequently.',
      fix: 'Set Access-Control-Max-Age to cache preflight results. 86400 (24 hours) is common.',
    });
  }

  return {
    enabled,
    allow_origin: acao,
    allow_credentials: allowCredentials,
    allow_methods: allowMethods,
    allow_headers: allowHeaders,
    expose_headers: exposeHeaders,
    max_age: maxAge,
    preflight_status: preflightStatus,
    vary_origin: varyOrigin,
    issues,
  };
}

/** Full CORS simulation — "I'm on site X, trying to reach site Y, with these headers" */
export async function simulateCORS(req: CORSSimulationRequest): Promise<CORSSimulationResult> {
  const { target, origin, method = 'GET', headers = [], credentials = false } = req;

  const isSimple = isSimpleRequest(method, headers);

  // Build preflight request
  const preflightHeaders: Record<string, string> = {
    'User-Agent': 'preflight.lol/1.0 (CORS simulation; +https://preflight.lol)',
    'Origin': origin,
    'Access-Control-Request-Method': method,
  };
  if (headers.length > 0) {
    preflightHeaders['Access-Control-Request-Headers'] = headers.join(', ');
  }

  let preflightReceived: Record<string, string> = {};
  let preflightStatus = 0;

  // Send preflight if needed
  if (!isSimple) {
    try {
      const resp = await fetch(target, {
        method: 'OPTIONS',
        redirect: 'manual',
        headers: preflightHeaders,
        signal: AbortSignal.timeout(FETCH_TIMEOUT),
      });
      preflightStatus = resp.status;
      for (const key of [
        'access-control-allow-origin',
        'access-control-allow-methods',
        'access-control-allow-headers',
        'access-control-allow-credentials',
        'access-control-max-age',
        'vary',
      ]) {
        const val = resp.headers.get(key);
        if (val) preflightReceived[key] = val;
      }
    } catch (err) {
      return {
        allowed: false,
        reason: `Preflight request failed: ${err instanceof Error ? err.message : 'unknown error'}`,
        preflight: {
          sent: preflightHeaders,
          received: {},
        },
        fix: {
          explanation: 'The server did not respond to the OPTIONS preflight request. Ensure your server handles OPTIONS requests and returns CORS headers.',
          headers: buildFixHeaders(origin, method, headers, credentials),
          docs: SERVER_DOCS,
        },
      };
    }
  }

  // Send actual request with Origin
  const actualReqHeaders: Record<string, string> = {
    'User-Agent': 'preflight.lol/1.0',
    'Origin': origin,
    'Accept': '*/*',
  };

  let actualReceived: Record<string, string> = {};
  try {
    const resp = await fetch(target, {
      method: method === 'HEAD' ? 'HEAD' : 'GET', // CF Workers don't allow arbitrary methods on fetch
      redirect: 'manual',
      headers: actualReqHeaders,
      signal: AbortSignal.timeout(FETCH_TIMEOUT),
    });
    for (const key of [
      'access-control-allow-origin',
      'access-control-allow-credentials',
      'access-control-expose-headers',
      'vary',
    ]) {
      const val = resp.headers.get(key);
      if (val) actualReceived[key] = val;
    }
  } catch (err) {
    return {
      allowed: false,
      reason: `Request failed: ${err instanceof Error ? err.message : 'unknown error'}`,
      preflight: { sent: preflightHeaders, received: preflightReceived },
    };
  }

  // Determine if allowed
  const corsHeaders = !isSimple ? preflightReceived : actualReceived;
  const acao = corsHeaders['access-control-allow-origin'];
  const acac = corsHeaders['access-control-allow-credentials'];

  const reasons: string[] = [];

  if (!acao) {
    reasons.push('No Access-Control-Allow-Origin header in the response.');
  } else if (acao !== '*' && acao !== origin) {
    reasons.push(`Access-Control-Allow-Origin is "${acao}" but your origin is "${origin}".`);
  }

  if (credentials && acao === '*') {
    reasons.push('Credentials requested but Access-Control-Allow-Origin is wildcard (*). Browsers block this combination.');
  }

  if (credentials && acac?.toLowerCase() !== 'true') {
    reasons.push('Credentials requested but Access-Control-Allow-Credentials is not "true".');
  }

  if (!isSimple) {
    if (preflightStatus < 200 || preflightStatus >= 300) {
      reasons.push(`Preflight (OPTIONS) returned ${preflightStatus}. Browsers require a 2xx response.`);
    }

    const allowedMethods = (preflightReceived['access-control-allow-methods'] || '').split(',').map(m => m.trim().toUpperCase());
    if (!allowedMethods.includes(method.toUpperCase()) && method.toUpperCase() !== 'GET' && method.toUpperCase() !== 'HEAD' && method.toUpperCase() !== 'POST') {
      reasons.push(`Method "${method}" is not in Access-Control-Allow-Methods (${allowedMethods.join(', ') || 'none'}).`);
    }

    if (headers.length > 0) {
      const allowedHeaders = (preflightReceived['access-control-allow-headers'] || '').split(',').map(h => h.trim().toLowerCase());
      const blocked = headers.filter(h => !allowedHeaders.includes(h.toLowerCase()) && !isSafelistedHeader(h));
      if (blocked.length > 0) {
        reasons.push(`Header(s) ${blocked.join(', ')} not in Access-Control-Allow-Headers.`);
      }
    }
  }

  const allowed = reasons.length === 0;

  const result: CORSSimulationResult = {
    allowed,
    reason: allowed ? 'Request is allowed by the server\'s CORS policy.' : reasons.join(' '),
    preflight: {
      sent: isSimple ? actualReqHeaders : preflightHeaders,
      received: isSimple ? actualReceived : preflightReceived,
    },
  };

  if (!allowed) {
    result.fix = {
      explanation: reasons.join(' '),
      headers: buildFixHeaders(origin, method, headers, credentials),
      docs: SERVER_DOCS,
    };
  }

  return result;
}

/** Check if a request qualifies as a CORS "simple request" */
function isSimpleRequest(method: string, headers: string[]): boolean {
  const simpleMethods = ['GET', 'HEAD', 'POST'];
  if (!simpleMethods.includes(method.toUpperCase())) return false;

  // If any non-safelisted headers, it's not simple
  return headers.every(h => isSafelistedHeader(h));
}

/** Check if a header is CORS-safelisted */
function isSafelistedHeader(header: string): boolean {
  const safelisted = ['accept', 'accept-language', 'content-language', 'content-type'];
  return safelisted.includes(header.toLowerCase());
}

/** Build the correct CORS headers for a fix suggestion */
function buildFixHeaders(origin: string, method: string, headers: string[], credentials: boolean): Record<string, string> {
  const fix: Record<string, string> = {};

  if (credentials) {
    fix['Access-Control-Allow-Origin'] = origin;
    fix['Access-Control-Allow-Credentials'] = 'true';
    fix['Vary'] = 'Origin';
  } else {
    fix['Access-Control-Allow-Origin'] = origin;
  }

  if (!isSimpleRequest(method, headers)) {
    const methods = new Set(['GET', 'HEAD', 'POST', method.toUpperCase()]);
    fix['Access-Control-Allow-Methods'] = [...methods].join(', ');

    if (headers.length > 0) {
      fix['Access-Control-Allow-Headers'] = headers.join(', ');
    }

    fix['Access-Control-Max-Age'] = '86400';
  }

  return fix;
}
