// CORS error message decoder — paste a browser console error, get diagnosis + fix

import type { CORSErrorDecodeResult } from './types';

interface ErrorPattern {
  pattern: RegExp;
  error_type: string;
  diagnosis: string;
  likely_cause: string;
  fix_steps: string[];
  headers_needed: Record<string, string>;
}

const SERVER_DOCS: Record<string, string> = {
  nginx: 'https://nginx.org/en/docs/http/ngx_http_headers_module.html',
  apache: 'https://httpd.apache.org/docs/current/mod/mod_headers.html',
  express: 'https://expressjs.com/en/resources/middleware/cors.html',
  cloudflare_workers: 'https://developers.cloudflare.com/workers/examples/cors-header-proxy/',
  caddy: 'https://caddyserver.com/docs/caddyfile/directives/header',
};

const PATTERNS: ErrorPattern[] = [
  // No Access-Control-Allow-Origin header
  {
    pattern: /No 'Access-Control-Allow-Origin' header is present|has been blocked by CORS policy.*No.*Access-Control-Allow-Origin|CORS Missing Allow Origin/i,
    error_type: 'missing_acao',
    diagnosis: 'The server is not returning an Access-Control-Allow-Origin header.',
    likely_cause: 'CORS middleware is missing or not configured to run on this route. If the error mentions a preflight request, the server may not be handling OPTIONS requests.',
    fix_steps: [
      'Ensure your server responds with Access-Control-Allow-Origin on all responses (including OPTIONS).',
      'Set Access-Control-Allow-Origin to your frontend\'s origin or * for public APIs.',
      'For OPTIONS requests, return 204 No Content with the CORS headers.',
    ],
    headers_needed: { 'Access-Control-Allow-Origin': 'https://your-frontend.com' },
  },

  // Wildcard with credentials
  {
    pattern: /cannot use wildcard.*when credentials|credentials flag.*wildcard|The value of.*Access-Control-Allow-Origin.*must not be the wildcard/i,
    error_type: 'wildcard_credentials',
    diagnosis: 'The server returns Access-Control-Allow-Origin: * but the request includes credentials. Browsers block this combination.',
    likely_cause: 'The request uses cookies or Authorization headers (credentials mode), but the server uses a wildcard origin. CORS requires a specific origin when credentials are involved.',
    fix_steps: [
      'Change Access-Control-Allow-Origin from * to the specific requesting origin.',
      'Add Access-Control-Allow-Credentials: true.',
      'Add Vary: Origin so caches serve the correct response per origin.',
    ],
    headers_needed: {
      'Access-Control-Allow-Origin': 'https://your-frontend.com',
      'Access-Control-Allow-Credentials': 'true',
      'Vary': 'Origin',
    },
  },

  // Preflight response failure
  {
    pattern: /preflight request.*doesn't pass|Response to preflight request/i,
    error_type: 'preflight_failure',
    diagnosis: 'The preflight (OPTIONS) request did not receive the required CORS headers.',
    likely_cause: 'Your server is not handling OPTIONS requests, or the CORS middleware isn\'t running on preflight requests. Some frameworks need explicit OPTIONS route handlers.',
    fix_steps: [
      'Add an OPTIONS handler for the affected route that returns 204 with CORS headers.',
      'Ensure CORS middleware runs before route handlers and authentication.',
      'Set Access-Control-Allow-Methods to include the method being used.',
      'Set Access-Control-Allow-Headers to include any custom headers.',
    ],
    headers_needed: {
      'Access-Control-Allow-Origin': 'https://your-frontend.com',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    },
  },

  // Method not allowed
  {
    pattern: /Method.*not allowed|Access-Control-Allow-Methods/i,
    error_type: 'method_not_allowed',
    diagnosis: 'The requested HTTP method is not listed in Access-Control-Allow-Methods.',
    likely_cause: 'The preflight response does not include the method you\'re trying to use (e.g., PUT, DELETE, PATCH).',
    fix_steps: [
      'Add the required method to Access-Control-Allow-Methods in your OPTIONS response.',
      'Common value: GET, POST, PUT, DELETE, PATCH, OPTIONS.',
    ],
    headers_needed: { 'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, PATCH, OPTIONS' },
  },

  // Header not allowed
  {
    pattern: /header.*not allowed|Request header field.*not allowed|Access-Control-Allow-Headers/i,
    error_type: 'header_not_allowed',
    diagnosis: 'A request header is not listed in Access-Control-Allow-Headers.',
    likely_cause: 'The request includes a custom header (like Authorization or X-Custom-Header) that the server\'s preflight response does not allow.',
    fix_steps: [
      'Add the header name to Access-Control-Allow-Headers in your OPTIONS response.',
      'Include all custom headers your frontend sends.',
    ],
    headers_needed: { 'Access-Control-Allow-Headers': 'Content-Type, Authorization' },
  },

  // Redirect not allowed
  {
    pattern: /redirect is not allowed.*preflight|CORS request.*redirect/i,
    error_type: 'redirect_on_preflight',
    diagnosis: 'The server is redirecting the preflight (OPTIONS) request. CORS does not allow redirects on preflight.',
    likely_cause: 'A redirect rule (HTTP→HTTPS, www→non-www, or trailing slash) is being applied to the OPTIONS request.',
    fix_steps: [
      'Ensure OPTIONS requests are handled before any redirect middleware.',
      'Exclude OPTIONS from redirect rules.',
      'Make the initial request URL match the final URL (use HTTPS, correct hostname).',
    ],
    headers_needed: {},
  },

  // Origin mismatch
  {
    pattern: /origin.*is not allowed|not an allowed origin|not equal to the supplied origin/i,
    error_type: 'origin_mismatch',
    diagnosis: 'The requesting origin is not in the server\'s allowed origins list.',
    likely_cause: 'The server has a specific origin allowlist that doesn\'t include your frontend\'s origin. Check for protocol (http vs https), port, and subdomain differences.',
    fix_steps: [
      'Add your frontend\'s exact origin to the server\'s CORS allowlist.',
      'Remember that origins include protocol + hostname + port (e.g., https://app.example.com).',
      'http://localhost:3000 and http://localhost:5173 are different origins.',
    ],
    headers_needed: { 'Access-Control-Allow-Origin': 'https://your-frontend.com' },
  },

  // Opaque response / no-cors mode
  {
    pattern: /opaque.*response|no-cors/i,
    error_type: 'opaque_response',
    diagnosis: 'The response is opaque — fetched with mode: "no-cors", which strips all readable data.',
    likely_cause: 'The fetch() call uses mode: "no-cors" (or a <script>/<img> tag made the request). The browser fetched the resource but JavaScript can\'t read it.',
    fix_steps: [
      'Change the fetch() call to mode: "cors" (the default).',
      'Configure the server to return proper CORS headers.',
      'If you don\'t control the server, use a server-side proxy instead of a browser fetch.',
    ],
    headers_needed: {},
  },

  // Network error
  {
    pattern: /Failed to fetch|NetworkError|net::ERR_FAILED|TypeError.*fetch/i,
    error_type: 'network_error',
    diagnosis: 'The request failed at the network level before CORS could be evaluated.',
    likely_cause: 'This could be: the server is down, the URL is wrong, HTTPS certificate issues, or a firewall/ad blocker is blocking the request. Browsers report CORS-blocked requests as network errors for security reasons.',
    fix_steps: [
      'Verify the server URL is correct and the server is running.',
      'Check the browser DevTools Network tab for the actual HTTP status.',
      'If the server returns an error (4xx, 5xx) without CORS headers, browsers report it as a CORS error.',
      'Test with curl to isolate network vs CORS issues.',
    ],
    headers_needed: {},
  },
];

/** Decode a CORS error message from a browser console */
export function decodeCORSError(errorText: string): CORSErrorDecodeResult {
  for (const pattern of PATTERNS) {
    if (pattern.pattern.test(errorText)) {
      return {
        diagnosis: pattern.diagnosis,
        likely_cause: pattern.likely_cause,
        fix_steps: pattern.fix_steps,
        headers_needed: pattern.headers_needed,
        docs: SERVER_DOCS,
      };
    }
  }

  // Generic fallback
  return {
    diagnosis: 'Could not match this error to a known CORS pattern.',
    likely_cause: 'This might be a CORS-related error wrapped in a different format, or a non-CORS issue.',
    fix_steps: [
      'Check the browser DevTools Network tab for the actual request/response.',
      'Look for the OPTIONS preflight request — if it fails or is missing CORS headers, that\'s the problem.',
      'Test the same request with curl to see the raw response headers.',
      'Ensure the server returns Access-Control-Allow-Origin on all responses, including errors.',
    ],
    headers_needed: { 'Access-Control-Allow-Origin': 'https://your-frontend.com' },
    docs: SERVER_DOCS,
  };
}
