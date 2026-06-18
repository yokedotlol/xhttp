// Shared types for xhttp.lol

export type Severity = 'critical' | 'high' | 'warning' | 'info' | 'pass';

export interface Finding {
  severity: Severity;
  code: string;
  message: string;
  fix?: string;
  mdn?: string;
}

// ── CORS ────────────────────────────────────────────────────────────

export interface CORSResult {
  enabled: boolean;
  allow_origin: string | null;
  allow_credentials: boolean;
  allow_methods: string[];
  allow_headers: string[];
  expose_headers: string[];
  max_age: number | null;
  preflight_status: number | null;
  vary_origin: boolean;
  issues: Finding[];
}

export interface CORSSimulationRequest {
  target: string;
  origin: string;
  method?: string;
  headers?: string[];
  credentials?: boolean;
}

export interface CORSSimulationResult {
  allowed: boolean;
  reason: string;
  preflight: {
    sent: Record<string, string>;
    received: Record<string, string>;
  };
  fix?: {
    explanation: string;
    headers: Record<string, string>;
    docs: Record<string, string>;
  };
}

// ── CSP ─────────────────────────────────────────────────────────────

export interface CSPDirectiveMap {
  [directive: string]: string[];
}

export interface CSPResult {
  present: boolean;
  mode: 'enforce' | 'report-only' | 'none';
  raw: string | null;
  parsed: CSPDirectiveMap;
  grade: string;
  issues: Finding[];
  missing_directives: string[];
}

// ── Security Headers ────────────────────────────────────────────────

export interface HeaderCheck {
  present: boolean;
  value: string | null;
  issues: Finding[];
  recommendation?: string;
}

export interface SecurityHeadersResult {
  grade: string;
  headers: {
    'strict-transport-security': HeaderCheck & { preload_eligible?: boolean; preload_listed?: boolean };
    'x-frame-options': HeaderCheck;
    'x-content-type-options': HeaderCheck;
    'referrer-policy': HeaderCheck;
    'permissions-policy': HeaderCheck;
    'content-security-policy': HeaderCheck;
    'cross-origin-opener-policy': HeaderCheck;
    'cross-origin-embedder-policy': HeaderCheck;
    'cross-origin-resource-policy': HeaderCheck;
  };
  conflicts: Finding[];
  score: number;
  max_score: number;
}

// ── Redirect Chain ──────────────────────────────────────────────────

export interface RedirectHop {
  url: string;
  status: number;
  location: string | null;
  timing_ms: number;
  headers_summary: Record<string, string>;
  hsts?: string | null;
}

export interface RedirectChainResult {
  hops: number;
  loop_detected: boolean;
  mixed_content: boolean;
  chain: RedirectHop[];
  issues: Finding[];
  total_time_ms: number;
}

// ── Cache ───────────────────────────────────────────────────────────

export interface CacheResult {
  cache_control: string | null;
  parsed: Record<string, string | boolean | number>;
  effective_ttl: number | null;
  vary: string[];
  cdn_status: string | null;
  cdn_provider: string | null;
  issues: Finding[];
  explanation: string;
}

// ── Full Scan ───────────────────────────────────────────────────────

export interface ScanResult {
  url: string;
  scanned_at: string;
  grade: string;
  cors: CORSResult;
  csp: CSPResult;
  security_headers: SecurityHeadersResult;
  redirect_chain: RedirectChainResult;
  cache: CacheResult;
  tls: {
    version: string | null;
    details: string;
  };
  _meta: {
    version: string;
    scan_time_ms: number;
    cache_hit: boolean;
    links: {
      full_report: string;
      tls_details: string;
      dns_details: string;
      email_validation: string;
    };
  };
}

// ── CORS Error Decoder ──────────────────────────────────────────────

export interface CORSErrorDecodeRequest {
  error: string;
}

export interface CORSErrorDecodeResult {
  diagnosis: string;
  likely_cause: string;
  fix_steps: string[];
  headers_needed: Record<string, string>;
  docs: Record<string, string>;
}

// ── CSP Evaluate ────────────────────────────────────────────────────

export interface CSPEvaluateRequest {
  policy: string;
}
