# xhttp.lol — Project Constitution

> Stable identity, architecture, and red lines. Changes here are rare and require discussion.

## What xhttp.lol Is

Free, open-source HTTP response debugger at [xhttp.lol](https://xhttp.lol). Users submit a domain → get a comprehensive analysis of CORS configuration, CSP policy, security headers, redirect chain, cache behavior, and TLS version. Letter-graded results with actionable fix suggestions. MIT license, repo at `yokedotlol/xhttp`.

**Tagline:** *"The HTTP response debugger."*

Formerly preflight.lol — renamed to xhttp.lol in June 2026.

## Architecture

| Layer | Technology | Location |
|-------|-----------|----------|
| Worker | Cloudflare Workers (TypeScript, zero-framework) | `src/` |
| CLI | Go binary | `cli/` |
| SPA | Server-rendered HTML (built into Worker response) | `src/spa.ts` |

### Storage
- **KV `CACHE`** — scan result cache (1hr TTL). Cache keys are `scan:{domain}:{route}`.
- **Durable Object `RateLimiterDO`** — per-IP rate limiting (60/hr).

### External Dependencies
- **Yoke Fly probe** — TLS version detection via `PROBE_URL` env var. Degrades gracefully if unavailable.

## The .lol Family

xhttp.lol is part of a family of developer utilities that share the same ethos and stack conventions.

| Project | What it does |
|---------|-------------|
| yoke.lol | Domain intelligence (the hub) |
| certs.lol | TLS/SSL certificate analysis |
| ns.lol | DNS toolkit |
| vrfy.lol | Email address validation |
| **xhttp.lol** | HTTP response debugger |

xhttp.lol is standalone — not a feeder tool to yoke. It includes informational cross-links to yoke (full report), certs (TLS details), ns (DNS details), and vrfy in `_meta.links`.

## Core Principles

1. **Five analysis axes.** CORS, CSP, security headers, redirect chain, cache behavior. Plus TLS version via probe.
2. **Letter grades.** Overall grade (A+ through F) from weighted sub-grades: headers 40%, CSP 30%, CORS 15%, redirects 15%.
3. **Fix suggestions with docs.** Every finding includes a fix suggestion and MDN link where applicable.
4. **POST endpoints for tooling.** `/cors` (CORS simulation), `/error` (CORS error decoder), `/csp/evaluate` (CSP policy evaluator).
5. **No accounts, no tracking, no API keys.** IP-based rate limiting only.
6. **Content negotiation.** Browsers get HTML SPA, API clients get JSON.

## Red Lines

- **No `as any`.** TypeScript strict mode, no escape hatches.
- **Secrets never in code or wrangler.toml.** Use `wrangler secret put`.
- **No unbounded response reads.** All external fetches have timeouts (10s).

## Cost Awareness

Same model as the .lol family — CF Workers $5/mo Paid plan.

- KV reads: $0.50/M (cache)
- KV writes: $5.00/M (cache results per domain)
- DO requests: $0.15/M (rate limiting)

## .ai/ Maintenance Protocol

Same as the family: CONSTITUTION changes are rare and require discussion. DECISIONS is append-only. INVARIANTS require explicit approval to add/remove.
