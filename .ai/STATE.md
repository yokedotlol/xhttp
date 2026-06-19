# xhttp.lol — Current State

> Volatile snapshot of the project. Updated after significant sessions.

**Last updated:** 2026-06-18

## Versions

| Component | Version | Source |
|-----------|---------|--------|
| Worker (service) | 1.0.0 | `VERSION` constant in `handler.ts` |
| CLI | — | `cli/main.go` (exists, Go binary, install.sh) |

## Analysis Axes

| Axis | Weight | Source |
|------|--------|--------|
| Security Headers | 40% | `headers.ts` → `analyzeSecurityHeaders()` |
| CSP | 30% | `csp.ts` → `evaluateCSP()` |
| CORS | 15% | `cors.ts` → `analyzeCORS()` |
| Redirects | 15% | `redirect.ts` → `followRedirects()` |
| Cache | — (informational) | `cache-analysis.ts` → `analyzeCacheBehavior()` |
| TLS | — (informational) | Via Fly probe, deep link to certs.lol |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/{domain}` | Full scan (all axes) |
| GET | `/{domain}/cors` | CORS-only scan |
| GET | `/{domain}/csp` | CSP-only scan |
| GET | `/{domain}/headers` | Security headers only |
| GET | `/{domain}/chain` | Redirect chain only |
| GET | `/{domain}/cache` | Cache behavior only |
| POST | `/cors` | CORS simulation (custom origin/method/headers) |
| POST | `/error` | CORS error message decoder |
| POST | `/csp/evaluate` | CSP policy string evaluator |
| GET | `/health` | Health check |

## Infrastructure

| Resource | Details |
|----------|---------|
| Domain | xhttp.lol |
| GitHub | yokedotlol/xhttp |
| Worker name | `xhttp-lol` |
| KV namespace | `CACHE` (ID: `99fb192bba6c448e937d2b439d02b41b`) |
| CF Zone | `0bd021b3bdd02cc96aa6e1f0e14642f8` |
| Rate limit | 60/hr per IP (Durable Object) |
| Cache TTL | 1 hour |
| Probe | Shared Yoke Fly probe (`PROBE_URL`) |
| CI | GitHub Actions: typecheck + deploy + smoke tests |
| Tag | v1.0.0 |

## Static Pages

All served from `spa.ts` (server-rendered HTML):
- `/` — Landing page
- `/about` — About page
- `/privacy` — Privacy policy
- `/terms` — Terms of service
- `/cli` — CLI documentation
- `/api/docs` — API documentation

Also: `/robots.txt`, `/sitemap.xml`, `/security.txt`, `/llms.txt`, `/favicon.svg`, `/.well-known/mta-sts.txt`

## Open / Known Issues

- ~~`package.json` still says `"name": "preflight-lol"`~~ — fixed, now `xhttp-lol`
- ~~`/install.sh` redirects to `yokedotlol/preflight`~~ — fixed, now points to `yokedotlol/xhttp`
- ~~contact email was `hello@xhttp.lol`~~ — fixed to `hello@yoke.lol` per family convention
