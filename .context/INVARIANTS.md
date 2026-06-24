# xhttp.lol — Invariants

> Things that must ALWAYS be true. Adding or removing an invariant requires explicit human approval.

## Core Product

- [ ] **Five analysis axes.** Every full scan returns: CORS, CSP, security headers, redirect chain, cache behavior.
  - _Verify:_ Check `runScan()` in `handler.ts` — must run all five analyses.

- [ ] **Letter grade in every response.** Overall grade (A+ through F) computed from weighted sub-grades.
  - _Verify:_ Check `computeOverallGrade()` in `handler.ts`.

- [ ] **Sub-route filtering.** `/{domain}/cors`, `/{domain}/csp`, `/{domain}/headers`, `/{domain}/chain`, `/{domain}/cache` return filtered results.
  - _Verify:_ Check `filterResult()` in `handler.ts`.

- [ ] **Fix suggestions with MDN links.** Every finding with a fix includes `fix` and optionally `mdn` fields.
  - _Verify:_ Check `Finding` type in `types.ts`.

## API

- [ ] **Content negotiation.** `Accept: text/html` returns SPA HTML. Default returns JSON.
  - _Verify:_ Check `wantsHtml` logic in `handleRequest()`.

- [ ] **`_meta` block in every scan response.** Version, scan time, cache hit status, cross-links.
  - _Verify:_ Check `ScanResult._meta` in `types.ts`.

- [ ] **POST endpoints for interactive tools.** `/cors` (simulation), `/error` (decoder), `/csp/evaluate` (policy eval).
  - _Verify:_ Check POST routing in `handleRequest()`.

## Privacy & Security

- [ ] **No raw user IPs in storage.** Rate limiting uses DO keyed by IP, but no IPs in KV or logs.
  - _Verify:_ Check rate limiter — IPs used as DO keys only, not persisted.

- [ ] **Security headers on every response.** CSP, HSTS, X-Content-Type-Options, X-Frame-Options, etc.
  - _Verify:_ Check `SECURITY_HEADERS` and `secHeaders()` in `handler.ts`.

- [ ] **No `as any`.** TypeScript strict mode.
  - _Verify:_ `grep -r 'as any' src/` — must return zero results.

## Build & Deploy

- [ ] **GitHub Actions CI/CD.** Typecheck → deploy on push to main.
  - _Verify:_ Check `.github/workflows/`.

- [ ] **Pre-commit hooks active.**
  - _Verify:_ `git config core.hooksPath`.
