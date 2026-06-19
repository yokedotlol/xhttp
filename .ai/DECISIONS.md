# xhttp.lol — Decision Log

> Append-only record of significant decisions. Never edit or remove entries.

---

### 2026-06 — Renamed from preflight.lol to xhttp.lol

**What changed:** Tool renamed from preflight.lol to xhttp.lol. GitHub repo renamed from `yokedotlol/preflight` to `yokedotlol/xhttp`. Domain changed. All internal references updated.
**Why:** "xhttp" better describes what the tool does (HTTP response analysis). "preflight" was too narrowly associated with CORS preflight requests — the tool covers much more (security headers, CSP, cache, redirects).
**Directive:** Use "xhttp" everywhere. Old "preflight" references are historical only.

---

### 2026-06 — Letter grades for scoring (not tiers)

**What changed:** xhttp uses traditional letter grades (A+ through F) for scoring, not Yoke's descriptive tiers (Excellent/Strong/Moderate/Weak/Critical).
**Why:** HTTP header analysis is closer to the SSL Labs / SecurityHeaders.io convention — letter grades are the industry standard here. The weighted sub-grade formula (headers 40%, CSP 30%, CORS 15%, redirects 15%) maps naturally to letter grades.
**Directive:** Keep letter grades. This is intentionally different from Yoke's tier system — each tool uses the scoring convention that fits its domain.

---

### 2026-06 — Uses real Chrome User-Agent for probing

**What changed:** External HTTP fetches use a real Chrome User-Agent string instead of a bot identifier.
**Why:** Sites behind WAFs/CDNs serve different responses to bots. To analyze what a real browser sees, we need to look like a real browser.
**Directive:** Keep the Chrome UA. Update it when major Chrome versions ship.

---

### 2026-06 — Cross-links to family in _meta.links

**What changed:** Every scan response includes `_meta.links` with URLs to yoke.lol (full report), certs.lol (TLS details), ns.lol (DNS details), and vrfy.lol (email validation).
**Why:** Unlike vrfy.lol, the context switch is natural: "your headers are configured, here's your full domain report." These are informational cross-references, not a feeder funnel.
**Directive:** xhttp is standalone — these are convenience links, not a dependency.

---

### 2026-06 — TLS version via Yoke probe

**What changed:** TLS version detection delegated to the shared Yoke Fly probe (`PROBE_URL`). Falls back to null if probe unavailable.
**Why:** CF Workers can't do raw TLS handshakes. The probe already exists for Yoke. Reusing it avoids deploying a separate probe.
**Directive:** TLS is informational in xhttp (deep link to certs.lol for full analysis). Probe failure should never block a scan.
