package main

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// analyzeSecurityHeaders analyzes security headers from an HTTP response.
func analyzeSecurityHeaders(headers http.Header) SecurityHeaders {
	conflicts := make([]Finding, 0)
	score := 0
	maxScore := 100

	// ── HSTS ──────────────────────────────────────────────────────────
	hsts := analyzeHSTS(headers)
	score += hstsScore(hsts)

	// ── X-Frame-Options ───────────────────────────────────────────────
	xfo := analyzeXFO(headers)
	if xfo.Present {
		score += 10
	}

	// ── X-Content-Type-Options ────────────────────────────────────────
	xcto := analyzeXCTO(headers)
	if xcto.Present {
		score += 10
	}

	// ── Referrer-Policy ───────────────────────────────────────────────
	referrer := analyzeReferrerPolicy(headers)
	if referrer.Present {
		score += 10
	}

	// ── Permissions-Policy ────────────────────────────────────────────
	permissions := analyzePermissionsPolicy(headers)
	if permissions.Present {
		score += 10
	}

	// ── CSP (presence check) ──────────────────────────────────────────
	cspHeader := headers.Get("Content-Security-Policy")
	cspCheck := HeaderCheck{
		Present: cspHeader != "",
		Issues:  make([]Finding, 0),
	}
	if cspHeader != "" {
		cspCheck.Value = &cspHeader
	}
	if cspHeader == "" {
		cspCheck.Issues = append(cspCheck.Issues, Finding{
			Severity: "high",
			Code:     "NO_CSP_HEADER",
			Message:  "No Content-Security-Policy header.",
			Fix:      "Add a Content-Security-Policy header to control resource loading.",
			MDN:      "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
		})
		cspCheck.Recommendation = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'; base-uri 'self'"
	}
	if cspHeader != "" {
		score += 15
	}

	// ── COOP ──────────────────────────────────────────────────────────
	coopVal := headers.Get("Cross-Origin-Opener-Policy")
	coop := HeaderCheck{
		Present: coopVal != "",
		Issues:  make([]Finding, 0),
	}
	if coopVal != "" {
		coop.Value = &coopVal
	}
	if coopVal == "" {
		coop.Recommendation = "same-origin"
	}
	if coopVal != "" {
		score += 5
	}

	// ── COEP ──────────────────────────────────────────────────────────
	coepVal := headers.Get("Cross-Origin-Embedder-Policy")
	coep := HeaderCheck{
		Present: coepVal != "",
		Issues:  make([]Finding, 0),
	}
	if coepVal != "" {
		coep.Value = &coepVal
	}
	if coepVal == "" {
		coep.Recommendation = "credentialless"
	}
	if coepVal != "" {
		score += 5
	}

	// ── CORP ──────────────────────────────────────────────────────────
	corpVal := headers.Get("Cross-Origin-Resource-Policy")
	corp := HeaderCheck{
		Present: corpVal != "",
		Issues:  make([]Finding, 0),
	}
	if corpVal != "" {
		corp.Value = &corpVal
	}
	if corpVal == "" {
		corp.Recommendation = "same-origin"
	}
	if corpVal != "" {
		score += 5
	}

	// ── Conflicts ─────────────────────────────────────────────────────
	xxss := headers.Get("X-XSS-Protection")
	if xxss != "" && xxss != "0" {
		conflicts = append(conflicts, Finding{
			Severity: "info",
			Code:     "XXSS_PROTECTION_ENABLED",
			Message:  fmt.Sprintf("X-XSS-Protection is set to %q. This header is deprecated and can introduce vulnerabilities in older browsers. Modern browsers ignore it.", xxss),
			Fix:      "Set X-XSS-Protection: 0 to explicitly disable it, and rely on CSP for XSS protection.",
			MDN:      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection",
		})
	}

	grade := scoreToGrade(score, maxScore)

	return SecurityHeaders{
		Grade: grade,
		Headers: map[string]HeaderCheck{
			"strict-transport-security":   hsts,
			"x-frame-options":             xfo,
			"x-content-type-options":      xcto,
			"referrer-policy":             referrer,
			"permissions-policy":          permissions,
			"content-security-policy":     cspCheck,
			"cross-origin-opener-policy":  coop,
			"cross-origin-embedder-policy": coep,
			"cross-origin-resource-policy": corp,
		},
		Conflicts: conflicts,
		Score:     score,
		MaxScore:  maxScore,
	}
}

// ── Individual header analyzers ─────────────────────────────────────

var maxAgeRegexp = regexp.MustCompile(`max-age=(\d+)`)

func analyzeHSTS(headers http.Header) HeaderCheck {
	raw := headers.Get("Strict-Transport-Security")
	result := HeaderCheck{
		Present: raw != "",
		Issues:  make([]Finding, 0),
	}
	if raw != "" {
		result.Value = &raw
	}

	if raw == "" {
		result.Issues = append(result.Issues, Finding{
			Severity: "high",
			Code:     "NO_HSTS",
			Message:  "No Strict-Transport-Security header. The site can be downgraded to HTTP.",
			Fix:      "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
			MDN:      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
		})
		result.Recommendation = "max-age=31536000; includeSubDomains; preload"
		return result
	}

	lower := strings.ToLower(raw)
	var maxAge int
	if m := maxAgeRegexp.FindStringSubmatch(lower); len(m) > 1 {
		fmt.Sscanf(m[1], "%d", &maxAge)
	}
	includesSubs := strings.Contains(lower, "includesubdomains")
	preload := strings.Contains(lower, "preload")

	if maxAge < 31536000 {
		result.Issues = append(result.Issues, Finding{
			Severity: "warning",
			Code:     "HSTS_SHORT_MAX_AGE",
			Message:  fmt.Sprintf("HSTS max-age is %d seconds (%d days). Best practice is at least 1 year (31536000).", maxAge, maxAge/86400),
			Fix:      "Set max-age=31536000 (1 year) or higher.",
		})
	}

	if !includesSubs {
		result.Issues = append(result.Issues, Finding{
			Severity: "warning",
			Code:     "HSTS_NO_SUBDOMAINS",
			Message:  "HSTS does not include subdomains. Subdomains can still be accessed over HTTP.",
			Fix:      "Add includeSubDomains to enforce HSTS on all subdomains.",
		})
	}

	if !preload {
		result.Issues = append(result.Issues, Finding{
			Severity: "info",
			Code:     "HSTS_NO_PRELOAD",
			Message:  "HSTS preload directive is missing. The site is not eligible for browser preload lists.",
			Fix:      "Add the preload directive and submit to hstspreload.org to be hardcoded into browsers.",
		})
	}

	eligible := maxAge >= 31536000 && includesSubs && preload
	result.PreloadEligible = &eligible

	return result
}

func analyzeXFO(headers http.Header) HeaderCheck {
	raw := headers.Get("X-Frame-Options")
	result := HeaderCheck{
		Present: raw != "",
		Issues:  make([]Finding, 0),
	}
	if raw != "" {
		result.Value = &raw
	}

	if raw == "" {
		result.Issues = append(result.Issues, Finding{
			Severity: "warning",
			Code:     "NO_XFO",
			Message:  "No X-Frame-Options header. The page can be embedded in iframes (clickjacking risk).",
			Fix:      "Add X-Frame-Options: DENY (or SAMEORIGIN if you need self-framing). Better: use CSP frame-ancestors.",
			MDN:      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
		})
		result.Recommendation = "DENY"
		return result
	}

	upper := strings.ToUpper(strings.TrimSpace(raw))
	if upper != "DENY" && upper != "SAMEORIGIN" {
		result.Issues = append(result.Issues, Finding{
			Severity: "warning",
			Code:     "XFO_INVALID",
			Message:  fmt.Sprintf("X-Frame-Options value %q is not valid. Only DENY and SAMEORIGIN are supported.", raw),
			Fix:      "Set X-Frame-Options to DENY or SAMEORIGIN.",
		})
	}

	if strings.HasPrefix(upper, "ALLOW-FROM") {
		result.Issues = append(result.Issues, Finding{
			Severity: "warning",
			Code:     "XFO_ALLOW_FROM_DEPRECATED",
			Message:  "ALLOW-FROM is deprecated and not supported by modern browsers. Use CSP frame-ancestors instead.",
			Fix:      "Replace X-Frame-Options: ALLOW-FROM with Content-Security-Policy: frame-ancestors <origin>.",
		})
	}

	return result
}

func analyzeXCTO(headers http.Header) HeaderCheck {
	raw := headers.Get("X-Content-Type-Options")
	result := HeaderCheck{
		Present: raw != "",
		Issues:  make([]Finding, 0),
	}
	if raw != "" {
		result.Value = &raw
	}

	if raw == "" {
		result.Issues = append(result.Issues, Finding{
			Severity: "warning",
			Code:     "NO_XCTO",
			Message:  "No X-Content-Type-Options header. Browsers may MIME-sniff responses, enabling attacks.",
			Fix:      "Add X-Content-Type-Options: nosniff",
			MDN:      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
		})
		result.Recommendation = "nosniff"
		return result
	}

	if strings.ToLower(strings.TrimSpace(raw)) != "nosniff" {
		result.Issues = append(result.Issues, Finding{
			Severity: "warning",
			Code:     "XCTO_INVALID",
			Message:  fmt.Sprintf("X-Content-Type-Options value %q is not valid. Only \"nosniff\" is supported.", raw),
			Fix:      "Set X-Content-Type-Options: nosniff",
		})
	}

	return result
}

func analyzeReferrerPolicy(headers http.Header) HeaderCheck {
	raw := headers.Get("Referrer-Policy")
	result := HeaderCheck{
		Present: raw != "",
		Issues:  make([]Finding, 0),
	}
	if raw != "" {
		result.Value = &raw
	}

	if raw == "" {
		result.Issues = append(result.Issues, Finding{
			Severity: "warning",
			Code:     "NO_REFERRER_POLICY",
			Message:  "No Referrer-Policy header. Browsers default to strict-origin-when-cross-origin, but explicit is better.",
			Fix:      "Add Referrer-Policy: strict-origin-when-cross-origin (or no-referrer for maximum privacy).",
			MDN:      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
		})
		result.Recommendation = "strict-origin-when-cross-origin"
		return result
	}

	leaky := map[string]bool{"unsafe-url": true, "no-referrer-when-downgrade": true}
	if leaky[strings.ToLower(strings.TrimSpace(raw))] {
		result.Issues = append(result.Issues, Finding{
			Severity: "warning",
			Code:     "REFERRER_LEAKY",
			Message:  fmt.Sprintf("Referrer-Policy %q leaks full URLs to other sites, including paths and query strings.", raw),
			Fix:      "Use strict-origin-when-cross-origin or strict-origin to limit referrer information.",
		})
	}

	return result
}

func analyzePermissionsPolicy(headers http.Header) HeaderCheck {
	raw := headers.Get("Permissions-Policy")
	isLegacy := false
	if raw == "" {
		raw = headers.Get("Feature-Policy")
		if raw != "" {
			isLegacy = true
		}
	}

	result := HeaderCheck{
		Present: raw != "",
		Issues:  make([]Finding, 0),
	}
	if raw != "" {
		result.Value = &raw
	}

	if raw == "" {
		result.Issues = append(result.Issues, Finding{
			Severity: "info",
			Code:     "NO_PERMISSIONS_POLICY",
			Message:  "No Permissions-Policy header. Browser features like camera, microphone, and geolocation use default permissions.",
			Fix:      "Add Permissions-Policy: camera=(), microphone=(), geolocation=() to restrict sensitive features.",
			MDN:      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
		})
		result.Recommendation = "camera=(), microphone=(), geolocation=()"
		return result
	}

	if isLegacy {
		result.Issues = append(result.Issues, Finding{
			Severity: "info",
			Code:     "FEATURE_POLICY_LEGACY",
			Message:  "Using deprecated Feature-Policy header instead of Permissions-Policy.",
			Fix:      "Replace Feature-Policy with Permissions-Policy. Syntax changed: e.g., camera 'none' → camera=()",
		})
	}

	return result
}

// ── Scoring / grading ───────────────────────────────────────────────

func hstsScore(hsts HeaderCheck) int {
	if !hsts.Present {
		return 0
	}
	raw := ""
	if hsts.Value != nil {
		raw = strings.ToLower(*hsts.Value)
	}
	var maxAge int
	if m := maxAgeRegexp.FindStringSubmatch(raw); len(m) > 1 {
		fmt.Sscanf(m[1], "%d", &maxAge)
	}

	s := 10
	if maxAge >= 31536000 {
		s += 5
	}
	if strings.Contains(raw, "includesubdomains") {
		s += 5
	}
	if strings.Contains(raw, "preload") {
		s += 5
	}
	if s > 20 {
		s = 20
	}
	return s
}

func scoreToGrade(score, max int) string {
	pct := float64(score) / float64(max) * 100
	if pct >= 90 {
		return "A"
	}
	if pct >= 80 {
		return "B"
	}
	if pct >= 65 {
		return "C"
	}
	if pct >= 50 {
		return "D"
	}
	return "F"
}
