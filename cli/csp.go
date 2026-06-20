package main

import (
	"regexp"
	"strings"
)

// CSPDirectiveMap maps CSP directive names to their values.
type CSPDirectiveMap map[string][]string

// parseCSP parses a raw CSP string into a directive map.
func parseCSP(raw string) CSPDirectiveMap {
	directives := make(CSPDirectiveMap)
	if raw == "" {
		return directives
	}
	parts := strings.Split(raw, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		tokens := strings.Fields(part)
		name := strings.ToLower(tokens[0])
		directives[name] = tokens[1:]
	}
	return directives
}

// evaluateCSPFromHeaders evaluates a CSP from response headers.
func evaluateCSPFromHeaders(raw string, allHeaders map[string]string) *CSPResult {
	if raw == "" {
		reportOnly := allHeaders["content-security-policy-report-only"]
		if reportOnly != "" {
			parsed := parseCSP(reportOnly)
			return &CSPResult{
				Present: true,
				Mode:    "report-only",
				Raw:     reportOnly,
				Parsed:  parsed,
				Grade:   "D",
				Issues: []Finding{{
					Severity: "warning",
					Code:     "CSP_REPORT_ONLY",
					Message:  "CSP is in report-only mode — violations are logged but not enforced.",
					Fix:      "Once you've verified your CSP isn't breaking anything, switch Content-Security-Policy-Report-Only to Content-Security-Policy to enforce it.",
					MDN:      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only",
				}},
				MissingDirectives: findMissingDirectives(parsed),
			}
		}

		return &CSPResult{
			Present: false,
			Mode:    "none",
			Raw:     "",
			Parsed:  CSPDirectiveMap{},
			Grade:   "F",
			Issues: []Finding{{
				Severity: "high",
				Code:     "NO_CSP",
				Message:  "No Content-Security-Policy header. The browser will load resources from any source.",
				Fix:      "Add a Content-Security-Policy header. Start with a restrictive policy like: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
				MDN:      "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
			}},
			MissingDirectives: nil,
		}
	}

	parsed := parseCSP(raw)
	issues := make([]Finding, 0)

	// Dangerous directives
	checkUnsafeInline(parsed, &issues)
	checkUnsafeEval(parsed, &issues)
	checkDataURI(parsed, &issues)
	checkBlobURI(parsed, &issues)
	checkWildcards(parsed, &issues)
	checkBypassPatterns(parsed, &issues)

	// Missing directives
	missing := findMissingDirectives(parsed)
	for _, directive := range missing {
		issues = append(issues, Finding{
			Severity: "warning",
			Code:     "MISSING_" + strings.ToUpper(strings.ReplaceAll(directive, "-", "_")),
			Message:  "Missing " + directive + " directive. Without it, " + directiveExplanation(directive) + ".",
			Fix:      "Add " + directive + " to your CSP. Recommended: " + directiveRecommendation(directive),
			MDN:      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/" + directive,
		})
	}

	// Conflict: frame-ancestors vs X-Frame-Options
	xfo := allHeaders["x-frame-options"]
	frameAncestors := parsed["frame-ancestors"]
	if xfo != "" && frameAncestors != nil {
		xfoNorm := strings.ToUpper(strings.TrimSpace(xfo))
		faStr := strings.Join(frameAncestors, " ")
		conflict := false

		if xfoNorm == "DENY" && faStr != "'none'" {
			conflict = true
		}
		if xfoNorm == "SAMEORIGIN" && faStr != "'self'" {
			conflict = true
		}

		if conflict {
			issues = append(issues, Finding{
				Severity: "warning",
				Code:     "XFO_CSP_CONFLICT",
				Message:  "X-Frame-Options (" + xfo + ") conflicts with CSP frame-ancestors (" + faStr + "). CSP takes precedence in modern browsers.",
				Fix:      "Remove X-Frame-Options and rely on CSP frame-ancestors. Or align both: DENY ↔ frame-ancestors 'none', SAMEORIGIN ↔ frame-ancestors 'self'.",
				MDN:      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors",
			})
		}
	}

	grade := gradeCSP(parsed, issues)

	return &CSPResult{
		Present:           true,
		Mode:              "enforce",
		Raw:               raw,
		Parsed:            parsed,
		Grade:             grade,
		Issues:            issues,
		MissingDirectives: missing,
	}
}

// evaluateCSPString evaluates a standalone CSP string (no live scan needed).
func evaluateCSPString(policy string) *CSPResult {
	return evaluateCSPFromHeaders(policy, map[string]string{})
}

// ── Issue detection ─────────────────────────────────────────────────

func checkUnsafeInline(parsed CSPDirectiveMap, issues *[]Finding) {
	for _, directive := range []string{"script-src", "script-src-elem", "script-src-attr", "default-src"} {
		values, ok := parsed[directive]
		if !ok {
			continue
		}
		for _, v := range values {
			if v != "'unsafe-inline'" {
				continue
			}
			hasNonceOrHash := false
			for _, v2 := range values {
				if strings.HasPrefix(v2, "'nonce-") || strings.HasPrefix(v2, "'sha256-") ||
					strings.HasPrefix(v2, "'sha384-") || strings.HasPrefix(v2, "'sha512-") {
					hasNonceOrHash = true
					break
				}
			}
			if hasNonceOrHash {
				*issues = append(*issues, Finding{
					Severity: "info",
					Code:     "UNSAFE_INLINE_WITH_NONCE",
					Message:  directive + " includes 'unsafe-inline' alongside nonce/hash values. The 'unsafe-inline' is ignored by modern browsers when nonce/hash is present (kept for backward compatibility).",
				})
			} else {
				sev := "high"
				if strings.HasPrefix(directive, "script") || directive == "default-src" {
					sev = "critical"
				}
				*issues = append(*issues, Finding{
					Severity: sev,
					Code:     "UNSAFE_INLINE",
					Message:  directive + " includes 'unsafe-inline', which allows inline scripts and defeats XSS protection.",
					Fix:      "Replace 'unsafe-inline' with nonce-based or hash-based script loading. Use 'nonce-{random}' and add the matching nonce attribute to your <script> tags.",
					MDN:      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src#unsafe_inline_script",
				})
			}
			break
		}
	}
}

func checkUnsafeEval(parsed CSPDirectiveMap, issues *[]Finding) {
	for _, directive := range []string{"script-src", "script-src-elem", "default-src"} {
		values, ok := parsed[directive]
		if !ok {
			continue
		}
		for _, v := range values {
			if v == "'unsafe-eval'" {
				*issues = append(*issues, Finding{
					Severity: "high",
					Code:     "UNSAFE_EVAL",
					Message:  directive + " includes 'unsafe-eval', allowing eval(), Function(), and setTimeout('string'). This enables code injection attacks.",
					Fix:      "Remove 'unsafe-eval' and refactor code to avoid eval(). Most modern frameworks don't need it.",
					MDN:      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src#unsafe_eval",
				})
				break
			}
		}
	}
}

func checkDataURI(parsed CSPDirectiveMap, issues *[]Finding) {
	for _, directive := range []string{"script-src", "default-src", "object-src"} {
		values, ok := parsed[directive]
		if !ok {
			continue
		}
		for _, v := range values {
			if v == "data:" {
				sev := "warning"
				if strings.HasPrefix(directive, "script") || directive == "default-src" {
					sev = "high"
				}
				*issues = append(*issues, Finding{
					Severity: sev,
					Code:     "DATA_URI",
					Message:  directive + " allows data: URIs, which can be used to inject executable content.",
					Fix:      "Remove data: from " + directive + ". If you need data: URIs for images, add them only to img-src.",
					MDN:      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/Sources#data",
				})
				break
			}
		}
	}
}

func checkBlobURI(parsed CSPDirectiveMap, issues *[]Finding) {
	for _, directive := range []string{"script-src", "default-src", "worker-src"} {
		values, ok := parsed[directive]
		if !ok {
			continue
		}
		for _, v := range values {
			if v == "blob:" {
				*issues = append(*issues, Finding{
					Severity: "warning",
					Code:     "BLOB_URI",
					Message:  directive + " allows blob: URIs, which can be used to create executable content dynamically.",
					Fix:      "Remove blob: from " + directive + " unless your application specifically needs it for Web Workers or dynamic scripts.",
				})
				break
			}
		}
	}
}

func checkWildcards(parsed CSPDirectiveMap, issues *[]Finding) {
	riskyDomains := []string{
		"googleapis.com", "gstatic.com", "cloudflare.com",
		"amazonaws.com", "azurewebsites.net",
	}

	for directive, values := range parsed {
		for _, val := range values {
			if val == "*" {
				sev := "high"
				if strings.HasPrefix(directive, "script") || directive == "default-src" {
					sev = "critical"
				}
				*issues = append(*issues, Finding{
					Severity: sev,
					Code:     "WILDCARD_SOURCE",
					Message:  directive + " uses wildcard (*), allowing resources from any host. This provides no meaningful protection.",
					Fix:      "Replace * with specific trusted domains in " + directive + ".",
				})
			}

			if strings.HasPrefix(val, "*.") && !strings.HasPrefix(val, "*.localhost") {
				domain := val[2:]
				if strings.HasPrefix(directive, "script") || directive == "default-src" {
					for _, risky := range riskyDomains {
						if domain == risky || strings.HasSuffix(domain, "."+risky) {
							*issues = append(*issues, Finding{
								Severity: "warning",
								Code:     "BROAD_WILDCARD",
								Message:  directive + " allows " + val + " — this large domain may host JSONP endpoints or user-uploadable content that can bypass CSP.",
								Fix:      "Narrow the wildcard to specific subdomains you actually use instead of " + val + ".",
							})
							break
						}
					}
				}
			}
		}
	}
}

func checkBypassPatterns(parsed CSPDirectiveMap, issues *[]Finding) {
	var scriptSources []string
	if v, ok := parsed["script-src"]; ok {
		scriptSources = append(scriptSources, v...)
	}
	if v, ok := parsed["script-src-elem"]; ok {
		scriptSources = append(scriptSources, v...)
	}
	if _, hasScript := parsed["script-src"]; !hasScript {
		if _, hasElem := parsed["script-src-elem"]; !hasElem {
			if v, ok := parsed["default-src"]; ok {
				scriptSources = append(scriptSources, v...)
			}
		}
	}

	type jsonpPattern struct {
		pattern *regexp.Regexp
		name    string
	}

	jsonpEndpoints := []jsonpPattern{
		{regexp.MustCompile(`accounts\.google\.com`), "Google Accounts (JSONP)"},
		{regexp.MustCompile(`maps\.googleapis\.com`), "Google Maps (JSONP)"},
		{regexp.MustCompile(`translate\.googleapis\.com`), "Google Translate (JSONP)"},
		{regexp.MustCompile(`cdnjs\.cloudflare\.com`), "cdnjs (hosts Angular, which can bypass CSP)"},
		{regexp.MustCompile(`ajax\.googleapis\.com`), "Google Hosted Libraries (hosts Angular)"},
		{regexp.MustCompile(`cdn\.jsdelivr\.net`), "jsDelivr (arbitrary npm packages)"},
		{regexp.MustCompile(`unpkg\.com`), "unpkg (arbitrary npm packages)"},
	}

	for _, src := range scriptSources {
		for _, jp := range jsonpEndpoints {
			if jp.pattern.MatchString(src) {
				*issues = append(*issues, Finding{
					Severity: "high",
					Code:     "KNOWN_BYPASS",
					Message:  "script-src allows " + src + " — " + jp.name + ". This can be used to bypass CSP.",
					Fix:      "Remove " + src + " from script-src or use subresource integrity (SRI) hashes. If you need this CDN, pin specific files with their hashes.",
				})
			}
		}
	}
}

// ── Grading ─────────────────────────────────────────────────────────

func gradeCSP(_ CSPDirectiveMap, issues []Finding) string {
	var criticals, highs, warnings int
	for _, iss := range issues {
		switch iss.Severity {
		case "critical":
			criticals++
		case "high":
			highs++
		case "warning":
			warnings++
		}
	}

	if criticals > 0 {
		return "F"
	}
	if highs > 1 {
		return "D"
	}
	if highs == 1 {
		return "C"
	}
	if warnings > 2 {
		return "C"
	}
	if warnings > 0 {
		return "B"
	}
	return "A"
}

// ── Helpers ─────────────────────────────────────────────────────────

var criticalDirectives = []string{"form-action", "frame-ancestors", "base-uri"}

func findMissingDirectives(parsed CSPDirectiveMap) []string {
	var missing []string
	for _, d := range criticalDirectives {
		if _, ok := parsed[d]; !ok {
			missing = append(missing, d)
		}
	}

	// object-src should be 'none' or at least present
	if _, hasObj := parsed["object-src"]; !hasObj {
		defaultSrc, hasDef := parsed["default-src"]
		isNone := false
		if hasDef {
			for _, v := range defaultSrc {
				if v == "'none'" {
					isNone = true
					break
				}
			}
		}
		if !isNone {
			missing = append(missing, "object-src")
		}
	}

	return missing
}

func directiveExplanation(directive string) string {
	explanations := map[string]string{
		"form-action":    "forms can submit to any URL, enabling phishing attacks",
		"frame-ancestors": "the page can be embedded in iframes on any site (clickjacking)",
		"base-uri":       "attackers can inject <base> tags to redirect relative URLs",
		"object-src":     "plugins like Flash/Java can load from any source",
	}
	if e, ok := explanations[directive]; ok {
		return e
	}
	return "the default-src fallback applies"
}

func directiveRecommendation(directive string) string {
	recs := map[string]string{
		"form-action":    "form-action 'self'",
		"frame-ancestors": "frame-ancestors 'none'",
		"base-uri":       "base-uri 'self'",
		"object-src":     "object-src 'none'",
	}
	if r, ok := recs[directive]; ok {
		return r
	}
	return directive + " 'self'"
}
