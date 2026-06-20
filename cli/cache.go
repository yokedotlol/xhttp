package main

import (
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// analyzeCacheBehavior analyzes cache behavior from response headers.
func analyzeCacheBehavior(headers http.Header) CacheResult {
	issues := make([]Finding, 0)

	// ── Cache-Control ─────────────────────────────────────────────────
	ccRaw := headers.Get("Cache-Control")
	parsed := parseCacheControl(ccRaw)
	effectiveTTL := computeTTL(parsed, headers)
	explanation := explainCacheControl(parsed, effectiveTTL)

	// ── Vary ──────────────────────────────────────────────────────────
	varyRaw := headers.Get("Vary")
	var vary []string
	if varyRaw != "" {
		for _, v := range strings.Split(varyRaw, ",") {
			v = strings.TrimSpace(v)
			if v != "" {
				vary = append(vary, v)
			}
		}
	}

	for _, v := range vary {
		if v == "*" {
			issues = append(issues, Finding{
				Severity: "warning",
				Code:     "VARY_STAR",
				Message:  "Vary: * makes the response uncacheable. Every request is treated as unique.",
				Fix:      "Replace Vary: * with the specific headers that affect the response (e.g., Vary: Accept-Encoding, Accept).",
				MDN:      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Vary",
			})
			break
		}
	}

	// ── CDN detection ─────────────────────────────────────────────────
	cdnStatus, cdnProvider := detectCDN(headers)

	// ── Issues ────────────────────────────────────────────────────────
	if ccRaw == "" {
		issues = append(issues, Finding{
			Severity: "info",
			Code:     "NO_CACHE_CONTROL",
			Message:  "No Cache-Control header. Browsers and CDNs will use heuristic caching based on Last-Modified.",
			Fix:      "Set an explicit Cache-Control header. For static assets: public, max-age=31536000, immutable. For HTML: no-cache or public, max-age=0, must-revalidate.",
			MDN:      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control",
		})
	}

	if parsed["no-store"] != nil && parsed["max-age"] != nil {
		issues = append(issues, Finding{
			Severity: "warning",
			Code:     "CONFLICTING_DIRECTIVES",
			Message:  "Cache-Control has both no-store and max-age. no-store takes precedence — the max-age is ignored.",
			Fix:      "Remove max-age if you intend no-store, or remove no-store if you want caching.",
		})
	}

	if parsed["public"] != nil && parsed["no-store"] != nil {
		issues = append(issues, Finding{
			Severity: "warning",
			Code:     "PUBLIC_NO_STORE",
			Message:  "Cache-Control has both public and no-store. These conflict — no-store wins.",
			Fix:      "Remove public if you intend no-store.",
		})
	}

	return CacheResult{
		CacheControl: ccRaw,
		Parsed:       parsed,
		EffectiveTTL: effectiveTTL,
		Vary:         vary,
		CDNStatus:    cdnStatus,
		CDNProvider:  cdnProvider,
		Issues:       issues,
		Explanation:  explanation,
	}
}

// ── Cache-Control parser ────────────────────────────────────────────

func parseCacheControl(raw string) map[string]interface{} {
	result := make(map[string]interface{})
	if raw == "" {
		return result
	}

	directives := strings.Split(raw, ",")
	for _, d := range directives {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		eqIdx := strings.Index(d, "=")
		if eqIdx == -1 {
			result[strings.ToLower(d)] = true
		} else {
			key := strings.ToLower(strings.TrimSpace(d[:eqIdx]))
			val := strings.TrimSpace(d[eqIdx+1:])
			val = strings.Trim(val, "\"")
			if num, err := strconv.Atoi(val); err == nil {
				result[key] = num
			} else {
				result[key] = val
			}
		}
	}

	return result
}

// ── TTL computation ─────────────────────────────────────────────────

func computeTTL(parsed map[string]interface{}, headers http.Header) *int {
	if parsed["no-store"] != nil {
		zero := 0
		return &zero
	}
	if parsed["no-cache"] != nil {
		zero := 0
		return &zero
	}

	// s-maxage takes precedence for shared caches
	if v, ok := parsed["s-maxage"]; ok {
		if num, ok := v.(int); ok {
			return &num
		}
	}
	if v, ok := parsed["max-age"]; ok {
		if num, ok := v.(int); ok {
			return &num
		}
	}

	// Fall back to Expires header
	expires := headers.Get("Expires")
	if expires != "" {
		expDate, err := time.Parse(time.RFC1123, expires)
		if err != nil {
			expDate, err = time.Parse(time.RFC1123Z, expires)
		}
		if err == nil {
			dateStr := headers.Get("Date")
			var base time.Time
			if dateStr != "" {
				base, err = time.Parse(time.RFC1123, dateStr)
				if err != nil {
					base = time.Now()
				}
			} else {
				base = time.Now()
			}
			ttl := int(math.Max(0, expDate.Sub(base).Seconds()))
			return &ttl
		}
	}

	return nil // Unknown — heuristic caching applies
}

// ── Human-readable explanation ──────────────────────────────────────

func explainCacheControl(parsed map[string]interface{}, ttl *int) string {
	var parts []string

	if parsed["no-store"] != nil {
		parts = append(parts, "Not cached anywhere — every request goes to the server.")
	} else if parsed["no-cache"] != nil {
		parts = append(parts, "Cached but always revalidated with the server before use.")
	} else if parsed["private"] != nil {
		parts = append(parts, "Cached by the browser only (not shared caches like CDNs).")
	} else if parsed["public"] != nil {
		parts = append(parts, "Cacheable by browsers and CDNs.")
	}

	if ttl != nil && *ttl > 0 {
		parts = append(parts, fmt.Sprintf("Fresh for %s.", formatDuration(*ttl)))
	}

	if parsed["must-revalidate"] != nil {
		parts = append(parts, "Must revalidate with the server once stale.")
	}

	if parsed["immutable"] != nil {
		parts = append(parts, "Marked immutable — browsers won't revalidate even on reload.")
	}

	if v, ok := parsed["stale-while-revalidate"]; ok {
		if num, ok := v.(int); ok {
			parts = append(parts, fmt.Sprintf("Can serve stale content for %s while revalidating in the background.", formatDuration(num)))
		}
	}

	if len(parts) == 0 {
		return "No explicit cache policy. Browsers will use heuristic caching."
	}

	return strings.Join(parts, " ")
}

func formatDuration(seconds int) string {
	if seconds >= 86400 {
		days := seconds / 86400
		if days == 1 {
			return "1 day"
		}
		return fmt.Sprintf("%d days", days)
	}
	if seconds >= 3600 {
		hours := seconds / 3600
		if hours == 1 {
			return "1 hour"
		}
		return fmt.Sprintf("%d hours", hours)
	}
	if seconds >= 60 {
		mins := seconds / 60
		if mins == 1 {
			return "1 minute"
		}
		return fmt.Sprintf("%d minutes", mins)
	}
	if seconds == 1 {
		return "1 second"
	}
	return fmt.Sprintf("%d seconds", seconds)
}

// ── CDN detection ───────────────────────────────────────────────────

func detectCDN(headers http.Header) (status string, provider string) {
	// Cloudflare
	if v := headers.Get("CF-Cache-Status"); v != "" {
		return v, "Cloudflare"
	}
	if headers.Get("CF-Ray") != "" {
		return "", "Cloudflare"
	}

	// AWS CloudFront
	xCache := headers.Get("X-Cache")
	if headers.Get("X-Amz-Cf-Id") != "" || headers.Get("X-Amz-Cf-Pop") != "" {
		return xCache, "CloudFront"
	}

	// Fastly
	if v := headers.Get("X-Served-By"); strings.Contains(v, "cache-") {
		return headers.Get("X-Cache"), "Fastly"
	}

	// Vercel
	if headers.Get("X-Vercel-Id") != "" || headers.Get("X-Vercel-Cache") != "" {
		return headers.Get("X-Vercel-Cache"), "Vercel"
	}

	// Netlify
	if headers.Get("X-NF-Request-ID") != "" || headers.Get("X-Netlify-Request-ID") != "" {
		return headers.Get("X-Cache"), "Netlify"
	}

	// Akamai
	if headers.Get("X-Akamai-Transformed") != "" {
		return xCache, "Akamai"
	}

	// Generic X-Cache header
	if xCache != "" {
		return xCache, ""
	}

	if age := headers.Get("Age"); age != "" {
		return fmt.Sprintf("Age: %ss", age), ""
	}

	return "", ""
}
