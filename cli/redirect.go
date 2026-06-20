package main

import (
	"fmt"
	"net/http"
	"net/url"
	"time"
)

const maxRedirectHops = 20

var summaryHeaders = []string{
	"server", "x-powered-by", "via", "alt-svc",
	"strict-transport-security", "x-frame-options", "x-content-type-options",
	"referrer-policy", "permissions-policy", "content-security-policy",
	"cross-origin-opener-policy", "cross-origin-embedder-policy",
	"cross-origin-resource-policy", "cache-control", "content-type",
	"cf-cache-status", "x-cache", "age", "vary",
}

// followRedirects follows a URL's redirect chain, recording per-hop details.
func followRedirects(startURL string) RedirectChain {
	chain := make([]RedirectHop, 0, 4)
	issues := make([]Finding, 0)
	seen := make(map[string]bool)
	current := startURL
	loopDetected := false
	mixedContent := false

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for i := 0; i < maxRedirectHops; i++ {
		if seen[current] {
			loopDetected = true
			issues = append(issues, Finding{
				Severity: "critical",
				Code:     "REDIRECT_LOOP",
				Message:  fmt.Sprintf("Redirect loop detected: %s was already visited", current),
				Fix:      "Check your server configuration for circular redirects. A common cause is conflicting redirect rules (e.g., www → non-www and non-www → www both active).",
			})
			break
		}
		seen[current] = true

		req, err := http.NewRequest("GET", current, nil)
		if err != nil {
			issues = append(issues, Finding{
				Severity: "critical",
				Code:     "FETCH_ERROR",
				Message:  fmt.Sprintf("Failed to build request for %s: %v", current, err),
				Fix:      "The URL may be malformed.",
			})
			break
		}
		req.Header.Set("User-Agent", fmt.Sprintf("xhttp-cli/%s", version))
		req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*")

		hopStart := time.Now()
		resp, err := client.Do(req)
		hopTime := float64(time.Since(hopStart).Milliseconds())

		if err != nil {
			issues = append(issues, Finding{
				Severity: "critical",
				Code:     "FETCH_ERROR",
				Message:  fmt.Sprintf("Failed to fetch %s: %v", current, err),
				Fix:      "The server may be down, blocking requests, or the domain may not resolve.",
			})
			break
		}
		resp.Body.Close()

		location := resp.Header.Get("Location")
		status := resp.StatusCode

		// Extract key headers for summary
		headersSummary := make(map[string]string)
		for _, key := range summaryHeaders {
			if val := resp.Header.Get(key); val != "" {
				headersSummary[key] = val
			}
		}

		hop := RedirectHop{
			URL:            current,
			Status:         status,
			Location:       location,
			TimingMs:       hopTime,
			HeadersSummary: headersSummary,
		}
		chain = append(chain, hop)

		// Check for mixed content (HTTPS → HTTP redirect)
		if location != "" {
			if len(current) >= 8 && current[:8] == "https://" && len(location) >= 7 && location[:7] == "http://" {
				mixedContent = true
				issues = append(issues, Finding{
					Severity: "critical",
					Code:     "MIXED_CONTENT_REDIRECT",
					Message:  fmt.Sprintf("HTTPS → HTTP downgrade: %s redirects to %s", current, location),
					Fix:      "Never redirect from HTTPS to HTTP. Update the redirect target to use HTTPS.",
					MDN:      "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content",
				})
			}
		}

		// Classify redirect type
		if status == 302 || status == 303 {
			issues = append(issues, Finding{
				Severity: "info",
				Code:     "TEMPORARY_REDIRECT",
				Message:  fmt.Sprintf("Hop %d uses %d (temporary). If this is a permanent move, use 301 or 308 for better caching and SEO.", i+1, status),
				Fix:      fmt.Sprintf("Change the %d response to 301 (permanent) or 308 (permanent, preserves method) if the redirect is permanent.", status),
			})
		}

		// Not a redirect — final destination
		if status < 300 || status >= 400 || location == "" {
			break
		}

		// Resolve relative Location
		parsed, err := url.Parse(location)
		if err != nil {
			issues = append(issues, Finding{
				Severity: "high",
				Code:     "INVALID_LOCATION",
				Message:  fmt.Sprintf("Invalid Location header at hop %d: %q", i+1, location),
				Fix:      "The Location header contains an invalid URL. Ensure it is a valid absolute or relative URL.",
			})
			break
		}
		base, _ := url.Parse(current)
		current = base.ResolveReference(parsed).String()
	}

	if len(chain) >= maxRedirectHops {
		issues = append(issues, Finding{
			Severity: "critical",
			Code:     "TOO_MANY_REDIRECTS",
			Message:  fmt.Sprintf("Redirect chain exceeded %d hops", maxRedirectHops),
			Fix:      "Reduce the number of redirects. Most browsers give up after 20 hops.",
		})
	}

	// Check for HTTP → HTTPS upgrade (informational)
	if len(chain) >= 2 {
		first := chain[0]
		if len(first.URL) >= 7 && first.URL[:7] == "http://" &&
			first.Status >= 300 && first.Status < 400 &&
			first.Location != "" && len(first.Location) >= 8 && first.Location[:8] == "https://" {
			issues = append(issues, Finding{
				Severity: "pass",
				Code:     "HTTP_TO_HTTPS",
				Message:  fmt.Sprintf("HTTP → HTTPS redirect in place (%d)", first.Status),
			})
		}
	}

	return RedirectChain{
		Hops:         len(chain),
		LoopDetected: loopDetected,
		MixedContent: mixedContent,
		Chain:        chain,
		Issues:       issues,
	}
}
