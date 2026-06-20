package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

const defaultTestOrigin = "https://example.com"

// analyzeCORS checks CORS behavior of a URL by sending preflight + actual requests.
func analyzeCORS(targetURL string) CORSResult {
	origin := defaultTestOrigin
	issues := make([]Finding, 0)

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Send OPTIONS preflight
	var preflightStatus int
	var preflightHeaders http.Header
	preflightReq, err := http.NewRequest("OPTIONS", targetURL, nil)
	if err == nil {
		preflightReq.Header.Set("User-Agent", fmt.Sprintf("xhttp-cli/%s", version))
		preflightReq.Header.Set("Origin", origin)
		preflightReq.Header.Set("Access-Control-Request-Method", "GET")
		preflightReq.Header.Set("Access-Control-Request-Headers", "Content-Type")

		resp, err := client.Do(preflightReq)
		if err == nil {
			preflightStatus = resp.StatusCode
			preflightHeaders = resp.Header
			resp.Body.Close()
		}
	}

	// Send actual GET with Origin header
	actualReq, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return CORSResult{
			Enabled: false,
			Issues: []Finding{{
				Severity: "info",
				Code:     "CORS_FETCH_FAILED",
				Message:  "Could not build request to check CORS headers.",
			}},
		}
	}
	actualReq.Header.Set("User-Agent", fmt.Sprintf("xhttp-cli/%s", version))
	actualReq.Header.Set("Origin", origin)
	actualReq.Header.Set("Accept", "*/*")

	actualResp, err := client.Do(actualReq)
	if err != nil {
		return CORSResult{
			Enabled:         false,
			PreflightStatus: preflightStatus,
			Issues: []Finding{{
				Severity: "info",
				Code:     "CORS_FETCH_FAILED",
				Message:  "Could not fetch the target URL to check CORS headers.",
			}},
		}
	}
	actualResp.Body.Close()

	// Use preflight headers if available, fall back to actual response
	corsHeaders := actualResp.Header
	if preflightHeaders != nil {
		corsHeaders = preflightHeaders
	}

	acao := corsHeaders.Get("Access-Control-Allow-Origin")
	acac := corsHeaders.Get("Access-Control-Allow-Credentials")
	acam := corsHeaders.Get("Access-Control-Allow-Methods")
	acah := corsHeaders.Get("Access-Control-Allow-Headers")
	aceh := corsHeaders.Get("Access-Control-Expose-Headers")
	acma := corsHeaders.Get("Access-Control-Max-Age")
	vary := corsHeaders.Get("Vary")

	enabled := acao != ""
	allowCredentials := strings.EqualFold(acac, "true")
	allowMethods := splitTrimFilter(acam, ",")
	allowHeaders := splitTrimFilter(acah, ",")
	exposeHeaders := splitTrimFilter(aceh, ",")
	var maxAge *int
	if acma != "" {
		v := 0
		fmt.Sscanf(acma, "%d", &v)
		maxAge = &v
	}
	varyOrigin := strings.Contains(strings.ToLower(vary), "origin")

	var allowOrigin *string
	if acao != "" {
		allowOrigin = &acao
	}

	if !enabled {
		issues = append(issues, Finding{
			Severity: "info",
			Code:     "NO_CORS_HEADERS",
			Message:  "No CORS headers present. Cross-origin requests from browsers will be blocked.",
			Fix:      "If you intend to allow cross-origin access, set the Access-Control-Allow-Origin header.",
			MDN:      "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
		})
	}

	// Wildcard origin
	if acao == "*" {
		issues = append(issues, Finding{
			Severity: "warning",
			Code:     "WILDCARD_ORIGIN",
			Message:  "Wildcard origin (*) allows any site to read responses.",
			Fix:      "If only specific origins need access, set Access-Control-Allow-Origin to your frontend's origin instead of *.",
			MDN:      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin",
		})
	}

	// Wildcard + credentials
	if acao == "*" && allowCredentials {
		issues = append(issues, Finding{
			Severity: "critical",
			Code:     "WILDCARD_WITH_CREDENTIALS",
			Message:  "Wildcard origin (*) combined with Access-Control-Allow-Credentials: true. Browsers will block this.",
			Fix:      "When using credentials, the server must echo the specific requesting origin, not *. Set Access-Control-Allow-Origin to the exact origin and add Vary: Origin.",
			MDN:      "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS/Errors/CORSNotSupportingCredentials",
		})
	}

	// Origin reflection (echoing the request origin — potential vulnerability)
	if acao == origin && acao != "*" && enabled {
		evilReq, err := http.NewRequest("GET", targetURL, nil)
		if err == nil {
			evilReq.Header.Set("User-Agent", fmt.Sprintf("xhttp-cli/%s", version))
			evilReq.Header.Set("Origin", "https://evil.example.com")
			evilReq.Header.Set("Accept", "*/*")

			evilResp, err := client.Do(evilReq)
			if err == nil {
				reflected := evilResp.Header.Get("Access-Control-Allow-Origin")
				evilResp.Body.Close()
				if reflected == "https://evil.example.com" {
					issues = append(issues, Finding{
						Severity: "critical",
						Code:     "ORIGIN_REFLECTION",
						Message:  "Server reflects any Origin header as Access-Control-Allow-Origin. This is equivalent to a wildcard but bypasses the credentials restriction.",
						Fix:      "Maintain an allowlist of permitted origins and only echo origins that match. Never blindly reflect the Origin header.",
						MDN:      "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
					})
				}
			}
		}
	}

	// Missing Vary: Origin when ACAO is not wildcard
	if enabled && acao != "*" && !varyOrigin {
		issues = append(issues, Finding{
			Severity: "warning",
			Code:     "MISSING_VARY_ORIGIN",
			Message:  "Access-Control-Allow-Origin is origin-specific but Vary: Origin is missing. Caches may serve the wrong origin to different requesters.",
			Fix:      "Add Vary: Origin to responses that include Access-Control-Allow-Origin with a specific origin.",
			MDN:      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Vary",
		})
	}

	// Preflight returning non-2xx
	if preflightStatus > 0 && (preflightStatus < 200 || preflightStatus >= 300) {
		issues = append(issues, Finding{
			Severity: "high",
			Code:     "PREFLIGHT_FAILED",
			Message:  fmt.Sprintf("Preflight (OPTIONS) returned %d. Browsers require a 2xx response.", preflightStatus),
			Fix:      "Ensure your server responds to OPTIONS requests with a 200 or 204 status and the appropriate CORS headers.",
			MDN:      "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#preflighted_requests",
		})
	}

	// No max-age on preflight cache
	if enabled && maxAge == nil && preflightStatus > 0 {
		issues = append(issues, Finding{
			Severity: "info",
			Code:     "NO_PREFLIGHT_CACHE",
			Message:  "No Access-Control-Max-Age set. Browsers will re-send preflight OPTIONS requests frequently.",
			Fix:      "Set Access-Control-Max-Age to cache preflight results. 86400 (24 hours) is common.",
		})
	}

	return CORSResult{
		Enabled:          enabled,
		AllowOrigin:      allowOrigin,
		AllowCredentials: allowCredentials,
		AllowMethods:     allowMethods,
		AllowHeaders:     allowHeaders,
		ExposeHeaders:    exposeHeaders,
		MaxAge:           maxAge,
		PreflightStatus:  preflightStatus,
		VaryOrigin:       varyOrigin,
		Issues:           issues,
	}
}

// CORSSimResult holds the result of a CORS simulation.
type CORSSimResult struct {
	Allowed   bool              `json:"allowed"`
	Reason    string            `json:"reason"`
	Preflight map[string]interface{} `json:"preflight"`
	Fix       *CORSSimFix       `json:"fix,omitempty"`
}

// CORSSimFix holds fix suggestions for a CORS simulation.
type CORSSimFix struct {
	Explanation string            `json:"explanation"`
	Headers     map[string]string `json:"headers"`
	Docs        map[string]string `json:"docs"`
}

var serverDocs = map[string]string{
	"nginx":              "https://nginx.org/en/docs/http/ngx_http_headers_module.html",
	"apache":             "https://httpd.apache.org/docs/current/mod/mod_headers.html",
	"express":            "https://expressjs.com/en/resources/middleware/cors.html",
	"cloudflare_workers": "https://developers.cloudflare.com/workers/examples/cors-header-proxy/",
	"caddy":              "https://caddyserver.com/docs/caddyfile/directives/header",
}

// simulateCORS performs a full CORS simulation with custom parameters.
func simulateCORS(req CORSSimRequest) CORSSimResult {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	method := req.Method
	if method == "" {
		method = "GET"
	}
	isSimple := isSimpleRequest(method, req.Headers)

	preflightSent := map[string]string{
		"Origin":                        req.Origin,
		"Access-Control-Request-Method": method,
	}
	preflightReceived := map[string]string{}
	var preflightStatus int

	// Send preflight if needed
	if !isSimple {
		preflightHTTP, err := http.NewRequest("OPTIONS", req.Target, nil)
		if err == nil {
			preflightHTTP.Header.Set("User-Agent", fmt.Sprintf("xhttp-cli/%s", version))
			preflightHTTP.Header.Set("Origin", req.Origin)
			preflightHTTP.Header.Set("Access-Control-Request-Method", method)
			if len(req.Headers) > 0 {
				preflightHTTP.Header.Set("Access-Control-Request-Headers", strings.Join(req.Headers, ", "))
				preflightSent["Access-Control-Request-Headers"] = strings.Join(req.Headers, ", ")
			}

			resp, err := client.Do(preflightHTTP)
			if err != nil {
				return CORSSimResult{
					Allowed: false,
					Reason:  fmt.Sprintf("Preflight request failed: %v", err),
					Fix: &CORSSimFix{
						Explanation: "The server did not respond to the OPTIONS preflight request.",
						Headers:     buildFixHeaders(req.Origin, method, req.Headers, req.Credentials),
						Docs:        serverDocs,
					},
				}
			}
			resp.Body.Close()
			preflightStatus = resp.StatusCode
			for _, key := range []string{
				"access-control-allow-origin", "access-control-allow-methods",
				"access-control-allow-headers", "access-control-allow-credentials",
				"access-control-max-age", "vary",
			} {
				if val := resp.Header.Get(key); val != "" {
					preflightReceived[key] = val
				}
			}
		}
	}

	// Send actual request with Origin
	actualSent := map[string]string{
		"Origin": req.Origin,
		"Accept": "*/*",
	}
	actualReceived := map[string]string{}

	httpMethod := method
	if httpMethod == "HEAD" {
		httpMethod = "HEAD"
	} else {
		httpMethod = "GET"
	}
	actualHTTP, err := http.NewRequest(httpMethod, req.Target, nil)
	if err == nil {
		actualHTTP.Header.Set("User-Agent", fmt.Sprintf("xhttp-cli/%s", version))
		actualHTTP.Header.Set("Origin", req.Origin)
		actualHTTP.Header.Set("Accept", "*/*")

		resp, err := client.Do(actualHTTP)
		if err == nil {
			resp.Body.Close()
			for _, key := range []string{
				"access-control-allow-origin", "access-control-allow-credentials",
				"access-control-expose-headers", "vary",
			} {
				if val := resp.Header.Get(key); val != "" {
					actualReceived[key] = val
				}
			}
		}
	}

	// Determine if allowed
	corsHeaders := actualReceived
	if !isSimple {
		corsHeaders = preflightReceived
	}

	acao := corsHeaders["access-control-allow-origin"]
	acac := corsHeaders["access-control-allow-credentials"]

	var reasons []string

	if acao == "" {
		reasons = append(reasons, "No Access-Control-Allow-Origin header in the response.")
	} else if acao != "*" && acao != req.Origin {
		reasons = append(reasons, fmt.Sprintf("Access-Control-Allow-Origin is %q but your origin is %q.", acao, req.Origin))
	}

	if req.Credentials && acao == "*" {
		reasons = append(reasons, "Credentials requested but Access-Control-Allow-Origin is wildcard (*). Browsers block this combination.")
	}

	if req.Credentials && !strings.EqualFold(acac, "true") {
		reasons = append(reasons, "Credentials requested but Access-Control-Allow-Credentials is not \"true\".")
	}

	if !isSimple {
		if preflightStatus < 200 || preflightStatus >= 300 {
			reasons = append(reasons, fmt.Sprintf("Preflight (OPTIONS) returned %d. Browsers require a 2xx response.", preflightStatus))
		}

		allowedMethods := splitTrimFilter(preflightReceived["access-control-allow-methods"], ",")
		upperMethod := strings.ToUpper(method)
		if upperMethod != "GET" && upperMethod != "HEAD" && upperMethod != "POST" {
			found := false
			for _, m := range allowedMethods {
				if strings.ToUpper(m) == upperMethod {
					found = true
					break
				}
			}
			if !found {
				reasons = append(reasons, fmt.Sprintf("Method %q is not in Access-Control-Allow-Methods (%s).", method, strings.Join(allowedMethods, ", ")))
			}
		}

		if len(req.Headers) > 0 {
			allowedHeaders := splitTrimFilter(preflightReceived["access-control-allow-headers"], ",")
			allowedLower := make(map[string]bool)
			for _, h := range allowedHeaders {
				allowedLower[strings.ToLower(h)] = true
			}
			var blocked []string
			for _, h := range req.Headers {
				if !allowedLower[strings.ToLower(h)] && !isSafelistedHeader(h) {
					blocked = append(blocked, h)
				}
			}
			if len(blocked) > 0 {
				reasons = append(reasons, fmt.Sprintf("Header(s) %s not in Access-Control-Allow-Headers.", strings.Join(blocked, ", ")))
			}
		}
	}

	allowed := len(reasons) == 0

	sent := preflightSent
	received := preflightReceived
	if isSimple {
		sent = actualSent
		received = actualReceived
	}

	result := CORSSimResult{
		Allowed: allowed,
		Preflight: map[string]interface{}{
			"sent":     sent,
			"received": received,
		},
	}

	if allowed {
		result.Reason = "Request is allowed by the server's CORS policy."
	} else {
		combined := strings.Join(reasons, " ")
		result.Reason = combined
		result.Fix = &CORSSimFix{
			Explanation: combined,
			Headers:     buildFixHeaders(req.Origin, method, req.Headers, req.Credentials),
			Docs:        serverDocs,
		}
	}

	return result
}

// isSimpleRequest checks if a request qualifies as a CORS "simple request".
func isSimpleRequest(method string, headers []string) bool {
	simpleMethods := map[string]bool{"GET": true, "HEAD": true, "POST": true}
	if !simpleMethods[strings.ToUpper(method)] {
		return false
	}
	for _, h := range headers {
		if !isSafelistedHeader(h) {
			return false
		}
	}
	return true
}

// isSafelistedHeader checks if a header is CORS-safelisted.
func isSafelistedHeader(header string) bool {
	safelisted := map[string]bool{
		"accept": true, "accept-language": true,
		"content-language": true, "content-type": true,
	}
	return safelisted[strings.ToLower(header)]
}

// buildFixHeaders builds the correct CORS headers for a fix suggestion.
func buildFixHeaders(origin, method string, headers []string, credentials bool) map[string]string {
	fix := make(map[string]string)

	if credentials {
		fix["Access-Control-Allow-Origin"] = origin
		fix["Access-Control-Allow-Credentials"] = "true"
		fix["Vary"] = "Origin"
	} else {
		fix["Access-Control-Allow-Origin"] = origin
	}

	if !isSimpleRequest(method, headers) {
		methods := map[string]bool{"GET": true, "HEAD": true, "POST": true}
		methods[strings.ToUpper(method)] = true
		var ml []string
		for m := range methods {
			ml = append(ml, m)
		}
		fix["Access-Control-Allow-Methods"] = strings.Join(ml, ", ")

		if len(headers) > 0 {
			fix["Access-Control-Allow-Headers"] = strings.Join(headers, ", ")
		}

		fix["Access-Control-Max-Age"] = "86400"
	}

	return fix
}

// splitTrimFilter splits a string by sep, trims whitespace, and removes empty strings.
func splitTrimFilter(s, sep string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, sep)
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}
