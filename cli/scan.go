package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

const scanVersion = "2.0.0"

// runLocalScan performs a full local scan of a domain.
func runLocalScan(domain string) (*ScanResult, error) {
	start := time.Now()
	targetURL := "https://" + domain

	// Run redirect chain, CORS, and TLS version in parallel
	var redirectResult RedirectChain
	var corsResult CORSResult
	var tlsVersion string

	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		redirectResult = followRedirects(targetURL)
	}()

	go func() {
		defer wg.Done()
		corsResult = analyzeCORS(targetURL)
	}()

	go func() {
		defer wg.Done()
		tlsVersion = getTLSVersion(domain)
	}()

	wg.Wait()

	// Get the final URL from redirect chain
	finalURL := targetURL
	if len(redirectResult.Chain) > 0 {
		lastHop := redirectResult.Chain[len(redirectResult.Chain)-1]
		if lastHop.Status >= 200 && lastHop.Status < 300 {
			finalURL = lastHop.URL
		} else if lastHop.Location != "" {
			finalURL = lastHop.Location
		}
	}

	// Fetch final URL's full response headers for analysis
	headersObj := fetchFinalHeaders(finalURL, redirectResult)

	// Run header-based analyses
	cspRaw := headersObj.Get("Content-Security-Policy")
	allHeadersMap := make(map[string]string)
	for key := range headersObj {
		allHeadersMap[strings.ToLower(key)] = headersObj.Get(key)
	}

	cspResult := evaluateCSPFromHeaders(cspRaw, allHeadersMap)
	secHeaders := analyzeSecurityHeaders(headersObj)
	cacheResult := analyzeCacheBehavior(headersObj)

	// Compute overall grade
	grade := computeOverallGrade(secHeaders.Grade, cspResult.Grade, corsResult, redirectResult)

	scanTime := int(time.Since(start).Milliseconds())

	result := &ScanResult{
		URL:             targetURL,
		ScannedAt:       time.Now().UTC().Format(time.RFC3339),
		Grade:           grade,
		CORS:            corsResult,
		CSP:             cspResult,
		SecurityHeaders: secHeaders,
		RedirectChain:   redirectResult,
		Cache:           cacheResult,
		TLS: TLSResult{
			Version: tlsVersion,
			Details: fmt.Sprintf("→ certs.lol/%s", domain),
		},
		Meta: Meta{
			Version:    scanVersion,
			ScanTimeMs: scanTime,
			CacheHit:   false,
			Links: MetaLinks{
				FullReport: fmt.Sprintf("https://yoke.lol/%s", domain),
				TLSDetails: fmt.Sprintf("https://certs.lol/%s", domain),
				DNSDetails: fmt.Sprintf("https://ns.lol/%s", domain),
			},
		},
	}

	return result, nil
}

// runLocalSubScan performs a single-aspect local scan (cors, headers, csp, chain, cache).
func runLocalSubScan(domain, aspect string) (interface{}, error) {
	targetURL := "https://" + domain

	switch aspect {
	case "cors":
		result := analyzeCORS(targetURL)
		return SubCORS{URL: targetURL, CORS: result, Meta: buildSubMeta(domain)}, nil

	case "headers":
		headers := fetchHeadersForDomain(targetURL)
		result := analyzeSecurityHeaders(headers)
		return SubHeaders{URL: targetURL, SecurityHeaders: result, Meta: buildSubMeta(domain)}, nil

	case "csp":
		headers := fetchHeadersForDomain(targetURL)
		cspRaw := headers.Get("Content-Security-Policy")
		allHeadersMap := make(map[string]string)
		for key := range headers {
			allHeadersMap[strings.ToLower(key)] = headers.Get(key)
		}
		result := evaluateCSPFromHeaders(cspRaw, allHeadersMap)
		return SubCSP{URL: targetURL, CSP: result, Meta: buildSubMeta(domain)}, nil

	case "chain":
		result := followRedirects(targetURL)
		return SubChain{URL: targetURL, RedirectChain: result, Meta: buildSubMeta(domain)}, nil

	case "cache":
		headers := fetchHeadersForDomain(targetURL)
		result := analyzeCacheBehavior(headers)
		return SubCache{URL: targetURL, Cache: result, Meta: buildSubMeta(domain)}, nil

	default:
		return nil, fmt.Errorf("unknown aspect: %s", aspect)
	}
}

// getTLSVersion probes a domain's TLS version by making an HTTPS HEAD request
// and reading the connection state. Uses net/http so it works through proxies.
func getTLSVersion(domain string) string {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Head("https://" + domain)
	if err != nil {
		return ""
	}
	resp.Body.Close()

	if resp.TLS == nil {
		return ""
	}

	switch resp.TLS.Version {
	case tls.VersionTLS13:
		return "TLSv1.3"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS10:
		return "TLSv1.0"
	default:
		return fmt.Sprintf("unknown (0x%04x)", resp.TLS.Version)
	}
}

// fetchFinalHeaders fetches the full response headers of the final URL.
// Falls back to the redirect chain's last hop headers_summary if the direct fetch fails.
func fetchFinalHeaders(finalURL string, chain RedirectChain) http.Header {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest("GET", finalURL, nil)
	if err == nil {
		req.Header.Set("User-Agent", fmt.Sprintf("xhttp-cli/%s", version))
		req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*")

		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			return resp.Header
		}
	}

	// Fallback: reconstruct headers from redirect chain summary
	headers := make(http.Header)
	if len(chain.Chain) > 0 {
		last := chain.Chain[len(chain.Chain)-1]
		for key, val := range last.HeadersSummary {
			headers.Set(key, val)
		}
	}
	return headers
}

// fetchHeadersForDomain fetches response headers for a domain (following redirects to final destination).
func fetchHeadersForDomain(targetURL string) http.Header {
	client := &http.Client{
		Timeout: 15 * time.Second,
		// Allow redirects — we want the final destination's headers
	}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return make(http.Header)
	}
	req.Header.Set("User-Agent", fmt.Sprintf("xhttp-cli/%s", version))
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*")

	resp, err := client.Do(req)
	if err != nil {
		return make(http.Header)
	}
	resp.Body.Close()
	return resp.Header
}

// computeOverallGrade computes a weighted overall grade.
func computeOverallGrade(headersGrade, cspGrade string, cors CORSResult, redirects RedirectChain) string {
	gradeToNum := map[string]float64{
		"A+": 97, "A": 93, "A-": 90,
		"B+": 87, "B": 83, "B-": 80,
		"C+": 77, "C": 73, "C-": 70,
		"D": 60, "F": 40,
	}

	getGrade := func(g string) float64 {
		if v, ok := gradeToNum[g]; ok {
			return v
		}
		return 50
	}

	var score float64

	// Headers: 40%, CSP: 30%, CORS: 15%, Redirects: 15%
	score += getGrade(headersGrade) * 0.4
	score += getGrade(cspGrade) * 0.3

	// CORS score
	corsCritical := 0
	corsHigh := 0
	for _, iss := range cors.Issues {
		if iss.Severity == "critical" {
			corsCritical++
		}
		if iss.Severity == "high" {
			corsHigh++
		}
	}
	corsScore := 100 - corsCritical*30 - corsHigh*15
	if corsScore < 40 {
		corsScore = 40
	}
	score += float64(corsScore) * 0.15

	// Redirect score
	redirectScore := 100
	if redirects.MixedContent {
		redirectScore -= 40
	}
	if redirects.LoopDetected {
		redirectScore -= 50
	}
	excess := redirects.Hops - 2
	if excess > 0 {
		redirectScore -= excess * 5
	}
	if redirectScore < 40 {
		redirectScore = 40
	}
	score += float64(redirectScore) * 0.15

	rounded := int(score + 0.5)
	return numToGrade(rounded)
}

func numToGrade(n int) string {
	if n >= 95 {
		return "A+"
	}
	if n >= 90 {
		return "A"
	}
	if n >= 85 {
		return "B+"
	}
	if n >= 80 {
		return "B"
	}
	if n >= 75 {
		return "B-"
	}
	if n >= 70 {
		return "C+"
	}
	if n >= 65 {
		return "C"
	}
	if n >= 55 {
		return "D"
	}
	return "F"
}

func buildSubMeta(domain string) Meta {
	return Meta{
		Version:    scanVersion,
		ScanTimeMs: 0,
		CacheHit:   false,
		Links: MetaLinks{
			FullReport: fmt.Sprintf("https://yoke.lol/%s", domain),
			TLSDetails: fmt.Sprintf("https://certs.lol/%s", domain),
			DNSDetails: fmt.Sprintf("https://ns.lol/%s", domain),
		},
	}
}
