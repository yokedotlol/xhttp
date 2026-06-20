package main

import (
	"fmt"
	"regexp"
	"sort"
)

// CORSErrorDecodeResult holds the result of decoding a CORS error message.
type CORSErrorDecodeResult struct {
	Diagnosis    string            `json:"diagnosis"`
	LikelyCause  string            `json:"likely_cause"`
	FixSteps     []string          `json:"fix_steps"`
	HeadersNeeded map[string]string `json:"headers_needed"`
	Docs         map[string]string `json:"docs"`
}

type errorPattern struct {
	pattern      *regexp.Regexp
	diagnosis    string
	likelyCause  string
	fixSteps     []string
	headersNeeded map[string]string
}

var corsErrorPatterns = []errorPattern{
	{
		pattern:   regexp.MustCompile(`(?i)No 'Access-Control-Allow-Origin' header is present|has been blocked by CORS policy.*No.*Access-Control-Allow-Origin|CORS Missing Allow Origin`),
		diagnosis: "The server is not returning an Access-Control-Allow-Origin header.",
		likelyCause: "CORS middleware is missing or not configured to run on this route. If the error mentions a preflight request, the server may not be handling OPTIONS requests.",
		fixSteps: []string{
			"Ensure your server responds with Access-Control-Allow-Origin on all responses (including OPTIONS).",
			"Set Access-Control-Allow-Origin to your frontend's origin or * for public APIs.",
			"For OPTIONS requests, return 204 No Content with the CORS headers.",
		},
		headersNeeded: map[string]string{"Access-Control-Allow-Origin": "https://your-frontend.com"},
	},
	{
		pattern:   regexp.MustCompile(`(?i)cannot use wildcard.*when credentials|credentials flag.*wildcard|The value of.*Access-Control-Allow-Origin.*must not be the wildcard`),
		diagnosis: "The server returns Access-Control-Allow-Origin: * but the request includes credentials. Browsers block this combination.",
		likelyCause: "The request uses cookies or Authorization headers (credentials mode), but the server uses a wildcard origin. CORS requires a specific origin when credentials are involved.",
		fixSteps: []string{
			"Change Access-Control-Allow-Origin from * to the specific requesting origin.",
			"Add Access-Control-Allow-Credentials: true.",
			"Add Vary: Origin so caches serve the correct response per origin.",
		},
		headersNeeded: map[string]string{
			"Access-Control-Allow-Origin":      "https://your-frontend.com",
			"Access-Control-Allow-Credentials": "true",
			"Vary":                             "Origin",
		},
	},
	{
		pattern:   regexp.MustCompile(`(?i)preflight request.*doesn't pass|Response to preflight request`),
		diagnosis: "The preflight (OPTIONS) request did not receive the required CORS headers.",
		likelyCause: "Your server is not handling OPTIONS requests, or the CORS middleware isn't running on preflight requests. Some frameworks need explicit OPTIONS route handlers.",
		fixSteps: []string{
			"Add an OPTIONS handler for the affected route that returns 204 with CORS headers.",
			"Ensure CORS middleware runs before route handlers and authentication.",
			"Set Access-Control-Allow-Methods to include the method being used.",
			"Set Access-Control-Allow-Headers to include any custom headers.",
		},
		headersNeeded: map[string]string{
			"Access-Control-Allow-Origin":  "https://your-frontend.com",
			"Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
			"Access-Control-Allow-Headers": "Content-Type, Authorization",
		},
	},
	{
		pattern:   regexp.MustCompile(`(?i)Method.*not allowed|Access-Control-Allow-Methods`),
		diagnosis: "The requested HTTP method is not listed in Access-Control-Allow-Methods.",
		likelyCause: "The preflight response does not include the method you're trying to use (e.g., PUT, DELETE, PATCH).",
		fixSteps: []string{
			"Add the required method to Access-Control-Allow-Methods in your OPTIONS response.",
			"Common value: GET, POST, PUT, DELETE, PATCH, OPTIONS.",
		},
		headersNeeded: map[string]string{"Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS"},
	},
	{
		pattern:   regexp.MustCompile(`(?i)header.*not allowed|Request header field.*not allowed|Access-Control-Allow-Headers`),
		diagnosis: "A request header is not listed in Access-Control-Allow-Headers.",
		likelyCause: "The request includes a custom header (like Authorization or X-Custom-Header) that the server's preflight response does not allow.",
		fixSteps: []string{
			"Add the header name to Access-Control-Allow-Headers in your OPTIONS response.",
			"Include all custom headers your frontend sends.",
		},
		headersNeeded: map[string]string{"Access-Control-Allow-Headers": "Content-Type, Authorization"},
	},
	{
		pattern:   regexp.MustCompile(`(?i)redirect is not allowed.*preflight|CORS request.*redirect`),
		diagnosis: "The server is redirecting the preflight (OPTIONS) request. CORS does not allow redirects on preflight.",
		likelyCause: "A redirect rule (HTTP→HTTPS, www→non-www, or trailing slash) is being applied to the OPTIONS request.",
		fixSteps: []string{
			"Ensure OPTIONS requests are handled before any redirect middleware.",
			"Exclude OPTIONS from redirect rules.",
			"Make the initial request URL match the final URL (use HTTPS, correct hostname).",
		},
		headersNeeded: map[string]string{},
	},
	{
		pattern:   regexp.MustCompile(`(?i)origin.*is not allowed|not an allowed origin|not equal to the supplied origin`),
		diagnosis: "The requesting origin is not in the server's allowed origins list.",
		likelyCause: "The server has a specific origin allowlist that doesn't include your frontend's origin. Check for protocol (http vs https), port, and subdomain differences.",
		fixSteps: []string{
			"Add your frontend's exact origin to the server's CORS allowlist.",
			"Remember that origins include protocol + hostname + port (e.g., https://app.example.com).",
			"http://localhost:3000 and http://localhost:5173 are different origins.",
		},
		headersNeeded: map[string]string{"Access-Control-Allow-Origin": "https://your-frontend.com"},
	},
	{
		pattern:   regexp.MustCompile(`(?i)opaque.*response|no-cors`),
		diagnosis: "The response is opaque — fetched with mode: \"no-cors\", which strips all readable data.",
		likelyCause: "The fetch() call uses mode: \"no-cors\" (or a <script>/<img> tag made the request). The browser fetched the resource but JavaScript can't read it.",
		fixSteps: []string{
			"Change the fetch() call to mode: \"cors\" (the default).",
			"Configure the server to return proper CORS headers.",
			"If you don't control the server, use a server-side proxy instead of a browser fetch.",
		},
		headersNeeded: map[string]string{},
	},
	{
		pattern:   regexp.MustCompile(`(?i)Failed to fetch|NetworkError|net::ERR_FAILED|TypeError.*fetch`),
		diagnosis: "The request failed at the network level before CORS could be evaluated.",
		likelyCause: "This could be: the server is down, the URL is wrong, HTTPS certificate issues, or a firewall/ad blocker is blocking the request. Browsers report CORS-blocked requests as network errors for security reasons.",
		fixSteps: []string{
			"Verify the server URL is correct and the server is running.",
			"Check the browser DevTools Network tab for the actual HTTP status.",
			"If the server returns an error (4xx, 5xx) without CORS headers, browsers report it as a CORS error.",
			"Test with curl to isolate network vs CORS issues.",
		},
		headersNeeded: map[string]string{},
	},
}

// decodeCORSError decodes a CORS error message from a browser console.
func decodeCORSError(errorText string) CORSErrorDecodeResult {
	for _, p := range corsErrorPatterns {
		if p.pattern.MatchString(errorText) {
			headers := p.headersNeeded
			if headers == nil {
				headers = map[string]string{}
			}
			return CORSErrorDecodeResult{
				Diagnosis:     p.diagnosis,
				LikelyCause:   p.likelyCause,
				FixSteps:      p.fixSteps,
				HeadersNeeded: headers,
				Docs:          serverDocs,
			}
		}
	}

	// Generic fallback
	return CORSErrorDecodeResult{
		Diagnosis:   "Could not match this error to a known CORS pattern.",
		LikelyCause: "This might be a CORS-related error wrapped in a different format, or a non-CORS issue.",
		FixSteps: []string{
			"Check the browser DevTools Network tab for the actual request/response.",
			"Look for the OPTIONS preflight request — if it fails or is missing CORS headers, that's the problem.",
			"Test the same request with curl to see the raw response headers.",
			"Ensure the server returns Access-Control-Allow-Origin on all responses, including errors.",
		},
		HeadersNeeded: map[string]string{"Access-Control-Allow-Origin": "https://your-frontend.com"},
		Docs:          serverDocs,
	}
}

// renderCORSErrorResult renders a CORS error decode result to the terminal.
func renderCORSErrorResult(result CORSErrorDecodeResult) {
	fmt.Println()
	fmt.Printf("  %s\n\n", titleStyle.Render("CORS Error Decoded"))
	fmt.Printf("  %s %s\n\n", labelStyle.Render("Diagnosis:"), result.Diagnosis)
	fmt.Printf("  %s %s\n\n", labelStyle.Render("Likely cause:"), result.LikelyCause)

	if len(result.FixSteps) > 0 {
		fmt.Printf("  %s\n", labelStyle.Render("Fix:"))
		for i, s := range result.FixSteps {
			fmt.Printf("  %s%s\n", tree(i == len(result.FixSteps)-1), s)
		}
		fmt.Println()
	}

	if len(result.HeadersNeeded) > 0 {
		fmt.Printf("  %s\n", labelStyle.Render("Headers needed:"))
		keys := make([]string, 0, len(result.HeadersNeeded))
		for k := range result.HeadersNeeded {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i, k := range keys {
			fmt.Printf("  %s%s: %v\n", tree(i == len(keys)-1), accentStyle.Render(k), result.HeadersNeeded[k])
		}
		fmt.Println()
	}
}
