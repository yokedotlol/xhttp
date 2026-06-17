package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
)

var (
	version = "dev"
	commit  = "none"
)

const apiBase = "https://preflight.lol"

var isTTY = isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd())

// ─── Styles ─────────────────────────────────────────────────────────

var (
	amber     = lipgloss.Color("#d4a24c")
	green     = lipgloss.Color("#3fb950")
	red       = lipgloss.Color("#f85149")
	blue      = lipgloss.Color("#6ea8fe")
	yellow    = lipgloss.Color("#e5a820")
	dim       = lipgloss.Color("#55556a")
	muted     = lipgloss.Color("#7a7a8e")
	textColor = lipgloss.Color("#e0e0ea")

	titleStyle = lipgloss.NewStyle().Foreground(amber).Bold(true)
	gradeA     = lipgloss.NewStyle().Foreground(green).Bold(true)
	gradeB     = lipgloss.NewStyle().Foreground(blue).Bold(true)
	gradeC     = lipgloss.NewStyle().Foreground(yellow).Bold(true)
	gradeD     = lipgloss.NewStyle().Foreground(amber).Bold(true)
	gradeF     = lipgloss.NewStyle().Foreground(red).Bold(true)
	okStyle    = lipgloss.NewStyle().Foreground(green)
	warnStyle  = lipgloss.NewStyle().Foreground(yellow)
	errStyle   = lipgloss.NewStyle().Foreground(red)
	infoStyle  = lipgloss.NewStyle().Foreground(blue)
	dimStyle   = lipgloss.NewStyle().Foreground(dim)
	mutedStyle = lipgloss.NewStyle().Foreground(muted)
	labelStyle = lipgloss.NewStyle().Foreground(textColor).Bold(true)
	accentStyle = lipgloss.NewStyle().Foreground(amber)
)

// ─── Types ──────────────────────────────────────────────────────────

type Finding struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Message  string `json:"message"`
	Fix      string `json:"fix"`
	MDN      string `json:"mdn"`
}

type HeaderCheck struct {
	Present         bool      `json:"present"`
	Value           *string   `json:"value"`
	Issues          []Finding `json:"issues"`
	Recommendation  string    `json:"recommendation,omitempty"`
	PreloadEligible *bool     `json:"preload_eligible,omitempty"`
}

type SecurityHeaders struct {
	Grade     string                 `json:"grade"`
	Headers   map[string]HeaderCheck `json:"headers"`
	Conflicts []Finding              `json:"conflicts"`
	Score     int                    `json:"score"`
	MaxScore  int                    `json:"max_score"`
}

type CSPResult struct {
	Present           bool                `json:"present"`
	Mode              string              `json:"mode"`
	Raw               string              `json:"raw"`
	Parsed            map[string][]string `json:"parsed"`
	Grade             string              `json:"grade"`
	Issues            []Finding           `json:"issues"`
	MissingDirectives []string            `json:"missing_directives"`
}

type CORSResult struct {
	Enabled          bool      `json:"enabled"`
	AllowOrigin      *string   `json:"allow_origin"`
	AllowCredentials bool      `json:"allow_credentials"`
	AllowMethods     []string  `json:"allow_methods"`
	AllowHeaders     []string  `json:"allow_headers"`
	ExposeHeaders    []string  `json:"expose_headers"`
	MaxAge           *int      `json:"max_age"`
	PreflightStatus  int       `json:"preflight_status"`
	VaryOrigin       bool      `json:"vary_origin"`
	Issues           []Finding `json:"issues"`
}

type RedirectHop struct {
	URL            string            `json:"url"`
	Status         int               `json:"status"`
	Location       string            `json:"location,omitempty"`
	TimingMs       float64           `json:"timing_ms"`
	HSTSUpgrade    bool              `json:"hsts_upgrade"`
	HeadersSummary map[string]string `json:"headers_summary"`
}

type RedirectChain struct {
	Hops         int           `json:"hops"`
	LoopDetected bool          `json:"loop_detected"`
	MixedContent bool          `json:"mixed_content"`
	Chain        []RedirectHop `json:"chain"`
	Issues       []Finding     `json:"issues"`
}

type CacheResult struct {
	CacheControl string            `json:"cache_control"`
	Parsed       map[string]interface{} `json:"parsed"`
	EffectiveTTL *int              `json:"effective_ttl"`
	Vary         []string          `json:"vary"`
	CDNStatus    string            `json:"cdn_status"`
	CDNProvider  string            `json:"cdn_provider"`
	Issues       []Finding         `json:"issues"`
}

type TLSResult struct {
	Version string `json:"version"`
	Details string `json:"details"`
}

type Meta struct {
	Version    string `json:"version"`
	ScanTimeMs int    `json:"scan_time_ms"`
	CacheHit   bool   `json:"cache_hit"`
	Links      struct {
		FullReport string `json:"full_report"`
		TLSDetails string `json:"tls_details"`
		DNSDetails string `json:"dns_details"`
	} `json:"links"`
}

type ScanResult struct {
	URL             string          `json:"url"`
	ScannedAt       string          `json:"scanned_at"`
	Grade           string          `json:"grade"`
	CORS            CORSResult      `json:"cors"`
	CSP             *CSPResult      `json:"csp"`
	SecurityHeaders SecurityHeaders `json:"security_headers"`
	RedirectChain   RedirectChain   `json:"redirect_chain"`
	Cache           CacheResult     `json:"cache"`
	TLS             TLSResult       `json:"tls"`
	Meta            Meta            `json:"_meta"`
}

type CORSSimRequest struct {
	Target      string   `json:"target"`
	Origin      string   `json:"origin"`
	Method      string   `json:"method,omitempty"`
	Headers     []string `json:"headers,omitempty"`
	Credentials bool     `json:"credentials,omitempty"`
}

type CORSErrorRequest struct {
	Error string `json:"error"`
}

// ─── Sub-route wrappers ─────────────────────────────────────────────

type SubCORS struct {
	URL  string     `json:"url"`
	CORS CORSResult `json:"cors"`
	Meta Meta       `json:"_meta"`
}

type SubHeaders struct {
	URL             string          `json:"url"`
	SecurityHeaders SecurityHeaders `json:"security_headers"`
	Meta            Meta            `json:"_meta"`
}

type SubCSP struct {
	URL string     `json:"url"`
	CSP *CSPResult `json:"csp"`
	Meta Meta      `json:"_meta"`
}

type SubChain struct {
	URL           string        `json:"url"`
	RedirectChain RedirectChain `json:"redirect_chain"`
	Meta          Meta          `json:"_meta"`
}

type SubCache struct {
	URL   string      `json:"url"`
	Cache CacheResult `json:"cache"`
	Meta  Meta        `json:"_meta"`
}

// ─── Helpers ────────────────────────────────────────────────────────

func gradeStyle(g string) lipgloss.Style {
	if len(g) == 0 {
		return dimStyle
	}
	switch g[0] {
	case 'A':
		return gradeA
	case 'B':
		return gradeB
	case 'C':
		return gradeC
	case 'D':
		return gradeD
	default:
		return gradeF
	}
}

func severityIcon(s string) string {
	switch s {
	case "critical", "high":
		return errStyle.Render("✗")
	case "warning":
		return warnStyle.Render("⚠")
	case "info":
		return infoStyle.Render("ℹ")
	default:
		return dimStyle.Render("·")
	}
}

func check(ok bool) string {
	if ok {
		return okStyle.Render("✓")
	}
	return errStyle.Render("✗")
}

func tree(last bool) string {
	if last {
		return dimStyle.Render("└─ ")
	}
	return dimStyle.Render("├─ ")
}

func fetchJSON(url string, target interface{}) error {
	client := &http.Client{Timeout: 90 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", fmt.Sprintf("preflight-cli/%s", version))

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 429 {
		return fmt.Errorf("rate limited — try again in a minute")
	}
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	return json.NewDecoder(resp.Body).Decode(target)
}

func postJSON(url string, body interface{}, target interface{}) error {
	client := &http.Client{Timeout: 90 * time.Second}
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, strings.NewReader(string(data)))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", fmt.Sprintf("preflight-cli/%s", version))

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 429 {
		return fmt.Errorf("rate limited — try again in a minute")
	}
	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	return json.NewDecoder(resp.Body).Decode(target)
}

// ─── Renderers ──────────────────────────────────────────────────────

func renderBanner(domain string) {
	fmt.Println()
	fmt.Printf("  %s — %s\n", titleStyle.Render("preflight.lol"), labelStyle.Render(domain))
	fmt.Printf("  %s\n\n", dimStyle.Render(strings.Repeat("━", 40)))
}

func renderGrade(result *ScanResult) {
	g := result.Grade
	fmt.Printf("  Grade: %s", gradeStyle(g).Render(g))
	if result.Meta.CacheHit {
		fmt.Printf("  %s", dimStyle.Render("(cached)"))
	}
	fmt.Printf("  %s\n\n", dimStyle.Render(fmt.Sprintf("[%dms]", result.Meta.ScanTimeMs)))
}

func renderSecurityHeaders(h SecurityHeaders) {
	issueCount := 0
	for _, hc := range h.Headers {
		issueCount += len(hc.Issues)
	}

	status := okStyle.Render(fmt.Sprintf("✓ %d/%d", h.Score, h.MaxScore))
	if h.Score < 50 {
		status = errStyle.Render(fmt.Sprintf("✗ %d/%d", h.Score, h.MaxScore))
	} else if h.Score < 80 {
		status = warnStyle.Render(fmt.Sprintf("⚠ %d/%d", h.Score, h.MaxScore))
	}

	fmt.Printf("  %s  %s  %s\n", labelStyle.Render("Security Headers"), status, dimStyle.Render("Grade: "+h.Grade))

	// Sort header names for consistent output
	names := make([]string, 0, len(h.Headers))
	for name := range h.Headers {
		names = append(names, name)
	}
	sort.Strings(names)

	for i, name := range names {
		hc := h.Headers[name]
		last := i == len(names)-1 && len(h.Conflicts) == 0
		prefix := tree(last)

		if hc.Present {
			val := ""
			if hc.Value != nil {
				val = *hc.Value
				if len(val) > 60 {
					val = val[:57] + "..."
				}
			}
			fmt.Printf("  %s%s %s: %s\n", prefix, check(len(hc.Issues) == 0), mutedStyle.Render(name), val)
		} else {
			fmt.Printf("  %s%s %s: %s\n", prefix, check(false), mutedStyle.Render(name), dimStyle.Render("missing"))
		}
	}

	for i, c := range h.Conflicts {
		last := i == len(h.Conflicts)-1
		fmt.Printf("  %s%s %s\n", tree(last), warnStyle.Render("⚠"), c.Message)
	}
	fmt.Println()
}

func renderCSP(csp *CSPResult) {
	if csp == nil {
		fmt.Printf("  %s  %s\n", labelStyle.Render("CSP"), errStyle.Render("✗ not present"))
		fmt.Printf("  %s%s\n\n", tree(true), dimStyle.Render("No Content-Security-Policy header found"))
		return
	}

	issueLabel := okStyle.Render("✓ no issues")
	if len(csp.Issues) > 0 {
		sev := "warning"
		for _, iss := range csp.Issues {
			if iss.Severity == "critical" || iss.Severity == "high" {
				sev = "critical"
				break
			}
		}
		if sev == "critical" {
			issueLabel = errStyle.Render(fmt.Sprintf("✗ %d issues", len(csp.Issues)))
		} else {
			issueLabel = warnStyle.Render(fmt.Sprintf("⚠ %d issues", len(csp.Issues)))
		}
	}

	fmt.Printf("  %s  %s  %s\n", labelStyle.Render("CSP"), issueLabel, dimStyle.Render("Grade: "+csp.Grade))
	fmt.Printf("  %sMode: %s\n", tree(false), csp.Mode)

	for i, iss := range csp.Issues {
		last := i == len(csp.Issues)-1 && len(csp.MissingDirectives) == 0
		fmt.Printf("  %s%s %s\n", tree(last), severityIcon(iss.Severity), iss.Message)
	}

	if len(csp.MissingDirectives) > 0 {
		fmt.Printf("  %sMissing: %s\n", tree(true), warnStyle.Render(strings.Join(csp.MissingDirectives, ", ")))
	}
	fmt.Println()
}

func renderCORS(cors CORSResult) {
	if !cors.Enabled {
		issueCount := len(cors.Issues)
		if issueCount == 0 {
			fmt.Printf("  %s  %s\n", labelStyle.Render("CORS"), dimStyle.Render("not enabled"))
		} else {
			fmt.Printf("  %s  %s\n", labelStyle.Render("CORS"), warnStyle.Render(fmt.Sprintf("⚠ %d issues", issueCount)))
		}
		for i, iss := range cors.Issues {
			fmt.Printf("  %s%s %s\n", tree(i == len(cors.Issues)-1), severityIcon(iss.Severity), iss.Message)
		}
		fmt.Println()
		return
	}

	issueLabel := okStyle.Render("✓ no issues")
	if len(cors.Issues) > 0 {
		issueLabel = warnStyle.Render(fmt.Sprintf("⚠ %d issues", len(cors.Issues)))
	}

	fmt.Printf("  %s  %s\n", labelStyle.Render("CORS"), issueLabel)

	origin := "(none)"
	if cors.AllowOrigin != nil {
		origin = *cors.AllowOrigin
	}
	fmt.Printf("  %sAllow-Origin: %s\n", tree(false), origin)

	if len(cors.AllowMethods) > 0 {
		fmt.Printf("  %sAllow-Methods: %s\n", tree(false), strings.Join(cors.AllowMethods, ", "))
	}
	fmt.Printf("  %sCredentials: %v\n", tree(false), cors.AllowCredentials)

	for i, iss := range cors.Issues {
		last := i == len(cors.Issues)-1
		fmt.Printf("  %s%s %s\n", tree(last), severityIcon(iss.Severity), iss.Message)
	}

	if len(cors.Issues) == 0 {
		fmt.Printf("  %sVary: Origin: %v\n", tree(true), cors.VaryOrigin)
	}
	fmt.Println()
}

func renderRedirectChain(chain RedirectChain) {
	status := okStyle.Render(fmt.Sprintf("✓ %d hops", chain.Hops))
	if chain.LoopDetected {
		status = errStyle.Render("✗ loop detected")
	} else if chain.MixedContent {
		status = errStyle.Render("✗ mixed content")
	}

	fmt.Printf("  %s  %s\n", labelStyle.Render("Redirect Chain"), status)

	for i, hop := range chain.Chain {
		last := i == len(chain.Chain)-1 && len(chain.Issues) == 0
		prefix := tree(last)

		statusStr := dimStyle.Render(fmt.Sprintf("%d", hop.Status))
		if hop.Status >= 300 && hop.Status < 400 {
			statusStr = accentStyle.Render(fmt.Sprintf("%d", hop.Status))
		} else if hop.Status == 200 {
			statusStr = okStyle.Render(fmt.Sprintf("%d", hop.Status))
		} else if hop.Status >= 400 {
			statusStr = errStyle.Render(fmt.Sprintf("%d", hop.Status))
		}

		timing := dimStyle.Render(fmt.Sprintf("(%dms)", int(hop.TimingMs)))

		if hop.Location != "" {
			fmt.Printf("  %s%s → %s %s %s\n", prefix, hop.URL, statusStr, hop.Location, timing)
		} else {
			fmt.Printf("  %s%s → %s %s\n", prefix, hop.URL, statusStr, timing)
		}
	}

	for i, iss := range chain.Issues {
		fmt.Printf("  %s%s %s\n", tree(i == len(chain.Issues)-1), severityIcon(iss.Severity), iss.Message)
	}
	fmt.Println()
}

func renderCache(cache CacheResult) {
	fmt.Printf("  %s\n", labelStyle.Render("Cache"))

	if cache.CacheControl != "" {
		fmt.Printf("  %sCache-Control: %s\n", tree(false), cache.CacheControl)
	} else {
		fmt.Printf("  %sCache-Control: %s\n", tree(false), dimStyle.Render("not set"))
	}

	if cache.EffectiveTTL != nil {
		ttl := *cache.EffectiveTTL
		var ttlStr string
		if ttl >= 86400 {
			ttlStr = fmt.Sprintf("%dd", ttl/86400)
		} else if ttl >= 3600 {
			ttlStr = fmt.Sprintf("%dh", ttl/3600)
		} else if ttl >= 60 {
			ttlStr = fmt.Sprintf("%dm", ttl/60)
		} else {
			ttlStr = fmt.Sprintf("%ds", ttl)
		}
		fmt.Printf("  %sEffective TTL: %s\n", tree(false), ttlStr)
	}

	if cache.CDNProvider != "" {
		cdnStatus := cache.CDNStatus
		if cdnStatus == "" {
			cdnStatus = "unknown"
		}
		fmt.Printf("  %sCDN: %s (%s)\n", tree(false), cache.CDNProvider, cdnStatus)
	}

	if len(cache.Vary) > 0 {
		fmt.Printf("  %sVary: %s\n", tree(len(cache.Issues) == 0), strings.Join(cache.Vary, ", "))
	}

	for i, iss := range cache.Issues {
		fmt.Printf("  %s%s %s\n", tree(i == len(cache.Issues)-1), severityIcon(iss.Severity), iss.Message)
	}

	if cache.CacheControl == "" && cache.CDNProvider == "" && len(cache.Issues) == 0 {
		fmt.Printf("  %s%s\n", tree(true), dimStyle.Render("No cache headers detected"))
	}
	fmt.Println()
}

func renderTLS(tls TLSResult) {
	ver := tls.Version
	if ver == "" || ver == "unknown" {
		ver = "unknown"
		fmt.Printf("  %s TLS: %s  %s\n", dimStyle.Render("?"), dimStyle.Render(ver), dimStyle.Render("→ certs.lol for details"))
	} else {
		fmt.Printf("  %s TLS: %s  %s\n", check(true), ver, dimStyle.Render("→ certs.lol for details"))
	}
}

func renderLinks(meta Meta) {
	fmt.Printf("  %s\n", dimStyle.Render("─────────────────────────────"))
	if meta.Links.FullReport != "" {
		fmt.Printf("  %s %s\n", accentStyle.Render("📊"), dimStyle.Render(meta.Links.FullReport))
	}
	if meta.Links.TLSDetails != "" {
		fmt.Printf("  %s %s\n", accentStyle.Render("🔐"), dimStyle.Render(meta.Links.TLSDetails))
	}
	if meta.Links.DNSDetails != "" {
		fmt.Printf("  %s %s\n", accentStyle.Render("🌐"), dimStyle.Render(meta.Links.DNSDetails))
	}
	fmt.Println()
}

func renderFullScan(result *ScanResult) {
	renderBanner(result.URL)
	renderGrade(result)
	renderSecurityHeaders(result.SecurityHeaders)
	renderCSP(result.CSP)
	renderCORS(result.CORS)
	renderRedirectChain(result.RedirectChain)
	renderCache(result.Cache)
	renderTLS(result.TLS)
	renderLinks(result.Meta)
}

// ─── Commands ───────────────────────────────────────────────────────

func main() {
	var jsonOutput bool

	rootCmd := &cobra.Command{
		Use:   "preflight <domain>",
		Short: "HTTP response debugger — CORS, CSP, security headers, redirects, cache",
		Long: `preflight.lol CLI — everything the browser sees and enforces.

Scan any domain for CORS behavior, CSP policy, security headers, 
redirect chains, and cache configuration. One command, full picture.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := strings.TrimSpace(args[0])
			domain = strings.TrimPrefix(domain, "https://")
			domain = strings.TrimPrefix(domain, "http://")
			domain = strings.TrimRight(domain, "/")

			if jsonOutput {
				var raw json.RawMessage
				if err := fetchJSON(apiBase+"/"+domain, &raw); err != nil {
					return err
				}
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(raw)
			}

			if isTTY {
				fmt.Printf("  %s %s...", accentStyle.Render("⏳"), dimStyle.Render("scanning "+domain))
			}

			var result ScanResult
			if err := fetchJSON(apiBase+"/"+domain, &result); err != nil {
				if isTTY {
					fmt.Print("\r\033[K")
				}
				return err
			}

			if isTTY {
				fmt.Print("\r\033[K")
			}

			renderFullScan(&result)
			return exitCode(&result)
		},
	}

	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "Output raw JSON")

	// ── cors subcommand ───────────────────────────────────────────
	corsCmd := &cobra.Command{
		Use:   "cors <domain>",
		Short: "CORS-focused scan",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := cleanDomain(args[0])
			if jsonOutput {
				var raw json.RawMessage
				if err := fetchJSON(apiBase+"/"+domain+"/cors", &raw); err != nil {
					return err
				}
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(raw)
			}
			var result SubCORS
			if err := fetchJSON(apiBase+"/"+domain+"/cors", &result); err != nil {
				return err
			}
			fmt.Println()
			fmt.Printf("  %s — %s\n\n", titleStyle.Render("CORS"), labelStyle.Render(domain))
			renderCORS(result.CORS)
			return nil
		},
	}

	// ── headers subcommand ────────────────────────────────────────
	headersCmd := &cobra.Command{
		Use:   "headers <domain>",
		Short: "Security headers scan",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := cleanDomain(args[0])
			if jsonOutput {
				var raw json.RawMessage
				if err := fetchJSON(apiBase+"/"+domain+"/headers", &raw); err != nil {
					return err
				}
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(raw)
			}
			var result SubHeaders
			if err := fetchJSON(apiBase+"/"+domain+"/headers", &result); err != nil {
				return err
			}
			fmt.Println()
			fmt.Printf("  %s — %s\n\n", titleStyle.Render("Security Headers"), labelStyle.Render(domain))
			renderSecurityHeaders(result.SecurityHeaders)
			return nil
		},
	}

	// ── csp subcommand ────────────────────────────────────────────
	cspCmd := &cobra.Command{
		Use:   "csp <domain>",
		Short: "CSP-focused scan",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := cleanDomain(args[0])
			if jsonOutput {
				var raw json.RawMessage
				if err := fetchJSON(apiBase+"/"+domain+"/csp", &raw); err != nil {
					return err
				}
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(raw)
			}
			var result SubCSP
			if err := fetchJSON(apiBase+"/"+domain+"/csp", &result); err != nil {
				return err
			}
			fmt.Println()
			fmt.Printf("  %s — %s\n\n", titleStyle.Render("CSP"), labelStyle.Render(domain))
			renderCSP(result.CSP)
			return nil
		},
	}

	// ── chain subcommand ──────────────────────────────────────────
	chainCmd := &cobra.Command{
		Use:   "chain <domain>",
		Short: "Redirect chain analysis",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := cleanDomain(args[0])
			if jsonOutput {
				var raw json.RawMessage
				if err := fetchJSON(apiBase+"/"+domain+"/chain", &raw); err != nil {
					return err
				}
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(raw)
			}
			var result SubChain
			if err := fetchJSON(apiBase+"/"+domain+"/chain", &result); err != nil {
				return err
			}
			fmt.Println()
			fmt.Printf("  %s — %s\n\n", titleStyle.Render("Redirect Chain"), labelStyle.Render(domain))
			renderRedirectChain(result.RedirectChain)
			return nil
		},
	}

	// ── cache subcommand ──────────────────────────────────────────
	cacheCmd := &cobra.Command{
		Use:   "cache <domain>",
		Short: "Cache behavior analysis",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := cleanDomain(args[0])
			if jsonOutput {
				var raw json.RawMessage
				if err := fetchJSON(apiBase+"/"+domain+"/cache", &raw); err != nil {
					return err
				}
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(raw)
			}
			var result SubCache
			if err := fetchJSON(apiBase+"/"+domain+"/cache", &result); err != nil {
				return err
			}
			fmt.Println()
			fmt.Printf("  %s — %s\n\n", titleStyle.Render("Cache"), labelStyle.Render(domain))
			renderCache(result.Cache)
			return nil
		},
	}

	// ── error subcommand ──────────────────────────────────────────
	errorCmd := &cobra.Command{
		Use:   "error <cors-error-message>",
		Short: "Decode a CORS error from your browser console",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			errorMsg := strings.Join(args, " ")

			var result map[string]interface{}
			if err := postJSON(apiBase+"/error", CORSErrorRequest{Error: errorMsg}, &result); err != nil {
				return err
			}

			if jsonOutput {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(result)
			}

			fmt.Println()
			fmt.Printf("  %s\n\n", titleStyle.Render("CORS Error Decoded"))

			if diag, ok := result["diagnosis"].(string); ok {
				fmt.Printf("  %s %s\n\n", labelStyle.Render("Diagnosis:"), diag)
			}
			if cause, ok := result["likely_cause"].(string); ok {
				fmt.Printf("  %s %s\n\n", labelStyle.Render("Likely cause:"), cause)
			}
			if steps, ok := result["fix_steps"].([]interface{}); ok && len(steps) > 0 {
				fmt.Printf("  %s\n", labelStyle.Render("Fix:"))
				for i, s := range steps {
					fmt.Printf("  %s%s\n", tree(i == len(steps)-1), s)
				}
				fmt.Println()
			}
			if headers, ok := result["headers_needed"].(map[string]interface{}); ok && len(headers) > 0 {
				fmt.Printf("  %s\n", labelStyle.Render("Headers needed:"))
				keys := make([]string, 0, len(headers))
				for k := range headers {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for i, k := range keys {
					fmt.Printf("  %s%s: %v\n", tree(i == len(keys)-1), accentStyle.Render(k), headers[k])
				}
				fmt.Println()
			}
			return nil
		},
	}

	// ── simulate subcommand ───────────────────────────────────────
	var simOrigin, simMethod string
	var simHeaders []string
	var simCredentials bool

	simCmd := &cobra.Command{
		Use:   "simulate <target-url>",
		Short: "Simulate a CORS request with custom parameters",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			if !strings.HasPrefix(target, "http") {
				target = "https://" + target
			}

			req := CORSSimRequest{
				Target:      target,
				Origin:      simOrigin,
				Method:      simMethod,
				Headers:     simHeaders,
				Credentials: simCredentials,
			}

			var result map[string]interface{}
			if err := postJSON(apiBase+"/cors", req, &result); err != nil {
				return err
			}

			if jsonOutput {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(result)
			}

			fmt.Println()
			fmt.Printf("  %s\n", titleStyle.Render("CORS Simulation"))
			fmt.Printf("  %s → %s\n\n", accentStyle.Render(simOrigin), labelStyle.Render(target))

			if allowed, ok := result["allowed"].(bool); ok {
				if allowed {
					fmt.Printf("  Result: %s\n\n", okStyle.Render("✓ ALLOWED"))
				} else {
					fmt.Printf("  Result: %s\n\n", errStyle.Render("✗ BLOCKED"))
				}
			}

			if reason, ok := result["reason"].(string); ok && reason != "" {
				fmt.Printf("  %s\n\n", reason)
			}

			if fix, ok := result["fix"].(map[string]interface{}); ok {
				if explanation, ok := fix["explanation"].(string); ok {
					fmt.Printf("  %s %s\n\n", labelStyle.Render("Fix:"), explanation)
				}
				if headers, ok := fix["headers"].(map[string]interface{}); ok {
					fmt.Printf("  %s\n", labelStyle.Render("Headers:"))
					keys := make([]string, 0, len(headers))
					for k := range headers {
						keys = append(keys, k)
					}
					sort.Strings(keys)
					for i, k := range keys {
						fmt.Printf("  %s%s: %v\n", tree(i == len(keys)-1), accentStyle.Render(k), headers[k])
					}
					fmt.Println()
				}
			}
			return nil
		},
	}
	simCmd.Flags().StringVar(&simOrigin, "origin", "https://example.com", "Request origin")
	simCmd.Flags().StringVar(&simMethod, "method", "GET", "HTTP method")
	simCmd.Flags().StringSliceVar(&simHeaders, "header", nil, "Custom request headers")
	simCmd.Flags().BoolVar(&simCredentials, "credentials", false, "Include credentials")

	// ── version subcommand ────────────────────────────────────────
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("preflight %s (%s)\n", version, commit)
		},
	}

	rootCmd.AddCommand(corsCmd, headersCmd, cspCmd, chainCmd, cacheCmd, errorCmd, simCmd, versionCmd)

	// Suppress usage on RunE errors (exit codes from scan results, not user mistakes)
	rootCmd.SilenceUsage = true
	rootCmd.SilenceErrors = true

	if err := rootCmd.Execute(); err != nil {
		if e, ok := err.(*exitErr); ok {
			os.Exit(e.code)
		}
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}

func cleanDomain(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimRight(s, "/")
	return s
}

// exitCode returns an error (nonzero exit) when the scan found critical issues.
// 0 = all good, 1 = warnings only, 2 = critical/high issues.
func exitCode(result *ScanResult) error {
	hasCritical := false
	hasWarning := false

	for _, hc := range result.SecurityHeaders.Headers {
		for _, iss := range hc.Issues {
			if iss.Severity == "critical" || iss.Severity == "high" {
				hasCritical = true
			} else if iss.Severity == "warning" {
				hasWarning = true
			}
		}
	}

	if result.CSP != nil {
		for _, iss := range result.CSP.Issues {
			if iss.Severity == "critical" || iss.Severity == "high" {
				hasCritical = true
			} else if iss.Severity == "warning" {
				hasWarning = true
			}
		}
	}

	for _, iss := range result.CORS.Issues {
		if iss.Severity == "critical" || iss.Severity == "high" {
			hasCritical = true
		} else if iss.Severity == "warning" {
			hasWarning = true
		}
	}

	if hasCritical {
		return &exitErr{code: 2}
	}
	if hasWarning {
		return &exitErr{code: 1}
	}
	return nil
}

type exitErr struct {
	code int
}

func (e *exitErr) Error() string {
	return ""
}
