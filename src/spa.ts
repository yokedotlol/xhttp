// SPA renderer for xhttp.lol — dark-mode-first, orange accent, design system compliant

import type { ScanResult } from './types';

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

export function html(path: string, nonce: string, data?: Partial<ScanResult>): string {
  const domain = data?.url ? new URL(data.url).hostname : '';
  const title = domain ? `${domain} — xhttp.lol` : 'xhttp.lol — The HTTP response debugger.';
  const desc = domain && data?.grade
    ? `Security scan: ${domain} scored ${data.grade}. Headers, CORS, CSP, redirects, cache.`
    : 'CORS, CSP, security headers, redirects, cache — one command. No accounts, no tracking.';
  const nonceAttr = ` nonce="${nonce}"`;

  // Determine which page to render
  let bodyContent: string;
  if (path === '/about') bodyContent = aboutPage();
  else if (path === '/privacy') bodyContent = privacyPage();
  else if (path === '/terms') bodyContent = termsPage();
  else if (path === '/cli') bodyContent = cliPage();
  else if (path === '/api/docs') bodyContent = apiDocsPage();
  else if (data && domain) bodyContent = resultPage(data as ScanResult);
  else bodyContent = landingPage();

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<meta name="description" content="${esc(desc)}">
<meta property="og:title" content="${esc(title)}">
<meta property="og:description" content="${esc(desc)}">
<meta property="og:type" content="website">
<meta property="og:url" content="https://xhttp.lol${data ? '/' + esc(domain) : ''}">
<meta property="og:image" content="https://xhttp.lol/og.png">
<meta name="twitter:image" content="https://xhttp.lol/og.png">
<meta name="twitter:card" content="summary_large_image">
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="manifest" href="/manifest.json">
<link rel="canonical" href="https://xhttp.lol${path === '/' ? '' : esc(path)}">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<script type="application/ld+json"${nonceAttr}>${JSON.stringify({
    '@context': 'https://schema.org',
    '@type': 'WebApplication',
    name: 'xhttp.lol',
    url: 'https://xhttp.lol',
    description: 'The HTTP response debugger. CORS, CSP, security headers, redirects, cache.',
    applicationCategory: 'SecurityApplication',
    operatingSystem: 'Any',
    offers: { '@type': 'Offer', price: '0', priceCurrency: 'USD' },
    author: { '@type': 'Organization', name: 'Yoke', url: 'https://yoke.lol' },
  })}</script>
${styles()}
</head>
<body data-theme="dark">
<a href="#main" class="skip-nav">Skip to content</a>
<div class="theme-toggle">
  <button class="theme-opt active" data-t="dark">Dark</button>
  <button class="theme-opt" data-t="light">Light</button>
</div>
<div class="page">
  <header class="hdr">
    <a href="/" class="logo">xhttp<span>.lol</span></a>
    <span class="tag">HTTP response debugger</span>
  </header>
  <div class="input-wrap">
    <form action="/" method="GET" id="scanForm">
      <span class="p">$</span>
      <span class="cm">xhttp</span>
      <span class="dm">&nbsp;▸&nbsp;</span>
      <input class="di" name="d" type="text" placeholder="example.com" value="${esc(domain)}" autocomplete="off" autocapitalize="off" spellcheck="false" aria-label="Domain to scan">
    </form>
    <span class="cur" aria-hidden="true"></span>
  </div>
  <main id="main" role="main">
    ${bodyContent}
  </main>
  ${footer()}
</div>
${scripts(nonce)}
</body>
</html>`;
}

function styles(): string {
  return `<style>
*,*::before,*::after{margin:0;padding:0;box-sizing:border-box}
:root{--font-mono:'JetBrains Mono',ui-monospace,'Cascadia Code','Source Code Pro',Menlo,Consolas,monospace;--font-sans:'Inter',system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;--radius:8px;--radius-sm:6px}
body[data-theme="dark"]{
  --bg:#0a0a12;--surface:#15151f;--surface-raised:#1e1e2a;--surface-hover:#26263a;--border:#2a2a3a;--border-muted:#1e1e2a;
  --text:#e0e0ea;--text-secondary:#a8a8b8;--muted:#7a7a8e;--dim:#55556a;--faint:#3a3a4a;
  --accent:#d4a24c;--accent-fg:#0a0a12;--accent-dim:rgba(212,162,76,0.10);--accent-subtle:rgba(212,162,76,0.10);
  --ok:#3fb950;--ok-subtle:rgba(63,185,80,0.08);
  --info:#6ea8fe;--warn:#e5a820;--warn-subtle:rgba(229,168,32,0.08);--err:#f85149;--err-subtle:rgba(248,81,73,0.08);
  --purple:#bc8cff;--teal:#14b8a6;--blue:#3b82f6;--orange:#d4a24c;
}
body[data-theme="light"]{
  --bg:#fafafe;--surface:#f0f0f5;--surface-raised:#e8e8ef;--surface-hover:#dddde6;--border:#d0d0dc;--border-muted:#e0e0ea;
  --text:#1a1a2e;--text-secondary:#4a4a60;--muted:#6a6a80;--dim:#9090a4;--faint:#b8b8c8;
  --accent:#b8860b;--accent-fg:#ffffff;--accent-dim:rgba(184,134,11,0.08);--accent-subtle:rgba(184,134,11,0.08);
  --ok:#16a34a;--ok-subtle:rgba(22,163,74,0.06);
  --info:#2563eb;--warn:#b58900;--warn-subtle:rgba(181,137,0,0.06);--err:#dc2626;--err-subtle:rgba(220,38,38,0.06);
  --purple:#8250df;--teal:#0d9488;--blue:#2563eb;--orange:#b8860b;
}
html{background:var(--bg)}
body{background:var(--bg);color:var(--text);font-family:var(--font-sans);-webkit-font-smoothing:antialiased;line-height:1.6;transition:background .25s,color .25s}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
.page{max-width:720px;margin:0 auto;padding:0 1.5rem}

.skip-nav{position:absolute;left:-9999px;top:auto;width:1px;height:1px;overflow:hidden;z-index:200}.skip-nav:focus{left:0;width:auto;height:auto;padding:8px 16px;background:var(--accent);color:var(--accent-fg);font-weight:600;border-radius:0 0 var(--radius-sm) 0}

.hdr{padding:2rem 0 0;display:flex;align-items:baseline;gap:16px}
.logo{font-size:1.5rem;font-weight:800;letter-spacing:-0.04em;text-decoration:none;color:var(--text)}
.logo span{color:var(--accent)}
.tag{font-size:11px;color:var(--dim);font-family:var(--font-mono)}

.theme-toggle{position:fixed;top:16px;right:16px;z-index:100;display:flex;border-radius:var(--radius-sm);overflow:hidden;border:1px solid var(--border);background:var(--surface);font-family:var(--font-mono);font-size:11px}
.theme-opt{padding:5px 10px;cursor:pointer;border:none;background:none;color:var(--dim);transition:all .15s;white-space:nowrap}
.theme-opt.active{background:var(--accent);color:var(--accent-fg);font-weight:600}
.theme-opt:not(.active):hover{color:var(--text)}

.input-wrap{margin-top:2rem;border-bottom:2px solid var(--accent);padding-bottom:10px;font-family:var(--font-mono);font-size:14px;display:flex;align-items:center;transition:border-color .25s;outline:none}
.input-wrap form{display:contents}
.p{color:var(--accent);font-weight:600;margin-right:10px}
.cm{color:var(--accent);font-weight:600}.dm{color:var(--dim)}
.di{background:none;border:none;color:var(--text);font-family:var(--font-mono);font-size:14px;outline:none;flex:1;min-width:80px;caret-color:var(--accent)}
.di::placeholder{color:var(--faint)}
.cur{display:inline-block;width:7px;height:14px;background:var(--accent);animation:b 1.1s step-end infinite;vertical-align:text-bottom;margin-left:1px}
@keyframes b{0%,100%{opacity:.7}50%{opacity:0}}

.section{margin:2rem 0 0;background:var(--surface);border-radius:var(--radius);border:1px solid var(--border);overflow:hidden}
.section-title{padding:12px 16px;font-size:12px;font-weight:600;letter-spacing:0.05em;text-transform:uppercase;color:var(--muted);border-bottom:1px solid var(--border-muted);font-family:var(--font-mono)}
.section-body{padding:16px}

.grade-hero{display:flex;align-items:center;gap:24px;padding:2rem 0 1rem}
.grade-letter{font-size:64px;font-weight:800;font-family:var(--font-mono);letter-spacing:-0.04em;line-height:1}
.grade-A{color:var(--ok)}.grade-B{color:var(--info)}.grade-C{color:var(--warn)}.grade-D{color:var(--orange)}.grade-F{color:var(--err)}
.grade-meta{font-size:13px;color:var(--text-secondary);line-height:1.6}
.grade-meta strong{color:var(--text);font-weight:600}

.row{display:flex;justify-content:space-between;align-items:center;padding:10px 16px;border-bottom:1px solid var(--border-muted);font-size:13px;font-family:var(--font-mono);cursor:pointer;transition:background .12s}
.row:last-child{border-bottom:none}
.row:hover{background:var(--surface-hover)}
.row-label{color:var(--text-secondary);font-weight:500}
.row-value{color:var(--text);font-weight:600;max-width:60%;text-align:right;word-break:break-all}
.row-value.click-copy{cursor:pointer;position:relative}
.row-value.click-copy:hover::after{content:'📋';position:absolute;right:-20px;top:0;font-size:11px}

.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600;font-family:var(--font-mono)}
.badge-ok{background:var(--ok-subtle);color:var(--ok)}
.badge-warn{background:var(--warn-subtle);color:var(--warn)}
.badge-err{background:var(--err-subtle);color:var(--err)}
.badge-info{background:rgba(110,168,254,0.08);color:var(--info)}
.badge-pass{background:var(--ok-subtle);color:var(--ok)}
.badge-critical{background:var(--err-subtle);color:var(--err)}
.badge-high{background:var(--err-subtle);color:var(--err)}
.badge-warning{background:var(--warn-subtle);color:var(--warn)}

.finding{padding:12px 16px;border-bottom:1px solid var(--border-muted);font-size:13px;line-height:1.6}
.finding:last-child{border-bottom:none}
.finding-hdr{display:flex;align-items:center;gap:8px;margin-bottom:4px}
.finding-msg{color:var(--text)}
.finding-fix{color:var(--text-secondary);margin-top:4px;padding-left:16px;border-left:2px solid var(--border)}

.chain-hop{padding:12px 16px;border-bottom:1px solid var(--border-muted);font-size:13px;font-family:var(--font-mono)}
.chain-hop:last-child{border-bottom:none}
.chain-hop .url{color:var(--text);word-break:break-all}
.chain-hop .meta{color:var(--dim);font-size:12px;margin-top:4px}

.hero-text{margin:2.5rem 0 1rem;color:var(--text-secondary);font-size:14px;line-height:1.8;max-width:560px}
.hero-text strong{color:var(--text);font-weight:600}


.code-block{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:12px 16px;font-family:var(--font-mono);font-size:12px;overflow-x:auto;color:var(--text);margin:12px 0;line-height:1.6}
.code-block .kw{color:var(--accent)}.code-block .str{color:var(--ok)}.code-block .cmt{color:var(--dim)}

.tab-row{display:flex;border-bottom:1px solid var(--border);margin-top:2rem;overflow-x:auto;-webkit-overflow-scrolling:touch}
.tab{padding:8px 16px;font-size:12px;font-weight:500;color:var(--muted);cursor:pointer;border-bottom:2px solid transparent;transition:all .15s;white-space:nowrap;font-family:var(--font-mono)}
.tab.active{color:var(--accent);border-bottom-color:var(--accent)}
.tab:hover:not(.active){color:var(--text)}

.links-row{display:flex;gap:8px;margin:1.5rem 0;flex-wrap:wrap}
.link-pill{display:inline-flex;align-items:center;gap:4px;padding:6px 12px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);font-size:12px;color:var(--text-secondary);font-family:var(--font-mono);text-decoration:none;transition:all .15s}
.link-pill:hover{border-color:var(--accent);color:var(--accent);text-decoration:none}

.footer{margin-top:3rem;padding-top:1.5rem;border-top:1px solid var(--border-muted);text-align:center;font-size:0.8rem}
.footer-links{display:flex;justify-content:center;gap:1.25rem;flex-wrap:wrap;margin-bottom:0.75rem}
.footer-links a{color:var(--muted);text-decoration:none}.footer-links a:hover{color:var(--accent)}
.footer-tagline{color:var(--muted);font-size:0.75rem;margin-bottom:0.5rem}
.footer-tagline a{color:var(--accent);text-decoration:none}.footer-tagline a:hover{text-decoration:underline}
.footer-family{display:flex;justify-content:center;gap:1rem;flex-wrap:wrap;font-family:var(--font-mono);font-size:0.75rem;margin-bottom:0.75rem}
.footer-family a{color:var(--muted);text-decoration:none}.footer-family a:hover{color:var(--accent)}
.yoke-badge{display:inline-block;margin-top:0.25rem}

.rl-pill{position:fixed;bottom:16px;right:16px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:4px 10px;font-size:10px;font-family:var(--font-mono);color:var(--dim);z-index:100;display:none}

.loading{display:inline-block;width:14px;height:14px;border:2px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .8s linear infinite;vertical-align:middle}
@keyframes spin{to{transform:rotate(360deg)}}

@media(max-width:640px){.grade-hero{flex-direction:column;align-items:flex-start;gap:12px}.grade-letter{font-size:48px}}
.prose{font-size:14px;color:var(--text-secondary);line-height:1.8;max-width:560px;margin:1.5rem 0}
.prose h2{color:var(--text);font-size:16px;font-weight:700;margin:2rem 0 0.5rem}
.prose h3{color:var(--text);font-size:14px;font-weight:600;margin:1.5rem 0 0.5rem}
.prose p{margin:0.5rem 0}
.prose ul,.prose ol{margin:0.5rem 0 0.5rem 1.5rem}
.prose li{margin:0.25rem 0}
.prose code{font-family:var(--font-mono);font-size:12px;background:var(--surface-raised);padding:1px 5px;border-radius:3px}
</style>`;
}

function scripts(nonce: string): string {
  return `<script nonce="${nonce}">
(function(){
  // Theme toggle
  const saved=localStorage.getItem('theme')||'dark';
  document.body.setAttribute('data-theme',saved);
  document.querySelectorAll('.theme-opt').forEach(b=>{
    b.classList.toggle('active',b.dataset.t===saved);
    b.addEventListener('click',()=>{
      const t=b.dataset.t;
      document.body.setAttribute('data-theme',t);
      localStorage.setItem('theme',t);
      document.querySelectorAll('.theme-opt').forEach(x=>x.classList.toggle('active',x.dataset.t===t));
    });
  });

  // Form submission → /{domain}
  const form=document.getElementById('scanForm');
  if(form){
    form.addEventListener('submit',function(e){
      e.preventDefault();
      const d=form.querySelector('.di').value.trim().replace(/^https?:\\/\\//,'').replace(/\\/.*$/,'');
      if(d)window.location.href='/'+encodeURIComponent(d);
    });
  }

  // Click-to-copy
  document.querySelectorAll('.click-copy').forEach(el=>{
    el.addEventListener('click',()=>{
      navigator.clipboard.writeText(el.textContent.trim()).then(()=>{
        const orig=el.textContent;
        el.textContent='Copied!';
        setTimeout(()=>el.textContent=orig,1200);
      });
    });
  });

  // Focus input on load
  const inp=document.querySelector('.di');
  if(inp&&!inp.value)inp.focus();
})();
</script>`;
}

function footer(): string {
  return `<footer class="footer">
  <div class="footer-links">
    <a href="https://github.com/yokedotlol/xhttp">github</a>
    <a href="/api/docs">api</a>
    <a href="/cli">cli</a>
    <a href="/about">about</a>
    <a href="/privacy">privacy</a>
    <a href="/terms">terms</a>
  </div>
  <div class="footer-tagline">Part of the <a href="https://yoke.lol/tools">.lol tools</a></div>
  <div class="footer-family">
    <a href="https://yoke.lol">yoke</a>
    <a href="https://certs.lol">certs</a>
    <a href="https://ns.lol">ns</a>
    <a href="https://vrfy.lol">vrfy</a>
  </div>
  <a href="https://yoke.lol/xhttp.lol" class="yoke-badge"><img src="https://yoke.lol/badge/xhttp.lol.svg" alt="Yoke score for xhttp.lol" height="20"></a>
</footer>`;
}

function landingPage(): string {
  return `
  <div class="hero-text">
    <strong>Debug HTTP responses in seconds.</strong> CORS policies, CSP directives, security headers, redirect chains, cache behavior — analyzed, graded, and explained. Just type a domain above.
  </div>
  <div class="code-block">
    <span class="cmt"># Full scan</span><br>
    <span class="kw">$</span> curl <span class="str">xhttp.lol/example.com</span><br><br>
    <span class="cmt"># CORS only</span><br>
    <span class="kw">$</span> curl <span class="str">xhttp.lol/example.com/cors</span><br><br>
    <span class="cmt"># Simulate a CORS request</span><br>
    <span class="kw">$</span> curl -X POST <span class="str">xhttp.lol/cors</span> -d '{"target":"https://api.example.com","origin":"https://app.example.com"}'<br><br>
    <span class="cmt"># Decode a browser CORS error</span><br>
    <span class="kw">$</span> curl -X POST <span class="str">xhttp.lol/error</span> -d '{"error":"No Access-Control-Allow-Origin header..."}'
  </div>`;
}

function resultPage(data: ScanResult): string {
  const domain = new URL(data.url).hostname;
  const gradeClass = `grade-${data.grade[0]}`;
  const cachedBanner = data._meta?.cache_hit
    ? `<div style="margin-top:12px;padding:8px 12px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);font-size:11px;font-family:var(--font-mono);color:var(--dim)">📦 Cached result · Scanned ${new Date(data.scanned_at).toLocaleString()}</div>`
    : '';

  return `
  ${cachedBanner}
  <div class="grade-hero">
    <div class="grade-letter ${gradeClass}">${esc(data.grade)}</div>
    <div class="grade-meta">
      <strong>${esc(domain)}</strong><br>
      Scanned ${new Date(data.scanned_at).toLocaleString()}<br>
      ${data._meta?.scan_time_ms ? `${data._meta.scan_time_ms}ms` : ''}
      ${data.tls.version ? ` · ${data.tls.version}` : ''}
    </div>
  </div>

  <div class="links-row">
    <a class="link-pill" href="${esc(data._meta?.links?.full_report || '#')}">📊 Full domain report → yoke.lol</a>
  </div>

  ${renderSecurityHeaders(data.security_headers)}
  ${renderCSP(data.csp)}
  ${renderCORS(data.cors)}
  ${renderRedirectChain(data.redirect_chain)}
  ${renderCache(data.cache)}`;
}

function renderSecurityHeaders(h: ScanResult['security_headers']): string {
  if (!h) return '';
  const entries = Object.entries(h.headers) as [string, { present: boolean; value: string | null; issues: import('./types').Finding[] }][];
  return `
  <div class="section">
    <div class="section-title">Security Headers · Grade: ${esc(h.grade)} (${h.score}/${h.max_score})</div>
    <div class="section-body" style="padding:0">
      ${entries.map(([name, check]) => `
        <div class="row">
          <span class="row-label">${esc(name)}</span>
          <span class="row-value">${check.present
            ? `<span class="badge badge-ok">Present</span>`
            : `<span class="badge badge-err">Missing</span>`
          }</span>
        </div>
        ${check.value ? `<div style="padding:4px 16px 8px;font-family:var(--font-mono);font-size:11px;color:var(--dim);word-break:break-all">${esc(check.value)}</div>` : ''}
      `).join('')}
    </div>
  </div>
  ${h.conflicts?.length ? renderFindings('Header Conflicts', h.conflicts) : ''}
  ${renderFindings('Security Header Issues', entries.flatMap(([, c]) => c.issues))}`;
}

function renderCSP(csp: ScanResult['csp']): string {
  if (!csp) return '';

  // No CSP at all
  if (!csp.present) {
    return `
    <div class="section">
      <div class="section-title">Content Security Policy · Grade: ${esc(csp.grade)} · Not present</div>
      <div class="section-body">
        <div style="color:var(--dim);font-size:13px;padding:8px 0">No Content-Security-Policy header detected. The browser will load resources from any source.</div>
      </div>
    </div>
    ${renderFindings('CSP Issues', csp.issues)}`;
  }

  // CSP present — render directive table
  const parsed = csp.parsed || {};
  const directives = Object.entries(parsed);

  // Color-code values by risk
  const dangerousValues = new Set(["'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'", "data:", "blob:", "*"]);
  const cautionValues = new Set(["'unsafe-inline'"]); // in style-src it's common but still flagged

  function colorValue(directive: string, value: string): string {
    const v = value.toLowerCase().trim();
    if (v === '*') return `<span style="color:var(--err);font-weight:600">${esc(value)}</span>`;
    if (dangerousValues.has(v)) return `<span style="color:var(--err)">${esc(value)}</span>`;
    if (v.startsWith("'nonce-") || v.startsWith("'sha256-") || v.startsWith("'sha384-") || v.startsWith("'sha512-")) {
      return `<span style="color:var(--ok)">${esc(value)}</span>`;
    }
    if (v === "'self'" || v === "'none'" || v === "'strict-dynamic'") {
      return `<span style="color:var(--ok)">${esc(value)}</span>`;
    }
    if (v === "'report-sample'") return `<span style="color:var(--info)">${esc(value)}</span>`;
    // URLs/domains
    return `<span style="color:var(--text)">${esc(value)}</span>`;
  }

  const directiveRows = directives.map(([dir, values]) => {
    const coloredValues = (values as string[]).map(v => colorValue(dir, v)).join(' ');
    return `
      <div class="row" style="align-items:flex-start">
        <span class="row-label" style="min-width:140px;flex-shrink:0">${esc(dir)}</span>
        <span class="row-value" style="text-align:left;font-size:12px;word-break:break-all;max-width:none;flex:1">${coloredValues}</span>
      </div>`;
  }).join('');

  // Show missing recommended directives
  const recommended = ['default-src', 'script-src', 'style-src', 'img-src', 'font-src', 'connect-src', 'frame-ancestors', 'base-uri', 'form-action', 'object-src'];
  const missing = recommended.filter(d => !parsed[d]);

  return `
  <div class="section">
    <div class="section-title">Content Security Policy · Grade: ${esc(csp.grade)} · ${csp.mode}</div>
    <div class="section-body" style="padding:0">
      ${directiveRows}
    </div>
    ${missing.length ? `
    <div style="padding:12px 16px;border-top:1px solid var(--border-muted)">
      <div style="font-size:11px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:6px">Missing recommended directives</div>
      <div style="display:flex;flex-wrap:wrap;gap:4px">
        ${missing.map(d => `<span style="padding:2px 8px;border-radius:10px;font-size:11px;font-family:var(--font-mono);background:var(--warn-subtle);color:var(--warn)">${esc(d)}</span>`).join('')}
      </div>
    </div>` : ''}
    ${csp.raw ? `
    <details style="padding:12px 16px;border-top:1px solid var(--border-muted)">
      <summary style="font-size:11px;color:var(--dim);cursor:pointer;font-family:var(--font-mono)">Raw header value</summary>
      <div class="code-block" style="font-size:10px;word-break:break-all;margin-top:8px">${esc(csp.raw)}</div>
    </details>` : ''}
  </div>
  ${renderFindings('CSP Issues', csp.issues)}`;
}

function renderCORS(cors: ScanResult['cors']): string {
  if (!cors) return '';
  return `
  <div class="section">
    <div class="section-title">CORS · ${cors.enabled ? 'Enabled' : 'Not enabled'}</div>
    <div class="section-body" style="padding:0">
      <div class="row"><span class="row-label">Access-Control-Allow-Origin</span><span class="row-value">${esc(cors.allow_origin || '—')}</span></div>
      <div class="row"><span class="row-label">Credentials</span><span class="row-value">${cors.allow_credentials ? 'true' : 'false'}</span></div>
      <div class="row"><span class="row-label">Allow-Methods</span><span class="row-value">${cors.allow_methods.length ? esc(cors.allow_methods.join(', ')) : '—'}</span></div>
      <div class="row"><span class="row-label">Expose-Headers</span><span class="row-value">${cors.expose_headers.length ? esc(cors.expose_headers.join(', ')) : '—'}</span></div>
      <div class="row"><span class="row-label">Max-Age</span><span class="row-value">${cors.max_age !== null ? `${cors.max_age}s` : '—'}</span></div>
      <div class="row"><span class="row-label">Vary: Origin</span><span class="row-value">${cors.vary_origin
        ? '<span class="badge badge-ok">Yes</span>'
        : '<span class="badge badge-warn">No</span>'
      }</span></div>
      <div class="row"><span class="row-label">Preflight Status</span><span class="row-value">${cors.preflight_status ?? '—'}</span></div>
    </div>
  </div>
  ${renderFindings('CORS Issues', cors.issues)}`;
}

function renderRedirectChain(chain: ScanResult['redirect_chain']): string {
  if (!chain) return '';
  if (chain.hops === 0 && chain.chain.length <= 1) {
    return `<div class="section"><div class="section-title">Redirect Chain · No redirects</div><div class="section-body" style="font-size:13px;color:var(--dim)">Direct response, no redirects detected.</div></div>`;
  }
  return `
  <div class="section">
    <div class="section-title">Redirect Chain · ${chain.hops} hop${chain.hops === 1 ? '' : 's'} · ${chain.total_time_ms}ms total</div>
    <div class="section-body" style="padding:0">
      ${chain.chain.map((hop, i) => `
        <div class="chain-hop">
          <div style="display:flex;align-items:center;gap:8px">
            <span class="badge ${hop.status >= 300 && hop.status < 400 ? 'badge-info' : hop.status >= 200 && hop.status < 300 ? 'badge-ok' : 'badge-warn'}">${hop.status}</span>
            <span style="font-size:11px;color:var(--dim)">${hop.timing_ms}ms</span>
            ${i < chain.chain.length - 1 ? '→' : '✓'}
          </div>
          <div class="url" style="margin-top:4px">${esc(hop.url)}</div>
          ${hop.location ? `<div class="meta">Location: ${esc(hop.location)}</div>` : ''}
        </div>
      `).join('')}
    </div>
  </div>
  ${chain.mixed_content ? '<div style="margin:8px 0;padding:8px 12px;background:var(--err-subtle);border-radius:var(--radius-sm);font-size:12px;color:var(--err);font-family:var(--font-mono)">⚠️ Mixed content: HTTPS → HTTP downgrade detected in redirect chain</div>' : ''}
  ${chain.loop_detected ? '<div style="margin:8px 0;padding:8px 12px;background:var(--err-subtle);border-radius:var(--radius-sm);font-size:12px;color:var(--err);font-family:var(--font-mono)">🔄 Redirect loop detected</div>' : ''}
  ${renderFindings('Redirect Issues', chain.issues)}`;
}

function renderCache(cache: ScanResult['cache']): string {
  if (!cache) return '';
  return `
  <div class="section">
    <div class="section-title">Cache Behavior</div>
    <div class="section-body" style="padding:0">
      <div class="row"><span class="row-label">Cache-Control</span><span class="row-value click-copy">${esc(cache.cache_control || 'Not set')}</span></div>
      <div class="row"><span class="row-label">Effective TTL</span><span class="row-value">${cache.effective_ttl !== null ? formatTTL(cache.effective_ttl) : '—'}</span></div>
      <div class="row"><span class="row-label">CDN</span><span class="row-value">${cache.cdn_provider ? esc(cache.cdn_provider) : '—'}${cache.cdn_status ? ` (${esc(cache.cdn_status)})` : ''}</span></div>
      <div class="row"><span class="row-label">Vary</span><span class="row-value">${cache.vary.length ? esc(cache.vary.join(', ')) : '—'}</span></div>
    </div>
    ${cache.explanation ? `<div style="padding:12px 16px;font-size:12px;color:var(--text-secondary);border-top:1px solid var(--border-muted)">${esc(cache.explanation)}</div>` : ''}
  </div>
  ${renderFindings('Cache Issues', cache.issues)}`;
}

function renderFindings(title: string, findings: import('./types').Finding[]): string {
  if (!findings || findings.length === 0) return '';
  return `
  <div class="section" style="margin-top:8px">
    <div class="section-title">${esc(title)}</div>
    <div class="section-body" style="padding:0">
      ${findings.map(f => `
        <div class="finding">
          <div class="finding-hdr">
            <span class="badge badge-${f.severity}">${f.severity}</span>
            <span style="font-family:var(--font-mono);font-size:11px;color:var(--dim)">${esc(f.code)}</span>
          </div>
          <div class="finding-msg">${esc(f.message)}</div>
          ${f.fix ? `<div class="finding-fix">${esc(f.fix)}</div>` : ''}
          ${f.mdn ? `<div style="margin-top:4px;font-size:11px"><a href="${esc(f.mdn)}">MDN docs →</a></div>` : ''}
        </div>
      `).join('')}
    </div>
  </div>`;
}

function formatTTL(seconds: number): string {
  if (seconds <= 0) return 'no-cache';
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h`;
  return `${Math.round(seconds / 86400)}d`;
}

// ── Static pages ─────────────────────────────────────────────────

function aboutPage(): string {
  return `<div class="prose">
  <h2>About xhttp.lol</h2>
  <p>xhttp.lol is the HTTP response debugger. It analyzes CORS policies, CSP directives, security headers, redirect chains, and cache behavior — and tells you exactly what's wrong and how to fix it.</p>
  <h3>Why?</h3>
  <p>Because CORS errors are the most frustrating part of web development. Because CSP policies are hard to get right. Because you shouldn't need to memorize which security headers exist and what they do. One command. Real answers. Fix suggestions with actual server configs.</p>
  <h3>How it works</h3>
  <p>We send real HTTP requests to your target (including OPTIONS preflight requests) and analyze every response header. No JavaScript execution, no screenshots, no third-party APIs — just HTTP analysis at the protocol level.</p>
  <h3>Part of the .lol family</h3>
  <p><a href="https://yoke.lol">yoke.lol</a> — full domain intelligence · <a href="https://certs.lol">certs.lol</a> — TLS/SSL analysis · <a href="https://ns.lol">ns.lol</a> — DNS toolkit · <a href="https://vrfy.lol">vrfy.lol</a> — email validation</p>
  <h3>Contact</h3>
  <p><a href="mailto:hello@yoke.lol">hello@yoke.lol</a> · <a href="https://github.com/yokedotlol/xhttp">GitHub</a></p>
  </div>`;
}

function privacyPage(): string {
  return `<div class="prose">
  <h2>Privacy</h2>
  <p>xhttp.lol does not track you. No cookies, no analytics, no advertising, no account required.</p>
  <p>We log scan counts per day (no domain names, no IPs) for capacity planning. Rate limiting uses an IP-derived hashed key in a Cloudflare Durable Object that expires after one hour.</p>
  <p>Scan results are cached for one hour in Cloudflare KV, keyed by domain name. No personal data is stored.</p>
  <p><a href="mailto:hello@yoke.lol">hello@yoke.lol</a> for questions.</p>
  </div>`;
}

function termsPage(): string {
  return `<div class="prose">
  <h2>Terms</h2>
  <p>xhttp.lol is a free tool. Use it responsibly. Don't use it to probe systems you don't have permission to test.</p>
  <p>Results are informational and may be incomplete or incorrect. Security decisions should not be based solely on this tool's output.</p>
  <p>We reserve the right to rate-limit or block abusive usage. No warranty, express or implied.</p>
  </div>`;
}

function cliPage(): string {
  return `<div class="prose">
  <h2>CLI</h2>
  <p>HTTP response debugger. CORS, CSP, security headers, redirects, cache — runs entirely on your machine.</p>
  <p style="display:flex;gap:6px;flex-wrap:wrap">
    <span style="display:inline-block;background:#1a1520;border:1px solid #2a2030;border-radius:4px;padding:2px 8px;font-size:12px;color:#d4a24c">MIT</span>
    <span style="display:inline-block;background:#1a1520;border:1px solid #2a2030;border-radius:4px;padding:2px 8px;font-size:12px;color:#d4a24c">Go</span>
    <span style="display:inline-block;background:#1a1520;border:1px solid #2a2030;border-radius:4px;padding:2px 8px;font-size:12px;color:#d4a24c">Zero dependencies</span>
  </p>
  <p style="margin-top:0.75rem;padding:8px 12px;background:#111116;border-left:3px solid #3fb950;border-radius:4px;font-size:12px;color:#8e8e9a">🔒 <strong style="color:#3fb950">Privacy:</strong> By default, this CLI never contacts xhttp.lol servers. All analysis runs directly from your machine to the target domain. The <code style="color:#d4a24c">--api</code> flag optionally routes requests through xhttp.lol for comparison. <a href="https://github.com/yokedotlol/xhttp" style="color:#d4a24c">You can always self-host if you need privacy.</a></p>
  </div>

  <div class="prose">
  <h3>Install</h3>
  </div>
  <div class="code-block">
    <span class="cmt"># Homebrew</span><br>
    <span class="kw">$</span> brew install yokedotlol/tap/xhttp<br><br>
    <span class="cmt"># Or one-liner</span><br>
    <span class="kw">$</span> curl -sSL <span class="str">https://xhttp.lol/install.sh</span> | bash<br><br>
    <span class="cmt"># Or download from GitHub Releases</span><br>
    <span class="kw">$</span> curl -sL <span class="str">https://github.com/yokedotlol/xhttp/releases/latest/download/xhttp_darwin_arm64.tar.gz</span> | tar xz<br>
    <span class="kw">$</span> sudo mv xhttp /usr/local/bin/
  </div>

  <div class="prose">
  <h3>Quick Start</h3>
  </div>
  <div class="code-block">
    <span class="cmt"># Full scan</span><br>
    <span class="kw">$</span> xhttp <span class="str">example.com</span><br><br>
    <span class="cmt"># JSON output (default when piped)</span><br>
    <span class="kw">$</span> xhttp <span class="str">example.com</span> --json | jq<br><br>
    <span class="cmt"># CORS only</span><br>
    <span class="kw">$</span> xhttp cors <span class="str">example.com</span><br><br>
    <span class="cmt"># Security headers</span><br>
    <span class="kw">$</span> xhttp headers <span class="str">example.com</span><br><br>
    <span class="cmt"># CSP analysis</span><br>
    <span class="kw">$</span> xhttp csp <span class="str">example.com</span><br><br>
    <span class="cmt"># Redirect chain</span><br>
    <span class="kw">$</span> xhttp chain <span class="str">example.com</span><br><br>
    <span class="cmt"># Cache behavior</span><br>
    <span class="kw">$</span> xhttp cache <span class="str">example.com</span><br><br>
    <span class="cmt"># Decode a CORS error from your browser console</span><br>
    <span class="kw">$</span> xhttp error <span class="str">"No 'Access-Control-Allow-Origin' header is present..."</span><br><br>
    <span class="cmt"># Simulate a CORS request</span><br>
    <span class="kw">$</span> xhttp simulate <span class="str">https://api.example.com</span> --origin <span class="str">https://app.example.com</span>
  </div>

  <div class="prose">
  <h3>Commands</h3>
  <table style="width:100%;border-collapse:collapse;font-size:13px;margin:0.75rem 0">
    <tr><td style="padding:6px 12px;border-bottom:1px solid #1a1520;color:#e0e0ea;white-space:nowrap"><code style="color:#d4a24c;font-size:12px">xhttp &lt;domain&gt;</code></td><td style="padding:6px 12px;border-bottom:1px solid #1a1520;color:#8e8e9a">Full scan (headers, CSP, CORS, redirects, cache, TLS)</td></tr>
    <tr><td style="padding:6px 12px;border-bottom:1px solid #1a1520;color:#e0e0ea;white-space:nowrap"><code style="color:#d4a24c;font-size:12px">xhttp cors &lt;domain&gt;</code></td><td style="padding:6px 12px;border-bottom:1px solid #1a1520;color:#8e8e9a">CORS-focused scan with origin reflection detection</td></tr>
    <tr><td style="padding:6px 12px;border-bottom:1px solid #1a1520;color:#e0e0ea;white-space:nowrap"><code style="color:#d4a24c;font-size:12px">xhttp headers &lt;domain&gt;</code></td><td style="padding:6px 12px;border-bottom:1px solid #1a1520;color:#8e8e9a">Security headers scan and grading</td></tr>
    <tr><td style="padding:6px 12px;border-bottom:1px solid #1a1520;color:#e0e0ea;white-space:nowrap"><code style="color:#d4a24c;font-size:12px">xhttp csp &lt;domain&gt;</code></td><td style="padding:6px 12px;border-bottom:1px solid #1a1520;color:#8e8e9a">CSP parsing, bypass detection, grading</td></tr>
    <tr><td style="padding:6px 12px;border-bottom:1px solid #1a1520;color:#e0e0ea;white-space:nowrap"><code style="color:#d4a24c;font-size:12px">xhttp chain &lt;domain&gt;</code></td><td style="padding:6px 12px;border-bottom:1px solid #1a1520;color:#8e8e9a">Redirect chain with per-hop timing</td></tr>
    <tr><td style="padding:6px 12px;border-bottom:1px solid #1a1520;color:#e0e0ea;white-space:nowrap"><code style="color:#d4a24c;font-size:12px">xhttp cache &lt;domain&gt;</code></td><td style="padding:6px 12px;border-bottom:1px solid #1a1520;color:#8e8e9a">Cache-Control, CDN detection, TTL</td></tr>
    <tr><td style="padding:6px 12px;border-bottom:1px solid #1a1520;color:#e0e0ea;white-space:nowrap"><code style="color:#d4a24c;font-size:12px">xhttp error &lt;msg&gt;</code></td><td style="padding:6px 12px;border-bottom:1px solid #1a1520;color:#8e8e9a">Decode a browser CORS error → diagnosis + fix</td></tr>
    <tr><td style="padding:6px 12px;border-bottom:1px solid #1a1520;color:#e0e0ea;white-space:nowrap"><code style="color:#d4a24c;font-size:12px">xhttp simulate &lt;url&gt;</code></td><td style="padding:6px 12px;border-bottom:1px solid #1a1520;color:#8e8e9a">Simulate CORS with custom origin/method/headers</td></tr>
  </table>

  <h3>Flags</h3>
  <table style="width:100%;border-collapse:collapse;font-size:13px;margin:0.75rem 0">
    <tr><td style="padding:6px 12px;border-bottom:1px solid #1a1520;color:#e0e0ea;white-space:nowrap"><code style="color:#d4a24c;font-size:12px">--json</code></td><td style="padding:6px 12px;border-bottom:1px solid #1a1520;color:#8e8e9a">Output raw JSON</td></tr>
    <tr><td style="padding:6px 12px;border-bottom:1px solid #1a1520;color:#e0e0ea;white-space:nowrap"><code style="color:#d4a24c;font-size:12px">--api</code></td><td style="padding:6px 12px;border-bottom:1px solid #1a1520;color:#8e8e9a">Route requests through xhttp.lol API instead of local analysis</td></tr>
  </table>

  <h3>Exit Codes</h3>
  <table style="width:100%;border-collapse:collapse;font-size:13px;margin:0.75rem 0">
    <tr><td style="padding:6px 12px;border-bottom:1px solid #1a1520;color:#e0e0ea;white-space:nowrap"><code style="color:#d4a24c;font-size:12px">0</code></td><td style="padding:6px 12px;border-bottom:1px solid #1a1520;color:#8e8e9a">Scan succeeded, no critical issues</td></tr>
    <tr><td style="padding:6px 12px;border-bottom:1px solid #1a1520;color:#e0e0ea;white-space:nowrap"><code style="color:#d4a24c;font-size:12px">1</code></td><td style="padding:6px 12px;border-bottom:1px solid #1a1520;color:#8e8e9a">Scan succeeded, warnings found</td></tr>
    <tr><td style="padding:6px 12px;border-bottom:1px solid #1a1520;color:#e0e0ea;white-space:nowrap"><code style="color:#d4a24c;font-size:12px">2</code></td><td style="padding:6px 12px;border-bottom:1px solid #1a1520;color:#8e8e9a">Critical/high severity issues or usage error</td></tr>
  </table>

  <h3>Source</h3>
  <p style="font-size:13px;color:#8e8e9a"><a href="https://github.com/yokedotlol/xhttp" style="color:#d4a24c">github.com/yokedotlol/xhttp</a> — MIT licensed.</p>
  </div>

  <div class="prose" style="margin-top:1.5rem;padding-top:1.5rem;border-top:1px solid #1a1520">
  <h3>API</h3>
  <p style="font-size:13px;color:#8e8e9a">Prefer curl? The web API returns the same data — no CLI required:</p>
  </div>
  <div class="code-block">
    <span class="kw">$</span> curl -s <span class="str">xhttp.lol/example.com</span> | jq
  </div>
  <div class="prose">
  <p style="font-size:12px;color:#5c5c6b">The API runs analysis server-side. Rate limited to 60 requests/hour. <a href="/api/docs" style="color:#d4a24c">Full API docs →</a></p>
  </div>`;
}

function apiDocsPage(): string {
  return `<div class="prose">
  <h2>API Documentation</h2>
  <p>All endpoints return JSON. No authentication required. Rate limited to 60 requests/hour per IP.</p>

  <h3>GET /{domain}</h3>
  <p>Full scan — security headers, CSP, CORS, redirect chain, cache behavior. Returns HTML for browsers, JSON for everything else.</p>

  <h3>GET /{domain}/cors</h3>
  <p>CORS-focused scan — preflight simulation, origin reflection detection.</p>

  <h3>GET /{domain}/csp</h3>
  <p>CSP analysis — directive parsing, bypass detection, grading.</p>

  <h3>GET /{domain}/headers</h3>
  <p>Security headers only — HSTS, XFO, XCTO, Referrer-Policy, Permissions-Policy, COOP, COEP, CORP.</p>

  <h3>GET /{domain}/chain</h3>
  <p>Redirect chain — follow up to 20 hops, per-hop timing, loop/mixed-content detection.</p>

  <h3>GET /{domain}/cache</h3>
  <p>Cache behavior — Cache-Control parsing, TTL, Vary, CDN detection.</p>

  <h3>POST /cors</h3>
  <p>CORS simulation. Body: <code>{"target":"…","origin":"…","method":"GET","headers":[],"credentials":false}</code></p>

  <h3>POST /error</h3>
  <p>CORS error decoder. Body: <code>{"error":"paste browser console error here"}</code></p>

  <h3>POST /csp/evaluate</h3>
  <p>Evaluate a CSP string. Body: <code>{"policy":"default-src 'self'; script-src …"}</code></p>

  <h3>Response format</h3>
  <p>All domain scan responses include <code>_meta.links</code> pointing to <a href="https://yoke.lol">yoke.lol</a> for deeper analysis — full report, TLS details, and DNS details all link to the comprehensive domain intelligence dashboard.</p>
  </div>`;
}
