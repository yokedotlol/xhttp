# preflight

> The HTTP response debugger. Everything the browser sees and enforces when it hits your site.

[![Website](https://img.shields.io/badge/web-preflight.lol-d4a24c)](https://preflight.lol)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Install

**Homebrew:**
```bash
brew install yokedotlol/tap/preflight
```

**Shell:**
```bash
curl -sSL https://preflight.lol/install.sh | bash
```

**Go:**
```bash
go install github.com/yokedotlol/preflight/cli@latest
```

## Usage

```bash
# Full scan
preflight example.com

# Focused scans
preflight headers example.com
preflight cors example.com
preflight csp example.com
preflight chain example.com
preflight cache example.com

# CORS simulation
preflight simulate https://api.example.com --origin=https://myapp.com --credentials

# Decode a CORS error from your browser console
preflight error "Access to fetch at ... has been blocked by CORS policy"

# JSON output (pipe-friendly)
preflight --json example.com | jq .grade
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Clean — no issues found |
| 1 | Warnings only |
| 2 | Critical or high-severity issues |

## API

```bash
# Same data, no CLI needed
curl -s https://preflight.lol/example.com | jq
```

See [preflight.lol/api/docs](https://preflight.lol/api/docs) for the full API reference.

## Family

Part of the [.lol developer tools](https://yoke.lol) family:

- **[yoke.lol](https://yoke.lol)** — Full domain intelligence
- **[certs.lol](https://certs.lol)** — TLS/SSL certificate analysis
- **[ns.lol](https://ns.lol)** — DNS toolkit
- **[preflight.lol](https://preflight.lol)** — HTTP response debugger

## License

MIT
