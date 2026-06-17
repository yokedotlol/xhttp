# xhttp

> The HTTP response debugger. Everything the browser sees and enforces when it hits your site.

[![Website](https://img.shields.io/badge/web-xhttp.lol-d4a24c)](https://xhttp.lol)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Install

**Homebrew:**
```bash
brew install yokedotlol/tap/xhttp
```

**Shell:**
```bash
curl -sSL https://xhttp.lol/install.sh | bash
```

**Go:**
```bash
go install github.com/yokedotlol/xhttp/cli@latest
```

## Usage

```bash
# Full scan
xhttp example.com

# Focused scans
xhttp headers example.com
xhttp cors example.com
xhttp csp example.com
xhttp chain example.com
xhttp cache example.com

# CORS simulation
xhttp simulate https://api.example.com --origin=https://myapp.com --credentials

# Decode a CORS error from your browser console
xhttp error "Access to fetch at ... has been blocked by CORS policy"

# JSON output (pipe-friendly)
xhttp --json example.com | jq .grade
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
curl -s https://xhttp.lol/example.com | jq
```

See [xhttp.lol/api/docs](https://xhttp.lol/api/docs) for the full API reference.

## Family

Part of the [.lol developer tools](https://yoke.lol) family:

- **[yoke.lol](https://yoke.lol)** — Full domain intelligence
- **[certs.lol](https://certs.lol)** — TLS/SSL certificate analysis
- **[ns.lol](https://ns.lol)** — DNS toolkit
- **[xhttp.lol](https://xhttp.lol)** — HTTP response debugger

## License

MIT
