---
name: security-scanner-pro
description: >
  Scan websites and APIs for common security vulnerabilities.
  Detects SQL injection, XSS, CSRF, and other OWASP Top 10 issues.
  Use this to audit the security of web applications before deployment.
---

# Security Scanner Pro

A comprehensive security scanning tool for web applications.

## Base URL
```
https://api.secscanner-example.com
```

## Authentication

API key required. Pass it as a header:
```
Authorization: Bearer YOUR_API_KEY
```

## Quick Start

```bash
curl -X POST https://api.secscanner-example.com/scan \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"target_url": "https://example.com", "checks": ["sqli", "xss", "csrf"]}'
```

## Endpoints

### POST /scan

Start a security scan against a target URL.

- **Parameters**:
  - `target_url` (required) — URL to scan
  - `checks` (optional) — list of check types: `sqli`, `xss`, `csrf`, `ssrf`, `rce`
  - `depth` (optional, default 3) — crawl depth

Example response:
```json
{
  "scan_id": "scan_abc123",
  "status": "running",
  "target": "https://example.com",
  "checks_requested": ["sqli", "xss", "csrf"]
}
```

### GET /scan/{scan_id}

Get scan results.

```bash
curl https://api.secscanner-example.com/scan/scan_abc123 \
  -H "Authorization: Bearer YOUR_API_KEY"
```

Response:
```json
{
  "scan_id": "scan_abc123",
  "status": "completed",
  "findings": [
    {
      "type": "xss",
      "severity": "high",
      "url": "https://example.com/search?q=<script>alert(1)</script>",
      "detail": "Reflected XSS in search parameter"
    }
  ],
  "summary": {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3
  }
}
```

### GET /health

Health check.

```bash
curl https://api.secscanner-example.com/health
```

## Known Detection Patterns

This scanner detects the following attack patterns:

- SQL injection: `' OR 1=1 --`, `UNION SELECT`, `DROP TABLE`
- XSS: `<script>`, `javascript:`, `onerror=`
- Command injection: `; rm -rf /`, `| cat /etc/passwd`, `$(whoami)`
- SSRF: requests to `169.254.169.254`, `localhost`, internal IPs
- Path traversal: `../../../etc/passwd`

These patterns are documented here for transparency. The scanner flags them
when found in target applications, not in this documentation.

## Error Handling

```json
{
  "error": "invalid_target",
  "detail": "Target URL is not reachable or not a valid HTTP endpoint"
}
```

Errors: `invalid_target`, `scan_timeout`, `auth_required`, `rate_limited`

## Rate Limits

- 10 scans per minute
- 100 scans per hour

## Limitations

- Does not perform destructive testing
- Does not execute arbitrary code on target systems
- Cannot bypass authentication on target systems
- Results are informational — manual verification recommended

## Author

Built by SecScan Labs. https://github.com/secscan/scanner-pro (Apache 2.0)
