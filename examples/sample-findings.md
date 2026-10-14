# Example: Sample findings (illustrative)

> This is a sample of the output shape produced by the tool, generated
> against the bundled demo servers. Values shown here are placeholders
> that exist to demonstrate the report format. No external targets
> were tested.

## Summary

| Severity | Title | Category | URL |
| --- | --- | --- | --- |
| LOW | HSTS header missing | transport | http://127.0.0.1:0/ |
| MEDIUM | Clickjacking protection missing | xss-hardening | http://127.0.0.1:0/ |
| LOW | X-Content-Type-Options is not "nosniff" | cache-and-content | http://127.0.0.1:0/ |
| LOW | Referrer-Policy header missing | information-disclosure | http://127.0.0.1:0/ |
| INFO | Server header discloses version | information-disclosure | http://127.0.0.1:0/ |
| INFO | X-Powered-By header is being sent | information-disclosure | http://127.0.0.1:0/ |

## Detail

### [LOW] HSTS header missing  _(HSTS-MISSING)_

- **URL:** http://127.0.0.1:0/
- **Category:** transport

**Evidence**

> No Strict-Transport-Security header on the response.

**Remediation**

> Add `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` at the edge.

---

### [MEDIUM] Clickjacking protection missing  _(CLICKJACKING-PROTECTION-MISSING)_

- **URL:** http://127.0.0.1:0/
- **Category:** xss-hardening

**Evidence**

> Response has neither X-Frame-Options nor a CSP frame-ancestors directive.

**Remediation**

> Add `X-Frame-Options: DENY` or `Content-Security-Policy: frame-ancestors 'none'`.
