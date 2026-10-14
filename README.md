# Web Application Security Assessment Toolkit (WSAT)

A focused, **authorized-only** security assessment toolkit for web applications and APIs.
Built for security engineers running internal pre-production checks, security champions reviewing
their own services, and engineers who want a transparent baseline of HTTP-header hygiene and
TLS configuration before any deeper manual testing.

> **Scope statement.** This toolkit performs safe, read-only HTTP and TLS handshakes against
> hosts that the operator explicitly authorizes. It refuses to scan disallowed targets,
> enforces a request budget, and produces structured findings (JSON + Markdown) suitable
> for engineering review. It is **not** a vulnerability scanner, fuzzer, or exploitation
> tool and is intended for systems you own or have written permission to assess.

## What it does

- **Security header analysis** — Evaluates the presence and quality of common hardening
  headers (HSTS, CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy,
  X-Content-Type-Options, COOP/COEP/CORP).
- **TLS configuration checks** — Inspects protocol version, cipher family, basic certificate
  properties (subject, issuer, expiry, SAN coverage), and flags expired or self-signed
  certificates. Strict posture options can require modern TLS (TLS 1.2+, no 3DES/RC4).
- **HTTP method auditing** — `OPTIONS` discovery for advertised methods and a basic
  HEAD/GET resource probe.
- **Redirect chain inspection** — Records every hop, flags open redirects by payload
  pattern (parameterized query tests), and stops at a configurable depth.
- **Authorization guard (scope enforcement)** — Only assesses URLs that the operator
  explicitly lists. Refuses private/internal address ranges unless the operator
  opts in via `--allow-private`.
- **Rate limiting** — Hard request budget per run plus an inter-request delay to keep
  the noise floor low.
- **Structured findings** — Each finding has a stable ID, severity, evidence, and a
  remediation recommendation. Outputs are JSON (machine-readable) or Markdown
  (human review / PR comment friendly).
- **Built-in `demo` mode** — Boots a local vulnerable-and-secure pair of services so
  the tool can be exercised end-to-end without ever leaving the machine.

## When to use it

Use this as a **first-pass review** before deeper manual testing, or as a regression
check in a CI pipeline over your own staging service. The output is short, evidence-led,
and meant to be read by an engineer.

Do **not** use this against systems you don't own or haven't been authorized to test.
The toolkit will refuse disallowed targets even when asked.

## Quick start

```bash
# 1. Inspect the tool's own options
node src/cli.js --help

# 2. Run a header-and-TLS assessment against an authorized target
node src/cli.js scan --url https://your-staging.example.com --out ./report

# 3. Inspect the demo (no external traffic — runs entirely on localhost)
node src/cli.js demo --out ./demo-report
```

`scan` and `demo` produce `<out>/findings.json` and `<out>/findings.md`.
A run summary is printed to stdout.

## Output example

```text
[LOW] HSTS-MISSING
      Header 'Strict-Transport-Security' is not present.
      Remediation: add `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`
      Evidence: response headers captured from https://your-staging.example.com/

[INFO] METHOD-OPTIONS-ALLOWED
      Allowed methods advertised: GET, HEAD, POST
      Remediation: disable unused HTTP verbs at the edge.
```

Full annotated examples live under `examples/`.

## Project layout

```text
webapp-security-toolkit/
├── src/
│   ├── cli.js              # command-line entry point
│   ├── index.js            # public API surface
│   ├── scope.js            # URL/host authorization guard
│   ├── headers.js          # header analysis logic
│   ├── tls.js              # TLS handshake + cert inspection
│   ├── http.js             # safe HTTP client with budget + delay
│   ├── findings.js         # finding model + JSON/MD renderers
│   └── demo/
│       ├── server.js       # demo vulnerable + secure twin services
│       └── payloads.js     # demo test corpus
├── test/
│   ├── scope.test.js
│   ├── headers.test.js
│   ├── tls.test.js
│   ├── findings.test.js
│   └── cli.test.js
├── examples/
│   └── sample-findings.md
├── package.json
└── LICENSE
```

## Security & ethics

- **Authorized use only.** The scope module refuses to assess any host not explicitly
  passed in. It rejects non-routable / private CIDRs by default and refuses to follow
  a redirect off the original scope unless the operator enables `--follow`.
- **No payloads, no fuzzing.** This is a posture tool, not an exploitation tool. It
  does not send SQLi/XSS/path-traversal payloads and does not mutate server state.
- **Rate-limited.** A configurable request cap (default: 25 per host) and a 200 ms
  inter-request delay prevent noisy scanning behavior.
- **No telemetry.** Nothing leaves your machine. The HTTP and TLS clients only talk
  to hosts the operator names.

## Limitations

- This is not a substitute for manual testing, dynamic application scanning, or
  authenticated API testing. It only inspects surface posture that can be observed
  with an unauthenticated `GET` and a TLS handshake.
- TLS inspection is limited to what Node's built-in `tls` module exposes (protocol
  version, cipher name, certificate fields). It does not benchmark negotiated curves,
  session resumption, or PFS guarantees.
- Findings are heuristic; severity reflects the **observed posture**, not the
  business impact of any specific exploit.

## Testing

```bash
npm test
```

The test suite uses Node's built-in `node:test`. It covers the scope guard,
header classification, TLS posture rules, the findings model, and the CLI command
router using the demo servers (no external network).

## License

MIT — see [`LICENSE`](./LICENSE).
