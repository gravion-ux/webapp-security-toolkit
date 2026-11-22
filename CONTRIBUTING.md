# Contributing to the Web Application Security Assessment Toolkit (WSAT)

Thanks for helping! WSAT is a focused, **authorized-only** security
assessment toolkit for web applications and APIs: safe, read-only
HTTP-header and TLS checks against hosts the operator explicitly
authorizes, with structured findings (JSON + Markdown) a human can
act on.

The most valuable contributions are new read-only checks, finding
quality improvements, and tests.

## Ground rules

- **Authorised targets only — hard rule.** The toolkit refuses to
  scan disallowed targets and enforces a request budget. Do not add
  checks that are destructive, state-changing, or that exceed the
  budget model — if a check cannot be done with safe, read-only
  requests, it does not belong here.
- **Zero runtime dependencies — hard rule.** Node.js built-ins only.
- **Findings must be actionable.** Every finding carries the
  evidence observed and a concrete remediation; "something looked
  odd" is not a finding.

## Development setup

Requires Node.js 18 or newer. There is nothing to install:

```bash
git clone https://github.com/gravion-ux/webapp-security-toolkit.git
cd webapp-security-toolkit
npm test
```

## Running the tests

```bash
npm test        # the full suite
npm run demo    # offline demo — the CI smoke test on Node 22
```

CI runs the suite on Node 18, 20 and 22, plus the demo smoke test.
Run the demo against no target you are not authorised to assess —
the bundled demo needs no target at all.

## Adding a check

Checks live in `src/` (scope, headers, TLS) and report through the
shared findings model. A new check needs:

1. A scope test first: the check must refuse out-of-scope targets
   exactly like the existing checks do.
2. Tests alongside the existing suites in `test/` (`scope`,
   `headers`, `tls`, `findings`, `cli`) — add the file to the
   `test` script in `package.json`, which lists files explicitly.
3. A finding shape consistent with the existing severities and
   remediation style.

## Code style

- Plain Node.js, no build step; tests use the built-in `node --test`
  runner.
- Comments explain *why* a header value or TLS property is flagged.

## Pull request workflow

1. Fork and branch from `main`: `feat/<short-name>`,
   `fix/<short-name>`, `check/<name>`, `docs/<short-name>`.
2. Run the full suite and the demo locally.
3. Open the PR against `main` with: what changed, why, how you
   tested it.
4. CI must be green. One logical change per PR.
