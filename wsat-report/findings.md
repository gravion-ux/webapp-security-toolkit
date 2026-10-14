# Web application security findings

- **Target:** http://127.0.0.1:1/
- **Generated:** 2026-10-11T16:11:26.852Z
- **Findings:** 1
- **Severity counts:** INFO=1

## Summary

| Severity | Title | Category | URL |
| --- | --- | --- | --- |
| INFO | Assessment refused by scope guard | scope | http://127.0.0.1:1/ |

## Detail

### [INFO] Assessment refused by scope guard  _(SCOPE-REFUSED)_

- **URL:** http://127.0.0.1:1/
- **Category:** scope

**Evidence**

> loopback address "127.0.0.1" blocked (set --allow-loopback to permit)

**Remediation**

> Only assess hosts you are explicitly authorized to test. Use the \`--allow-private\` / \`--allow-loopback\` flags for local targets.

---