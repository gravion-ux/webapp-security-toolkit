'use strict';

/**
 * Security header analyzer.
 *
 * Each analyzer takes the response header map (already lowercased keys)
 * and the original request URL and returns an array of `Finding` objects.
 *
 * Severity heuristic is intentionally conservative: header posture is a useful
 * baseline signal, but a missing header is rarely the actual root cause of an
 * incident. Most findings from this module are LOW or INFO.
 */

const { buildFinding } = require('./findings');

/**
 * @typedef {Object} Finding
 * @property {string} id
 * @property {string} title
 * @property {('CRITICAL'|'HIGH'|'MEDIUM'|'LOW'|'INFO')} severity
 * @property {string} category
 * @property {string} evidence
 * @property {string} remediation
 * @property {string} [observedValue]
 */

/**
 * Analyze the response headers from a single GET.
 *
 * @param {Record<string, string|string[]>} headers
 * @param {string} url
 * @returns {Finding[]}
 */
function analyzeHeaders(headers, url) {
  const findings = [];

  // Strict-Transport-Security
  if (!hasHeader(headers, 'strict-transport-security')) {
    findings.push(
      buildFinding({
        id: 'HSTS-MISSING',
        title: 'HSTS header missing',
        severity: 'LOW',
        category: 'transport',
        evidence: 'No Strict-Transport-Security header on the response.',
        remediation:
          'Add `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` at the edge.',
        url,
      })
    );
  } else {
    const hsts = getHeader(headers, 'strict-transport-security');
    const maxAge = /max-age\s*=\s*(\d+)/i.exec(hsts);
    const seconds = maxAge ? Number.parseInt(maxAge[1], 10) : 0;
    if (!maxAge) {
      findings.push(
        buildFinding({
          id: 'HSTS-MALFORMED',
          title: 'HSTS header malformed',
          severity: 'LOW',
          category: 'transport',
          observedValue: hsts,
          evidence: 'Strict-Transport-Security is present but no max-age directive was found.',
          remediation:
            'Add an explicit max-age, e.g. `Strict-Transport-Security: max-age=31536000; includeSubDomains`.',
          url,
        })
      );
    } else if (seconds < 31536000) {
      findings.push(
        buildFinding({
          id: 'HSTS-WEAK-MAXAGE',
          title: 'HSTS max-age below one year',
          severity: 'INFO',
          category: 'transport',
          observedValue: String(seconds),
          evidence: `HSTS max-age is ${seconds} seconds (under 31,536,000 / one year).`,
          remediation:
            'Prefer max-age values of at least 31,536,000 (one year) for production hosts.',
          url,
        })
      );
    }
    if (!/includeSubDomains/i.test(hsts)) {
      findings.push(
        buildFinding({
          id: 'HSTS-NO-INCLUDESUBDOMAINS',
          title: 'HSTS does not include subdomains',
          severity: 'INFO',
          category: 'transport',
          observedValue: hsts,
          evidence: 'includeSubDomains directive is missing.',
          remediation: 'Append `; includeSubDomains` to the HSTS header.',
          url,
        })
      );
    }
  }

  // Content-Security-Policy
  if (!hasHeader(headers, 'content-security-policy')) {
    findings.push(
      buildFinding({
        id: 'CSP-MISSING',
        title: 'Content-Security-Policy header missing',
        severity: 'MEDIUM',
        category: 'xss-hardening',
        evidence: 'No Content-Security-Policy header on the response.',
        remediation:
          'Adopt a CSP that starts with `default-src \'self\'` and explicitly lists trusted sources for scripts, styles, and images.',
        url,
      })
    );
  } else if (!/default-src/i.test(getHeader(headers, 'content-security-policy'))) {
    findings.push(
      buildFinding({
        id: 'CSP-NO-DEFAULT-SRC',
        title: 'CSP lacks a default-src fallback',
        severity: 'LOW',
        category: 'xss-hardening',
        observedValue: getHeader(headers, 'content-security-policy'),
        evidence: 'CSP is present but does not contain a default-src directive.',
        remediation:
          'Add `default-src \'self\'` so unknown directives default to a tight allow-list.',
        url,
      })
    );
  }

  // X-Frame-Options / frame-ancestors
  if (
    !hasHeader(headers, 'x-frame-options') &&
    !/frame-ancestors/i.test(getHeader(headers, 'content-security-policy') || '')
  ) {
    findings.push(
      buildFinding({
        id: 'CLICKJACKING-PROTECTION-MISSING',
        title: 'No clickjacking protection',
        severity: 'MEDIUM',
        category: 'xss-hardening',
        evidence:
          'Response has neither X-Frame-Options nor a CSP frame-ancestors directive.',
        remediation:
          "Add `X-Frame-Options: DENY` or `Content-Security-Policy: frame-ancestors 'none'`.",
        url,
      })
    );
  }

  // X-Content-Type-Options
  if (getHeader(headers, 'x-content-type-options') !== 'nosniff') {
    findings.push(
      buildFinding({
        id: 'MIME-SNIFF-PROTECTION-MISSING',
        title: 'X-Content-Type-Options is not "nosniff"',
        severity: 'LOW',
        category: 'cache-and-content',
        evidence: 'MIME sniffing is not explicitly disabled on this response.',
        remediation: 'Send `X-Content-Type-Options: nosniff` on every response.',
        url,
      })
    );
  }

  // Referrer-Policy
  if (!hasHeader(headers, 'referrer-policy')) {
    findings.push(
      buildFinding({
        id: 'REFERRER-POLICY-MISSING',
        title: 'Referrer-Policy header missing',
        severity: 'LOW',
        category: 'information-disclosure',
        evidence: 'No Referrer-Policy header is sent on the response.',
        remediation:
          "Add `Referrer-Policy: strict-origin-when-cross-origin` (or stricter).",
        url,
      })
    );
  }

  // Permissions-Policy
  if (!hasHeader(headers, 'permissions-policy')) {
    findings.push(
      buildFinding({
        id: 'PERMISSIONS-POLICY-MISSING',
        title: 'Permissions-Policy header missing',
        severity: 'INFO',
        category: 'feature-restriction',
        evidence: 'No Permissions-Policy header restricts browser features.',
        remediation:
          'Add a Permissions-Policy header that disables unused powerful APIs (camera, microphone, geolocation, payment, USB).',
        url,
      })
    );
  }

  // COOP / COEP / CORP (cross-origin isolation hardening)
  const coiMissing = [];
  if (!hasHeader(headers, 'cross-origin-opener-policy')) coiMissing.push('COOP');
  if (!hasHeader(headers, 'cross-origin-embedder-policy')) coiMissing.push('COEP');
  if (!hasHeader(headers, 'cross-origin-resource-policy')) coiMissing.push('CORP');
  if (coiMissing.length > 0) {
    findings.push(
      buildFinding({
        id: 'CROSS-ORIGIN-ISOLATION-INCOMPLETE',
        title: `Cross-origin isolation incomplete (${coiMissing.join(', ')} missing)`,
        severity: 'INFO',
        category: 'cross-origin-isolation',
        observedValue: coiMissing.join(','),
        evidence: 'One or more isolation headers are not present.',
        remediation:
          "Add `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Embedder-Policy: require-corp`, and `Cross-Origin-Resource-Policy: same-site` where appropriate.",
        url,
      })
    );
  }

  // Server version disclosure
  const server = getHeader(headers, 'server');
  if (server && /\d/.test(server)) {
    findings.push(
      buildFinding({
        id: 'SERVER-VERSION-DISCLOSURE',
        title: 'Server header discloses version',
        severity: 'INFO',
        category: 'information-disclosure',
        observedValue: server,
        evidence: 'The Server response header contains version-like tokens.',
        remediation:
          'Strip version tokens from the Server header (or set the header to a generic value) at the edge.',
        url,
      })
    );
  }
  const powered = getHeader(headers, 'x-powered-by');
  if (powered) {
    findings.push(
      buildFinding({
        id: 'X-POWERED-BY-DISCLOSURE',
        title: 'X-Powered-By header is being sent',
        severity: 'INFO',
        category: 'information-disclosure',
        observedValue: powered,
        evidence: 'The X-Powered-By header reveals the framework.',
        remediation: 'Disable the X-Powered-By header at the framework or edge.',
        url,
      })
    );
  }

  return findings;
}

function hasHeader(headers, name) {
  return Object.prototype.hasOwnProperty.call(headers, name.toLowerCase());
}

function getHeader(headers, name) {
  const k = name.toLowerCase();
  if (!hasHeader(headers, k)) return undefined;
  const v = headers[k];
  if (Array.isArray(v)) return v.join(', ');
  return v;
}

module.exports = {
  analyzeHeaders,
  hasHeader,
  getHeader,
};
