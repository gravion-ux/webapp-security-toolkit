'use strict';

/**
 * TLS posture inspector.
 *
 * Performs a single TLS handshake against the host:port derived from the URL
 * and returns a structured summary:
 *   - protocol version (TLSv1.2, TLSv1.3, ...)
 *   - cipher name + family classification
 *   - certificate fields (subject, issuer, valid_to, SAN coverage)
 *
 * The tool never sends application data. It only completes the handshake
 * (or fails it) and inspects the metadata visible to the client.
 *
 * Severity reflects the negotiated posture relative to widely accepted
 * modern TLS guidance (RFC 8446 + Mozilla "intermediate" profile).
 */

const tls = require('node:tls');
const { buildFinding } = require('./findings');

const STRONG_PROTOCOLS = new Set(['TLSv1.2', 'TLSv1.3']);
const WEAK_PROTOCOLS = new Set(['TLSv1', 'TLSv1.1', 'SSLv3']);

const WEAK_CIPHER_PATTERNS = [
  /RC4/i,
  /3DES/i,
  /NULL/i,
  /EXPORT/i,
  /DES(?:-CBC)?(?:-|$)/,
  /MD5/i,
];

const FINDING_CATEGORY = 'tls';

/**
 * @typedef {Object} TlsResult
 * @property {boolean} ok
 * @property {{ protocol: string, cipher: string }} [posture]
 * @property {{ subject: string, issuer: string, validFrom: string, validTo: string, sans: string[] }} [certificate]
 * @property {string} [error]
 */

/**
 * Establish a TLS connection just far enough to read posture, then close.
 *
 * @param {URL} parsedUrl
 * @param {{ timeoutMs?: number }} [opts]
 * @returns {Promise<TlsResult>}
 */
function inspectTls(parsedUrl, opts = {}) {
  const { timeoutMs = 5000 } = opts;
  if (parsedUrl.protocol !== 'https:') {
    return Promise.resolve({
      ok: false,
      error: 'TLS inspection skipped (URL is not https).',
    });
  }

  return new Promise((resolve) => {
    const socket = tls.connect({
      host: parsedUrl.hostname,
      port: Number.parseInt(parsedUrl.port || '443', 10),
      servername: parsedUrl.hostname,
      rejectUnauthorized: false, // we inspect, we don't trust-pin
      timeout: timeoutMs,
    });

    let resolved = false;
    function finish(result) {
      if (resolved) return;
      resolved = true;
      try { socket.destroy(); } catch (_e) { /* ignore */ }
      resolve(result);
    }

    socket.on('secureConnect', () => {
      try {
        const protocol = socket.getProtocol();
        const cipher = socket.getCipher();
        const peerCert = socket.getPeerCertificate(true);
        const certSummary = summarizeCert(peerCert);
        finish({
          ok: true,
          posture: { protocol, cipher: cipher && cipher.name },
          certificate: certSummary,
        });
      } catch (err) {
        finish({ ok: false, error: `handshake completed but inspection failed: ${err && err.message ? err.message : err}` });
      }
    });
    socket.on('timeout', () => finish({ ok: false, error: 'TLS connection timed out' }));
    socket.on('error', (err) => finish({ ok: false, error: `TLS error: ${err && err.message ? err.message : err}` }));
  });
}

function summarizeCert(cert) {
  if (!cert || Object.keys(cert).length === 0) {
    return { subject: '', issuer: '', validFrom: '', validTo: '', sans: [] };
  }
  const subject = (cert.subject && (cert.subject.CN || cert.subject.O)) || (cert.subject_name || '');
  const issuer = (cert.issuer && (cert.issuer.CN || cert.issuer.O)) || (cert.issuer_name || '') ;
  const validFrom = cert.valid_from || '';
  const validTo = cert.valid_to || '';
  let sans = [];
  if (cert.subjectAltName) {
    // subjectAltName is a colon-delimited string like 'DNS:example.com,DNS:www.example.com'
    sans = cert.subjectAltName
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s.startsWith('DNS:'))
      .map((s) => s.slice('DNS:'.length));
  }
  return { subject, issuer, validFrom, validTo, sans };
}

/**
 * Translate a TlsResult into an array of Finding records.
 *
 * @param {string} url
 * @param {TlsResult} result
 * @returns {import('./findings').Finding[]}
 */
function tlsFindings(url, result) {
  if (!result.ok) {
    return [
      buildFinding({
        id: 'TLS-CONNECT-FAILED',
        title: 'TLS handshake could not be completed',
        severity: 'MEDIUM',
        category: FINDING_CATEGORY,
        evidence: result.error || 'unknown error',
        remediation:
          'Confirm the host is reachable on 443/tcp and that a valid certificate is presented.',
        url,
      }),
    ];
  }

  const findings = [];
  const { posture, certificate } = result;
  if (!STRONG_PROTOCOLS.has(posture.protocol)) {
    if (WEAK_PROTOCOLS.has(posture.protocol)) {
      findings.push(
        buildFinding({
          id: 'TLS-DEPRECATED-PROTOCOL',
          title: `Deprecated TLS protocol negotiated: ${posture.protocol}`,
          severity: 'HIGH',
          category: FINDING_CATEGORY,
          observedValue: posture.protocol,
          evidence: `Server negotiated ${posture.protocol} which is no longer considered secure.`,
          remediation:
            'Disable TLS 1.0 and 1.1 at the server / load balancer. Modern clients support TLS 1.2+ (preferably 1.3).',
          url,
        })
      );
    } else {
      findings.push(
        buildFinding({
          id: 'TLS-UNKNOWN-PROTOCOL',
          title: `Unexpected TLS protocol: ${posture.protocol}`,
          severity: 'MEDIUM',
          category: FINDING_CATEGORY,
          observedValue: posture.protocol,
          evidence: 'The negotiated protocol is not in the recommended set.',
          remediation: 'Verify the server only permits TLS 1.2 and 1.3.',
          url,
        })
      );
    }
  }

  if (!posture.cipher) {
    findings.push(
      buildFinding({
        id: 'TLS-CIPHER-UNKNOWN',
        title: 'Could not determine negotiated cipher',
        severity: 'INFO',
        category: FINDING_CATEGORY,
        evidence: 'Cipher information was not available after the handshake.',
        remediation: 'Re-test with a TLS scanner that returns the negotiated cipher.',
        url,
      })
    );
  } else if (WEAK_CIPHER_PATTERNS.some((re) => re.test(posture.cipher))) {
    findings.push(
      buildFinding({
        id: 'TLS-WEAK-CIPHER',
        title: `Weak cipher suite negotiated: ${posture.cipher}`,
        severity: 'HIGH',
        category: FINDING_CATEGORY,
        observedValue: posture.cipher,
        evidence: 'Cipher name matches a known weak family.',
        remediation:
          'Reorder cipher preferences so AEAD suites (AES-GCM, ChaCha20-Poly1305) are tried first.',
        url,
      })
    );
  }

  if (certificate) {
    const now = new Date();
    const to = Date.parse(`${certificate.validTo} GMT`);
    if (!Number.isFinite(to)) {
      findings.push(
        buildFinding({
          id: 'TLS-CERT-PARSE-FAILED',
          title: 'Could not parse certificate expiry',
          severity: 'INFO',
          category: FINDING_CATEGORY,
          observedValue: certificate.validTo,
          evidence: 'valid_to was missing or non-parseable.',
          remediation: 'Verify the certificate chain with `openssl s_client -connect host:443 -showcerts`.',
          url,
        })
      );
    } else {
      const days = Math.round((to - now.getTime()) / 86_400_000);
      if (days < 0) {
        findings.push(
          buildFinding({
            id: 'TLS-CERT-EXPIRED',
            title: 'TLS certificate has expired',
            severity: 'CRITICAL',
            category: FINDING_CATEGORY,
            observedValue: `${days} days`,
            evidence: `Certificate expired on ${certificate.validTo}.`,
            remediation: 'Renew the certificate and redeploy the renewal workflow.',
            url,
          })
        );
      } else if (days < 14) {
        findings.push(
          buildFinding({
            id: 'TLS-CERT-EXPIRY-IMMINENT',
            title: `TLS certificate expires in ${days} day${days === 1 ? '' : 's'}`,
            severity: 'HIGH',
            category: FINDING_CATEGORY,
            observedValue: `${days} days`,
            evidence: `Certificate valid_to ${certificate.validTo}.`,
            remediation: 'Renew the certificate before the expiry window closes.',
            url,
          })
        );
      }
    }

    if (certificate.sans.length === 0) {
      findings.push(
        buildFinding({
          id: 'TLS-CERT-NO-SAN',
          title: 'Certificate has no DNS Subject Alternative Names',
          severity: 'INFO',
          category: FINDING_CATEGORY,
          evidence: 'No DNS: entries were observed in the certificate SAN list.',
          remediation:
            'Modern browsers require a SAN entry that matches the hostname; reissue the certificate if necessary.',
          url,
        })
      );
    } else {
      const hostname = new URL(url).hostname.toLowerCase();
      const matches = certificate.sans.some((s) => s.toLowerCase() === hostname);
      if (!matches) {
        findings.push(
          buildFinding({
            id: 'TLS-CERT-HOSTNAME-MISMATCH',
            title: `Certificate does not cover ${hostname}`,
            severity: 'HIGH',
            category: FINDING_CATEGORY,
            observedValue: certificate.sans.join(','),
            evidence: 'None of the certificate SANs equal the requested hostname.',
            remediation:
              'Reissue the certificate so its SAN list explicitly covers the requested hostname.',
            url,
          })
        );
      }
    }
  }

  return findings;
}

module.exports = {
  inspectTls,
  tlsFindings,
  WEAK_CIPHER_PATTERNS,
  WEAK_PROTOCOLS,
  STRONG_PROTOCOLS,
};
