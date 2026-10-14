'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { tlsFindings, WEAK_CIPHER_PATTERNS } = require('../src/tls');

const URL = 'https://example.test/';

test('tlsFindings: connection failure surfaces as MEDIUM', () => {
  const findings = tlsFindings(URL, { ok: false, error: 'boom' });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, 'TLS-CONNECT-FAILED');
  assert.equal(findings[0].severity, 'MEDIUM');
});

test('tlsFindings: TLSv1 handshake is HIGH', () => {
  const findings = tlsFindings(URL, {
    ok: true,
    posture: { protocol: 'TLSv1', cipher: 'TLS_RSA_WITH_AES_128_CBC_SHA' },
    certificate: { subject: '', issuer: '', validFrom: '', validTo: '', sans: [] },
  });
  assert.ok(findings.find((f) => f.id === 'TLS-DEPRECATED-PROTOCOL'));
  const f = findings.find((f) => f.id === 'TLS-DEPRECATED-PROTOCOL');
  assert.equal(f.severity, 'HIGH');
});

test('tlsFindings: TLSv1.3 + strong cipher yields no TLS findings', () => {
  const findings = tlsFindings(URL, {
    ok: true,
    posture: { protocol: 'TLSv1.3', cipher: 'TLS_AES_128_GCM_SHA256' },
    certificate: {
      subject: 'CN=example.test',
      issuer: 'CN=Issuer',
      validFrom: 'Jan  1 00:00:00 2030 GMT',
      validTo: 'Jan  1 00:00:00 2031 GMT',
      sans: ['example.test', 'www.example.test'],
    },
  });
  assert.deepEqual(findings, []);
});

test('tlsFindings: 3DES cipher is HIGH', () => {
  const findings = tlsFindings(URL, {
    ok: true,
    posture: { protocol: 'TLSv1.2', cipher: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA' },
    certificate: { subject: '', issuer: '', validFrom: '', validTo: '', sans: ['example.test'] },
  });
  const f = findings.find((f) => f.id === 'TLS-WEAK-CIPHER');
  assert.ok(f);
  assert.equal(f.severity, 'HIGH');
});

test('tlsFindings: expired cert is CRITICAL', () => {
  const findings = tlsFindings(URL, {
    ok: true,
    posture: { protocol: 'TLSv1.3', cipher: 'TLS_AES_256_GCM_SHA384' },
    certificate: {
      subject: 'CN=example.test',
      issuer: 'CN=Issuer',
      validFrom: 'Jan  1 00:00:00 2000 GMT',
      validTo: 'Jan  1 00:00:00 2001 GMT',
      sans: ['example.test'],
    },
  });
  const f = findings.find((f) => f.id === 'TLS-CERT-EXPIRED');
  assert.ok(f);
  assert.equal(f.severity, 'CRITICAL');
});

test('tlsFindings: cert without SAN is INFO', () => {
  const findings = tlsFindings(URL, {
    ok: true,
    posture: { protocol: 'TLSv1.3', cipher: 'TLS_AES_128_GCM_SHA256' },
    certificate: {
      subject: 'CN=example.test',
      issuer: 'CN=Issuer',
      validFrom: 'Jan  1 00:00:00 2030 GMT',
      validTo: 'Jan  1 00:00:00 2031 GMT',
      sans: [],
    },
  });
  const f = findings.find((f) => f.id === 'TLS-CERT-NO-SAN');
  assert.ok(f);
  assert.equal(f.severity, 'INFO');
});

test('tlsFindings: hostname not covered by SAN is HIGH', () => {
  const findings = tlsFindings(URL, {
    ok: true,
    posture: { protocol: 'TLSv1.3', cipher: 'TLS_AES_128_GCM_SHA256' },
    certificate: {
      subject: 'CN=other.test',
      issuer: 'CN=Issuer',
      validFrom: 'Jan  1 00:00:00 2030 GMT',
      validTo: 'Jan  1 00:00:00 2031 GMT',
      sans: ['other.test'],
    },
  });
  const f = findings.find((f) => f.id === 'TLS-CERT-HOSTNAME-MISMATCH');
  assert.ok(f);
  assert.equal(f.severity, 'HIGH');
});

test('WEAK_CIPHER_PATTERNS: catches the canonical weak ciphers', () => {
  const samples = [
    'TLS_RSA_WITH_RC4_128_SHA',
    'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
    'TLS_RSA_WITH_NULL_SHA',
    'TLS_RSA_EXPORT_WITH_RC4_40_MD5',
  ];
  for (const s of samples) {
    assert.ok(WEAK_CIPHER_PATTERNS.some((re) => re.test(s)), s);
  }
});
