'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { analyzeHeaders } = require('../src/headers');

const URL = 'https://example.test/';

function mapFromArray(arr) {
  const out = {};
  for (const [k, v] of arr) out[k.toLowerCase()] = v;
  return out;
}

test('analyzeHeaders: flags a completely bare response', () => {
  const findings = analyzeHeaders({}, URL);
  const ids = findings.map((f) => f.id);
  assert.ok(ids.includes('HSTS-MISSING'));
  assert.ok(ids.includes('CSP-MISSING'));
  assert.ok(ids.includes('CLICKJACKING-PROTECTION-MISSING'));
  assert.ok(ids.includes('MIME-SNIFF-PROTECTION-MISSING'));
  assert.ok(ids.includes('REFERRER-POLICY-MISSING'));
  assert.ok(ids.includes('PERMISSIONS-POLICY-MISSING'));
});

test('analyzeHeaders: a hardened response produces no MEDIUM findings', () => {
  const headers = mapFromArray([
    ['strict-transport-security', 'max-age=63072000; includeSubDomains; preload'],
    ['content-security-policy', "default-src 'self'; frame-ancestors 'none'"],
    ['x-frame-options', 'DENY'],
    ['x-content-type-options', 'nosniff'],
    ['referrer-policy', 'strict-origin-when-cross-origin'],
    ['permissions-policy', 'camera=(), microphone=(), geolocation=()'],
    ['cross-origin-opener-policy', 'same-origin'],
    ['cross-origin-embedder-policy', 'require-corp'],
    ['cross-origin-resource-policy', 'same-site'],
    ['server', 'demo'],
  ]);
  const findings = analyzeHeaders(headers, URL);
  assert.deepEqual(findings, []);
});

test('analyzeHeaders: HSTS low max-age is INFO, not LOW', () => {
  const headers = mapFromArray([
    ['strict-transport-security', 'max-age=3600'],
    ['content-security-policy', "default-src 'self'; frame-ancestors 'none'"],
    ['x-content-type-options', 'nosniff'],
  ]);
  const findings = analyzeHeaders(headers, URL);
  const weak = findings.find((f) => f.id === 'HSTS-WEAK-MAXAGE');
  assert.ok(weak, 'HSTS-WEAK-MAXAGE present');
  assert.equal(weak.severity, 'INFO');
});

test('analyzeHeaders: HSTS malformed is LOW', () => {
  const headers = mapFromArray([
    ['strict-transport-security', 'includeSubDomains'],
  ]);
  const findings = analyzeHeaders(headers, URL);
  const malformed = findings.find((f) => f.id === 'HSTS-MALFORMED');
  assert.ok(malformed);
  assert.equal(malformed.severity, 'LOW');
});

test('analyzeHeaders: CSP without default-src is LOW', () => {
  const headers = mapFromArray([
    ['content-security-policy', "script-src 'self'"],
  ]);
  const findings = analyzeHeaders(headers, URL);
  const finding = findings.find((f) => f.id === 'CSP-NO-DEFAULT-SRC');
  assert.ok(finding);
  assert.equal(finding.severity, 'LOW');
});

test('analyzeHeaders: frame-ancestors alone is enough for clickjacking', () => {
  const headers = mapFromArray([
    ['content-security-policy', "default-src 'self'; frame-ancestors 'none'"],
  ]);
  const findings = analyzeHeaders(headers, URL);
  assert.equal(findings.some((f) => f.id === 'CLICKJACKING-PROTECTION-MISSING'), false);
});

test('analyzeHeaders: Server header version discloses', () => {
  const headers = mapFromArray([
    ['server', 'nginx/1.21.4'],
  ]);
  const findings = analyzeHeaders(headers, URL);
  const f = findings.find((f) => f.id === 'SERVER-VERSION-DISCLOSURE');
  assert.ok(f);
  assert.equal(f.severity, 'INFO');
  assert.equal(f.observedValue, 'nginx/1.21.4');
});

test('analyzeHeaders: X-Powered-By disclosure flags', () => {
  const headers = mapFromArray([
    ['x-powered-by', 'Express'],
  ]);
  const findings = analyzeHeaders(headers, URL);
  assert.ok(findings.find((f) => f.id === 'X-POWERED-BY-DISCLOSURE'));
});
