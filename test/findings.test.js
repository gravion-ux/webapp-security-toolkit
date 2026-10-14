'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  buildFinding,
  sortFindings,
  severitySummary,
  toJson,
  toMarkdown,
} = require('../src/findings');

function sample(id, severity, opts = {}) {
  return buildFinding({
    id,
    title: `Title for ${id}`,
    severity,
    category: opts.category || 'x',
    evidence: 'observed fact',
    remediation: 'do the fix',
    observedValue: opts.observedValue,
    url: 'https://example.test/',
  });
}

test('buildFinding: rejects unknown severity', () => {
  assert.throws(() => buildFinding({
    id: 'X', title: 'x', severity: 'BANANA', category: 'c', evidence: 'e', remediation: 'r', url: 'u'
  }), /severity must be one of/);
});

test('buildFinding: rejects missing category', () => {
  assert.throws(() => buildFinding({
    id: 'X', title: 'x', severity: 'LOW', category: '', evidence: 'e', remediation: 'r', url: 'u'
  }), /category is required/);
});

test('buildFinding: rejects missing id', () => {
  assert.throws(() => buildFinding({
    id: '', title: 'x', severity: 'LOW', category: 'c', evidence: 'e', remediation: 'r', url: 'u'
  }), /id is required/);
});

test('severitySummary: counts every severity in the canonical order', () => {
  const f = [
    sample('A', 'LOW'),
    sample('B', 'INFO'),
    sample('C', 'LOW'),
    sample('D', 'HIGH'),
  ];
  const counts = severitySummary(f);
  assert.deepEqual(counts, { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 2, INFO: 1 });
});

test('sortFindings: highest severity first; ties broken by id', () => {
  const f = [
    sample('Z', 'LOW'),
    sample('A', 'HIGH'),
    sample('B', 'HIGH'),
    sample('C', 'CRITICAL'),
  ];
  const sorted = sortFindings(f).map((x) => x.id);
  assert.deepEqual(sorted, ['C', 'A', 'B', 'Z']);
});

test('toJson: shape contains meta, summary, and stable sorted findings', () => {
  const j = JSON.parse(toJson([sample('A', 'LOW')], { target: 'T' }));
  assert.equal(j.severitySummary.LOW, 1);
  assert.equal(j.findings[0].id, 'A');
  assert.equal(j.findings[0].tool, 'wsat');
});

test('toMarkdown: contains severity and title for each finding', () => {
  const md = toMarkdown([sample('A', 'LOW'), sample('B', 'HIGH')], { target: 'T' });
  assert.match(md, /# Web application security findings/);
  assert.match(md, /LOW/);
  assert.match(md, /HIGH/);
  assert.match(md, /Title for A/);
});

test('toMarkdown: escapes pipe characters in tables', () => {
  const md = toMarkdown([sample('A', 'LOW', { observedValue: 'a|b' })]);
  // pipe in observed value should be escaped so it doesn't break the table
  assert.ok(md.includes('a\\|b'));
});
