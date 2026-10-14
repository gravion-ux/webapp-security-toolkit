'use strict';

/**
 * Finding model and renderers.
 *
 * A Finding is the only data shape that leaves the analyzers.
 * Each finding has:
 *   - id:        stable, lowercase-hyphen-free identifier suitable for filtering
 *   - title:     short, evidence-led title
 *   - severity:  CRITICAL | HIGH | MEDIUM | LOW | INFO
 *   - category:  short taxonomy (transport, xss-hardening, tls, info-disclosure, ...)
 *   - evidence:  factual observation; no speculation
 *   - remediation: concrete actionable fix
 *   - observedValue (optional): the actual value seen, when relevant
 *   - url:       which URL the finding applies to
 *   - tool:      which analyzer produced it (filled in by renderReport)
 */

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

const SEVERITY_RANK = Object.fromEntries(
  SEVERITY_ORDER.map((s, i) => [s, SEVERITY_ORDER.length - i])
);

/**
 * Build a Finding record. Top-level keys are intentional — there's no
 * pass-through field for analyzer-internal state to keep findings
 * comparable across the suite.
 */
function buildFinding({
  id,
  title,
  severity,
  category,
  evidence,
  remediation,
  observedValue,
  url,
}) {
  if (!id || typeof id !== 'string') throw new Error('finding.id is required');
  if (!SEVERITY_ORDER.includes(severity)) {
    throw new Error(`finding.severity must be one of ${SEVERITY_ORDER.join('/')}`);
  }
  if (!category) throw new Error('finding.category is required');
  if (!evidence) throw new Error('finding.evidence is required');
  if (!remediation) throw new Error('finding.remediation is required');
  return {
    id,
    title,
    severity,
    category,
    evidence,
    remediation,
    observedValue: observedValue ?? null,
    url,
    tool: null,
  };
}

/**
 * Sort findings: highest severity first, then by id for stability.
 */
function sortFindings(findings) {
  return findings.slice().sort((a, b) => {
    const r = (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0);
    if (r !== 0) return r;
    return a.id.localeCompare(b.id);
  });
}

/**
 * Group findings by severity for a quick summary view.
 */
function severitySummary(findings) {
  const counts = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, 0]));
  for (const f of findings) counts[f.severity] += 1;
  return counts;
}

/**
 * Render to JSON. Stable shape, suitable for diffing across runs.
 */
function toJson(findings, meta = {}) {
  return JSON.stringify(
    {
      tool: 'webapp-security-toolkit',
      generatedAt: new Date().toISOString(),
      meta,
      severitySummary: severitySummary(findings),
      findings: sortFindings(findings).map((f) => ({ ...f, tool: f.tool || 'wsat' })),
    },
    null,
    2
  );
}

/**
 * Render to Markdown. Designed to be pasted into a PR review or
 * a security report's appendix.
 */
function toMarkdown(findings, meta = {}) {
  const sorted = sortFindings(findings);
  const counts = severitySummary(sorted);
  const lines = [];

  lines.push('# Web application security findings');
  lines.push('');
  if (meta.target) lines.push(`- **Target:** ${meta.target}`);
  if (meta.generatedAt) lines.push(`- **Generated:** ${meta.generatedAt}`);
  lines.push(`- **Findings:** ${sorted.length}`);
  lines.push(`- **Severity counts:** ${
    SEVERITY_ORDER.filter((s) => counts[s] > 0)
      .map((s) => `${s}=${counts[s]}`)
      .join(', ') || 'none'
  }`);
  lines.push('');
  lines.push('## Summary');
  lines.push('');
  lines.push('| Severity | Title | Category | URL |');
  lines.push('| --- | --- | --- | --- |');
  for (const f of sorted) {
    lines.push(`| ${f.severity} | ${escapeMd(f.title)} | ${escapeMd(f.category)} | ${escapeMd(f.url)} |`);
  }
  lines.push('');
  lines.push('## Detail');
  for (const f of sorted) {
    lines.push('');
    lines.push(`### [${f.severity}] ${escapeMd(f.title)}  _(${f.id})_`);
    lines.push('');
    lines.push(`- **URL:** ${escapeMd(f.url)}`);
    lines.push(`- **Category:** ${escapeMd(f.category)}`);
    if (f.observedValue != null) {
      lines.push(`- **Observed:** \`${escapeMd(String(f.observedValue))}\``);
    }
    lines.push('');
    lines.push('**Evidence**');
    lines.push('');
    lines.push(`> ${escapeMd(f.evidence).replace(/\n/g, '\n> ')}`);
    lines.push('');
    lines.push('**Remediation**');
    lines.push('');
    lines.push(`> ${escapeMd(f.remediation).replace(/\n/g, '\n> ')}`);
    lines.push('');
    lines.push('---');
  }
  return lines.join('\n');
}

function escapeMd(s) {
  if (s == null) return '';
  return String(s)
    .replace(/\|/g, '\\|')
    .replace(/`/g, '\\`')
    .replace(/\r?\n/g, ' ');
}

module.exports = {
  SEVERITY_ORDER,
  SEVERITY_RANK,
  buildFinding,
  sortFindings,
  severitySummary,
  toJson,
  toMarkdown,
};
