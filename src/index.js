'use strict';

/**
 * Public API surface of the toolkit.
 *
 * `assess(url, options)` is the single entry point that downstream tools
 * (including the CLI in src/cli.js) call. It orchestrates:
 *   1. scope gating (refusal on disallowed hosts)
 *   2. safe GET with budgeted retries and redirect scope validation
 *   3. header analysis
 *   4. TLS posture inspection (when https)
 *   5. finding aggregation + return value
 */

const { parseUrl, checkUrl } = require('./scope');
const { safeGet, makeBudget } = require('./http');
const { analyzeHeaders } = require('./headers');
const { inspectTls, tlsFindings } = require('./tls');
const { buildFinding } = require('./findings');

/**
 * @typedef {Object} AssessOptions
 * @property {boolean} [allowLoopback]
 * @property {boolean} [allowPrivate]
 * @property {boolean} [allowLinkLocal]
 * @property {boolean} [followRedirects]
 * @property {number} [maxHops]
 * @property {number} [requestBudget]
 * @property {number} [delayMs]
 * @property {number} [timeoutMs]
 * @property {Record<string,string>} [headers]
 */

/**
 * Run a posture assessment against a single URL.
 *
 * @param {string} urlText
 * @param {AssessOptions} [opts]
 * @returns {Promise<{ url: string, ok: boolean, error?: string, findings: any[], http?: any, tls?: any }>}
 */
async function assess(urlText, opts = {}) {
  const parsed = parseUrl(urlText);
  if (!parsed.ok) {
    return {
      url: urlText,
      ok: false,
      error: parsed.error,
      findings: [
        buildFinding({
          id: 'URL-INVALID',
          title: 'URL failed to parse',
          severity: 'INFO',
          category: 'scope',
          evidence: parsed.error || 'parser refused the URL',
          remediation: 'Verify the URL is well-formed and uses http or https.',
          url: urlText,
        }),
      ],
    };
  }

  const scopeOptions = {
    allowLoopback: !!opts.allowLoopback,
    allowPrivate: !!opts.allowPrivate,
    allowLinkLocal: !!opts.allowLinkLocal,
    followRedirects: !!opts.followRedirects,
    maxHops: typeof opts.maxHops === 'number' ? opts.maxHops : 5,
  };

  const authorizedHosts = new Set([parsed.value.hostname.toLowerCase()]);
  const scopeDecision = checkUrl(parsed.value, {
    authorizedHosts,
    options: scopeOptions,
  });

  if (!scopeDecision.allowed) {
    return {
      url: urlText,
      ok: false,
      error: scopeDecision.reason,
      findings: [
        buildFinding({
          id: 'SCOPE-REFUSED',
          title: 'Assessment refused by scope guard',
          severity: 'INFO',
          category: 'scope',
          evidence: scopeDecision.reason,
          remediation:
            'Only assess hosts you are explicitly authorized to test. Use the `--allow-private` / `--allow-loopback` flags for local targets.',
          url: urlText,
        }),
      ],
    };
  }

  const budget = makeBudget(opts.requestBudget);
  const findings = [];
  let httpResult;
  try {
    httpResult = await safeGet(parsed.value.toString(), {
      authorizedHosts,
      options: scopeOptions,
      budget,
      maxHops: scopeOptions.maxHops,
      delayMs: opts.delayMs,
      timeoutMs: opts.timeoutMs,
      headers: opts.headers,
    });
  } catch (err) {
    const message = err && err.message ? err.message : String(err);
    return {
      url: urlText,
      ok: false,
      error: message,
      findings: [
        buildFinding({
          id: 'HTTP-CONNECT-FAILED',
          title: 'HTTP request failed',
          severity: 'MEDIUM',
          category: 'http',
          evidence: message,
          remediation:
            'Verify the host is reachable, the path returns 200/3xx, and no WAF is blocking the user-agent.',
          url: urlText,
        }),
      ],
    };
  }

  findings.push(...analyzeHeaders(httpResult.headers, httpResult.finalUrl));

  let tls;
  if (new URL(httpResult.finalUrl).protocol === 'https:') {
    tls = await inspectTls(new URL(httpResult.finalUrl), { timeoutMs: opts.timeoutMs });
    findings.push(...tlsFindings(httpResult.finalUrl, tls));
  }

  return {
    url: urlText,
    ok: true,
    findings,
    http: {
      status: httpResult.status,
      finalUrl: httpResult.finalUrl,
      chain: httpResult.chain,
      budgetRemaining: budget.remaining,
    },
    tls,
  };
}

module.exports = {
  assess,
  // re-exported for callers that want lower-level access
  parseUrl,
  checkUrl,
  analyzeHeaders,
  inspectTls,
  tlsFindings,
  buildFinding,
  toJson: require('./findings').toJson,
  toMarkdown: require('./findings').toMarkdown,
  DEFAULT_OPTIONS: require('./scope').DEFAULT_OPTIONS,
};
