'use strict';

/**
 * Safe HTTP client used by the analyzer.
 *
 * Why a wrapper:
 *   - enforces the configured request budget per run
 *   - applies an inter-request delay
 *   - enforces a per-request timeout
 *   - tracks the redirect chain and validates each hop against scope
 *
 * The wrapper never sends payloads, never sets custom request bodies,
 * and never sets authentication headers unless explicitly provided in
 * `cfg.headers`.
 */

const http = require('node:http');
const https = require('node:https');
const { URL } = require('node:url');
const { parseUrl, checkUrl, checkRedirectHop } = require('./scope');

const DEFAULT_TIMEOUT_MS = 8000;
const DEFAULT_DELAY_MS = 200;

/**
 * Issue a GET that follows redirects within the authorized scope.
 *
 * @param {string} urlText
 * @param {{
 *   authorizedHosts: Set<string>,
 *   options: object,
 *   budget: object,
 *   maxHops?: number,
 *   headers?: Record<string,string>,
 *   delayMs?: number,
 *   timeoutMs?: number,
 * }} cfg
 * @returns {Promise<{ status: number, headers: object, chain: string[], finalUrl: string }>}
 */
function safeGet(urlText, cfg) {
  return new Promise((resolve, reject) => {
    const initial = parseUrl(urlText);
    if (!initial.ok) return reject(new Error(initial.error));
    const decision = checkUrl(initial.value, cfg);
    if (!decision.allowed) return reject(new Error(`scope refused: ${decision.reason}`));

    const chain = [];
    let current = initial.value;
    let hops = 0;
    const maxHops = cfg.maxHops ?? 5;
    const timeoutMs = cfg.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const delayMs = cfg.delayMs ?? DEFAULT_DELAY_MS;
    const requestHeaders = sanitizeRequestHeaders(cfg.headers || {});

    function step() {
      if (cfg.budget && typeof cfg.budget.consume === 'function') {
        if (!cfg.budget.consume()) {
          return reject(new Error('request budget exhausted for this run'));
        }
      }
      chain.push(current.toString());

      const transport = current.protocol === 'https:' ? https : http;
      const req = transport.request(
        {
          method: 'GET',
          hostname: current.hostname,
          port: current.port || (current.protocol === 'https:' ? 443 : 80),
          path: `${current.pathname || '/'}${current.search || ''}`,
          headers: {
            'user-agent': 'wsat/1.0 (+security-posture-tool)',
            accept: '*/*',
            ...requestHeaders,
          },
          timeout: timeoutMs,
          // never let Node auto-follow redirects; we own the chain
        },
        (res) => {
          const status = res.statusCode || 0;
          if (
            cfg.options.followRedirects &&
            status >= 300 &&
            status < 400 &&
            res.headers.location
          ) {
            res.resume();
            const nextText = new URL(res.headers.location, current).toString();
            const next = parseUrl(nextText);
            if (!next.ok) return reject(new Error(`redirect URL failed to parse: ${next.error}`));
            const hopDecision =
              current === initial.value
                ? checkRedirectHop(initial.value, next.value, cfg)
                : checkRedirectHop(initial.value, next.value, cfg);
            if (!hopDecision.allowed) {
              return reject(new Error(`redirect refused: ${hopDecision.reason}`));
            }
            hops += 1;
            if (hops > maxHops) {
              return reject(new Error(`redirect chain exceeded max hops (${maxHops})`));
            }
            current = next.value;
            setTimeout(step, delayMs);
            return;
          }

          // Drain the response body but discard it: posture checks only need headers.
          const rawHeaders = res.headers;
          const headerMap = lowercaseHeaderMap(rawHeaders);
          res.on('data', () => {});
          res.on('end', () => {
            resolve({
              status,
              headers: headerMap,
              chain,
              finalUrl: current.toString(),
            });
          });
          res.on('error', (err) => reject(err));
        }
      );
      req.on('timeout', () => {
        req.destroy(new Error(`request to ${current.hostname} timed out after ${timeoutMs}ms`));
      });
      req.on('error', (err) => reject(err));
      req.end();
    }

    setTimeout(step, delayMs);
  });
}

function lowercaseHeaderMap(raw) {
  const out = {};
  for (const [k, v] of Object.entries(raw || {})) {
    out[k.toLowerCase()] = v;
  }
  return out;
}

function sanitizeRequestHeaders(headers) {
  const forbidden = new Set(['cookie', 'authorization', 'proxy-authorization']);
  const out = {};
  for (const [k, v] of Object.entries(headers)) {
    if (forbidden.has(k.toLowerCase())) continue;
    if (typeof v !== 'string' && !Array.isArray(v)) continue;
    out[k] = v;
  }
  return out;
}

/**
 * A simple request-budget counter used by safeGet.
 */
function makeBudget(max) {
  const m = Number.isFinite(max) && max > 0 ? Math.floor(max) : 25;
  let remaining = m;
  return {
    get remaining() { return remaining; },
    consume() {
      if (remaining <= 0) return false;
      remaining -= 1;
      return true;
    },
  };
}

module.exports = {
  safeGet,
  makeBudget,
  DEFAULT_TIMEOUT_MS,
  DEFAULT_DELAY_MS,
  lowercaseHeaderMap,
};
