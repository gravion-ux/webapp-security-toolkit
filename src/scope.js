'use strict';

/**
 * Scope guard — the safety-critical layer of this toolkit.
 *
 * The toolkit will only assess URLs the operator explicitly passes in.
 * The scope module additionally:
 *   - validates URL syntax
 *   - rejects non-routable / private / loopback addresses by default
 *   - tracks an authorized hostname list per run
 *   - prevents redirect chains from drifting off the authorized scope
 *
 * Configuration is per-run and explicit; nothing is implicit.
 */

const net = require('node:net');
const url = require('node:url');

const DEFAULT_OPTIONS = Object.freeze({
  allowLoopback: false,
  allowPrivate: false,
  allowLinkLocal: false,
  followRedirects: false,
  maxHops: 5,
});

/**
 * @typedef {Object} ScopeDecision
 * @property {boolean} allowed
 * @property {string} reason
 */

/**
 * Validate URL syntax and return the parsed URL object or an error.
 *
 * @param {string} input
 * @returns {{ ok: true, value: URL } | { ok: false, error: string }}
 */
function parseUrl(input) {
  if (typeof input !== 'string' || input.length === 0) {
    return { ok: false, error: 'URL must be a non-empty string.' };
  }
  let parsed;
  try {
    parsed = new URL(input);
  } catch (_err) {
    return { ok: false, error: `URL failed to parse: ${input}` };
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return {
      ok: false,
      error: `URL must use http or https (got ${parsed.protocol}).`,
    };
  }
  return { ok: true, value: parsed };
}

/**
 * Returns true when the given IPv4 dotted-quad falls into a known non-public range.
 * IPv6 ranges are handled separately via `isNonRoutableIpV6` below.
 *
 * The rules here are deliberately strict: an operator who wants loopback access
 * must explicitly opt in via configuration.
 */
function isNonRoutableIpV4(ip) {
  const parts = ip.split('.').map((p) => Number.parseInt(p, 10));
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) {
    return true; // malformed — treat as non-routable so we never dial it
  }
  const [a, b] = parts;
  if (a === 10) return true;                  // 10.0.0.0/8
  if (a === 127) return true;                // 127.0.0.0/8 loopback
  if (a === 0) return true;                  // 0.0.0.0/8
  if (a === 169 && b === 254) return true;    // 169.254.0.0/16 link-local
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true;    // 192.168.0.0/16
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGN
  if (a >= 224) return true;                 // 224.0.0.0/4 multicast / 240/4 reserved
  return false;
}

function isNonRoutableIpV6(ip) {
  const lower = ip.toLowerCase();
  if (lower === '::1' || lower === '::') return true;
  if (lower.startsWith('fe80:')) return true;             // link-local
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true; // fc00::/7 ULA
  if (lower.startsWith('ff02')) return true;              // multicast
  return false;
}

function isPrivateIpLiteral(host) {
  if (net.isIP(host) === 4) return isNonRoutableIpV4(host);
  if (net.isIP(host) === 6) return isNonRoutableIpV6(host);
  return false;
}

/**
 * Validate a single URL against the operator's scope.
 *
 * @param {URL} parsedUrl
 * @param {{ authorizedHosts: Set<string>, options: object }} cfg
 * @returns {ScopeDecision}
 */
function checkUrl(parsedUrl, cfg) {
  if (!parsedUrl || typeof parsedUrl.hostname !== 'string' || parsedUrl.hostname.length === 0) {
    return { allowed: false, reason: 'hostname missing' };
  }

  // 1. authorize the host name (or IP literal) against the operator's allow-list
  const hostname = parsedUrl.hostname.toLowerCase();
  if (!cfg.authorizedHosts.has(hostname)) {
    return {
      allowed: false,
      reason: `hostname "${hostname}" is not in the operator's allow-list`,
    };
  }

  // 2. block private / loopback unless explicitly enabled
  if (isPrivateIpLiteral(hostname)) {
    const isLoopback =
      hostname === 'localhost' ||
      hostname === '127.0.0.1' ||
      hostname === '::1' ||
      hostname.startsWith('127.');
    if (isLoopback && !cfg.options.allowLoopback) {
      return {
        allowed: false,
        reason: `loopback address "${hostname}" blocked (set --allow-loopback to permit)`,
      };
    }
    if (!isLoopback && !cfg.options.allowPrivate) {
      return {
        allowed: false,
        reason: `private/internal address "${hostname}" blocked (set --allow-private to permit)`,
      };
    }
    if (hostname.startsWith('169.254.') && !cfg.options.allowLinkLocal) {
      return {
        allowed: false,
        reason: `link-local address "${hostname}" blocked (set --allow-link-local to permit)`,
      };
    }
  }

  // 3. refuse userinfo in scope URLs to avoid credential smuggling
  if (parsedUrl.username || parsedUrl.password) {
    return {
      allowed: false,
      reason: 'URLs containing userinfo are not permitted',
    };
  }

  return { allowed: true, reason: 'in scope' };
}

/**
 * Track redirect hops and refuse hops off the original scope.
 *
 * @param {URL} originalUrl the first authorized URL of the chain
 * @param {URL} hopUrl the URL returned by the latest redirect Location header
 * @param {object} cfg
 * @returns {ScopeDecision}
 */
function checkRedirectHop(originalUrl, hopUrl, cfg) {
  if (!cfg.options.followRedirects) {
    return { allowed: false, reason: 'redirect-following is disabled' };
  }
  // Re-use the same authorization list as the originating request
  const cfgWithHop = {
    ...cfg,
    authorizedHosts: new Set([
      originalUrl.hostname.toLowerCase(),
      ...cfg.authorizedHosts,
    ]),
  };
  return checkUrl(hopUrl, cfgWithHop);
}

module.exports = {
  DEFAULT_OPTIONS,
  parseUrl,
  checkUrl,
  checkRedirectHop,
  isPrivateIpLiteral,
  isNonRoutableIpV4,
  isNonRoutableIpV6,
};
