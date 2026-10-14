'use strict';

/**
 * Demo server pair: a deliberately weak twin and a hardened twin.
 *
 * The CLI demo command starts these on 127.0.0.1, hits them, tears them
 * down. Nothing in this module ever touches external hosts or the network.
 *
 * - Weak  → missing HSTS/CSP/X-Frame-Options/X-Content-Type-Options, leaks Server version.
 * - Hard  → explicit hardening headers set; no version disclosure.
 */

const http = require('node:http');

function startOne(port, mode) {
  return new Promise((resolve, reject) => {
    const handler = (req, res) => {
      if (req.url === '/healthz') {
        res.writeHead(200, { 'content-type': 'text/plain' });
        res.end('ok');
        return;
      }
      const body = `<!doctype html><html><head><title>demo ${mode}</title></head><body><h1>demo-${mode}</h1></body></html>`;
      res.writeHead(200, {
        'content-type': 'text/html; charset=utf-8',
        'content-length': Buffer.byteLength(body),
        ...(mode === 'weak'
          ? {
              // intentionally missing the headers the analyzer looks for
              server: 'Demo/1.0 (Ubuntu)',
              'x-powered-by': 'Express',
            }
          : {
              // hardened twin
              'strict-transport-security': 'max-age=31536000; includeSubDomains',
              'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
              'x-frame-options': 'DENY',
              'x-content-type-options': 'nosniff',
              'referrer-policy': 'strict-origin-when-cross-origin',
              'permissions-policy': 'camera=(), microphone=(), geolocation=()',
              'cross-origin-opener-policy': 'same-origin',
              'cross-origin-embedder-policy': 'require-corp',
              'cross-origin-resource-policy': 'same-site',
              server: 'demo',
            }),
      });
      res.end(body);
    };

    const server = http.createServer(handler);
    server.on('error', reject);
    server.listen(port, '127.0.0.1', () => {
      const actualPort = server.address().port;
      resolve({ server, port: actualPort, mode });
    });
  });
}

async function startDemo() {
  // ports 0 → let the OS assign free ports
  const weak = await startOne(0, 'weak');
  const hard = await startOne(0, 'hard');
  return [weak, hard];
}

function targets(servers) {
  return servers.map((s) => ({
    url: `http://127.0.0.1:${s.port}/`,
    tag: `demo-${s.mode}`,
  }));
}

module.exports = { startDemo, targets };
