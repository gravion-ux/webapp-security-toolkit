#!/usr/bin/env node
'use strict';

/**
 * Command-line entry point.
 *
 * Usage:
 *   wsat scan --url <authorized-url> [--out <dir>] [--allow-loopback] [--allow-private]
 *   wsat demo [--out <dir>]
 *
 * Both `scan` and `demo` write `findings.json` and `findings.md`
 * into the chosen output directory.
 *
 * No environment variables are read; no network calls happen unless
 * the operator passes --url (or runs `demo`, which talks only to
 * 127.0.0.1 via a server this CLI starts and tears down itself).
 */

const fs = require('node:fs');
const path = require('node:path');
const { assess } = require('./index');
const { buildFinding, toJson, toMarkdown, severitySummary, sortFindings } = require('./findings');

const HELP = `Web application security assessment toolkit (wsat)

Usage:
  wsat scan --url <authorized-url> [--out <dir>] [options]
  wsat demo [--out <dir>]
  wsat --help

Scan options:
  --url <url>            Authorized target URL (https or http).
  --out <dir>            Output directory for findings.json and findings.md.
                         (default: ./wsat-report)
  --allow-loopback       Allow loopback hosts (127.0.0.1, ::1).
  --allow-private        Allow RFC1918 / ULA private hosts.
  --allow-link-local     Allow 169.254.0.0/16 link-local hosts.
  --follow               Follow redirects (still inside authorized host).
  --budget <n>           Total HTTP requests allowed per run (default: 25).
  --timeout <ms>         Per-request timeout (default: 8000).
  --header <Name:Value>  Extra request header. May be repeated. Cookie /
                         Authorization / Proxy-Authorization are stripped.
  --json                 Emit JSON to stdout in addition to writing files.
  --quiet                Suppress the per-finding stdout summary.

Notes:
  Without --url, wsat refuses to dial anywhere.

Demo:
  wsat demo spins up two local services and assesses them — never
  leaves 127.0.0.1.
`;

async function main(argv) {
  const args = argv.slice(2);

  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    process.stdout.write(HELP);
    return 0;
  }

  const command = args[0];

  if (command === 'demo') return await runDemo(args.slice(1));
  if (command === 'scan') return await runScan(args.slice(1));

  process.stderr.write(`Unknown command: ${command}\nRun \`wsat --help\`.\n`);
  return 2;
}

async function runScan(args) {
  const opts = parseScanArgs(args);
  if (!opts.ok) {
    process.stderr.write(opts.error);
    process.stderr.write('\n');
    return 2;
  }

  // safety: refuse to dial anywhere without an explicit --url
  if (!opts.url) {
    process.stderr.write('Refusing to run: --url is required.\n');
    return 2;
  }

  const result = await assess(opts.url, {
    allowLoopback: opts.allowLoopback,
    allowPrivate: opts.allowPrivate,
    allowLinkLocal: opts.allowLinkLocal,
    followRedirects: opts.followRedirects,
    requestBudget: opts.budget,
    timeoutMs: opts.timeout,
    headers: opts.headers,
  });

  ensureOutDir(opts.out);
  const meta = { target: result.url, generatedAt: new Date().toISOString() };
  fs.writeFileSync(path.join(opts.out, 'findings.json'), toJson(result.findings, meta));
  fs.writeFileSync(path.join(opts.out, 'findings.md'), toMarkdown(result.findings, meta));

  if (!opts.quiet) {
    printSummary('SCAN', result.findings, opts.url);
  }
  if (opts.json) {
    process.stdout.write(toJson(result.findings, meta) + '\n');
  }

  return result.ok ? 0 : 1;
}

async function runDemo(args) {
  const opts = parseDemoArgs(args);

  const demo = require('./demo/server');
  const servers = await demo.startDemo();

  const targets = demo.targets(servers);
  const allFindings = [];
  for (const t of targets) {
    const r = await assess(t.url, {
      allowLoopback: true,
      followRedirects: false,
      requestBudget: 5,
      timeoutMs: 4000,
    });
    r.findings.forEach((f) => f.tag = t.tag);
    allFindings.push(...r.findings);
  }

  for (const s of servers) s.server.close();

  ensureOutDir(opts.out);
  const meta = { target: 'wsat-demo (loopback)', generatedAt: new Date().toISOString() };
  fs.writeFileSync(path.join(opts.out, 'findings.json'), toJson(allFindings, meta));
  fs.writeFileSync(path.join(opts.out, 'findings.md'), toMarkdown(allFindings, meta));

  if (!opts.quiet) {
    printSummary('DEMO', allFindings, 'loopback twin services');
  }
  return 0;
}

function printSummary(label, findings, target) {
  const counts = severitySummary(findings);
  process.stdout.write(`\n[${label}] target=${target}\n`);
  for (const sev of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']) {
    if (counts[sev] > 0) process.stdout.write(`  ${sev}: ${counts[sev]}\n`);
  }
  process.stdout.write('\n');
  const sorted = sortFindings(findings);
  for (const f of sorted) {
    const observed = f.observedValue != null ? ` observed=${JSON.stringify(f.observedValue)}` : '';
    process.stdout.write(`[${f.severity}] ${f.id}  — ${f.title}${observed}\n`);
    process.stdout.write(`        ${f.url}\n`);
    process.stdout.write(`        evidence: ${truncate(f.evidence, 120)}\n`);
    process.stdout.write(`        fix: ${truncate(f.remediation, 120)}\n\n`);
  }
}

function truncate(s, n) {
  s = String(s);
  return s.length <= n ? s : `${s.slice(0, n - 1)}…`;
}

function parseScanArgs(args) {
  const opts = { ok: true, headers: {}, url: null, out: 'wsat-report', budget: 25, timeout: 8000 };
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i];
    if (a === '--url') { opts.url = args[++i]; continue; }
    if (a === '--out') { opts.out = args[++i]; continue; }
    if (a === '--allow-loopback') { opts.allowLoopback = true; continue; }
    if (a === '--allow-private') { opts.allowPrivate = true; continue; }
    if (a === '--allow-link-local') { opts.allowLinkLocal = true; continue; }
    if (a === '--follow') { opts.followRedirects = true; continue; }
    if (a === '--budget') { opts.budget = Number.parseInt(args[++i], 10); continue; }
    if (a === '--timeout') { opts.timeout = Number.parseInt(args[++i], 10); continue; }
    if (a === '--json') { opts.json = true; continue; }
    if (a === '--quiet') { opts.quiet = true; continue; }
    if (a === '--header') {
      const raw = args[++i] || '';
      const idx = raw.indexOf(':');
      if (idx < 0) return { ok: false, error: `--header expects Name:Value (got "${raw}")` };
      const name = raw.slice(0, idx).trim();
      const value = raw.slice(idx + 1).trim();
      opts.headers[name] = value;
      continue;
    }
    return { ok: false, error: `unknown flag: ${a}` };
  }
  if (!opts.url) return { ok: false, error: '--url is required' };
  return opts;
}

function parseDemoArgs(args) {
  const opts = { out: 'wsat-demo-report' };
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i];
    if (a === '--out') { opts.out = args[++i]; continue; }
    if (a === '--quiet') { opts.quiet = true; continue; }
  }
  return opts;
}

function ensureOutDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

main(process.argv)
  .then((code) => process.exit(typeof code === 'number' ? code : 0))
  .catch((err) => {
    process.stderr.write(`fatal: ${err && err.message ? err.message : err}\n`);
    process.exit(1);
  });
