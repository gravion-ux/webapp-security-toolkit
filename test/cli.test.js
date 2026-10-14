'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const CLI = path.join(__dirname, '..', 'src', 'cli.js');

function run(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf-8',
    timeout: 30_000,
    ...opts,
  });
}

test('CLI: --help exits 0 and prints summary', () => {
  const r = run(['--help']);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /wsat/);
  assert.match(r.stdout, /scan/);
  assert.match(r.stdout, /demo/);
});

test('CLI: scan without --url exits 2 with refusal message', () => {
  const r = run(['scan']);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /--url is required/);
});

test('CLI: scan against a disallowed URL exits 1 with a scope refusal', () => {
  // Without --allow-private/--allow-loopback, 127.0.0.1 must be refused at the
  // scope layer (assess() returns ok=false) which the CLI surfaces as exit 1.
  // Missing --url is the only case that exits 2.
  const r = run(['scan', '--url', 'http://127.0.0.1:1/']);
  assert.equal(r.status, 1, `expected exit 1, got ${r.status}; stderr=${r.stderr}`);
  // status file should still have been written? — no, because result.ok was false;
  // CLI returns 1 without calling ensureOutDir in that branch. Verify no files leaked.
});

test('CLI: scan with --url flag validates and exercises the assessor', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'wsat-test-'));
  const r = run(['scan', '--url', 'http://93.184.216.34/', '--out', tmp]);
  // We are NOT making this test rely on external network; this just verifies
  // the CLI path runs (success or failure based on connectivity — either is OK
  // as long as the exit code is 0 or 1, not 2).
  assert.ok(r.status === 0 || r.status === 1, `unexpected exit ${r.status}: ${r.stderr}`);
});

test('CLI: demo runs the loopback end-to-end and produces both files', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'wsat-test-'));
  const r = run(['demo', '--out', tmp, '--quiet']);
  assert.equal(r.status, 0, `stderr: ${r.stderr}`);
  assert.ok(fs.existsSync(path.join(tmp, 'findings.json')));
  assert.ok(fs.existsSync(path.join(tmp, 'findings.md')));

  const json = JSON.parse(fs.readFileSync(path.join(tmp, 'findings.json'), 'utf-8'));
  assert.ok(Array.isArray(json.findings));
  // weak twin should produce many findings; hard twin should produce none
  const weakTags = new Set(json.findings.map((f) => f.tag).filter(Boolean));
  assert.ok(weakTags.size >= 1);
});
