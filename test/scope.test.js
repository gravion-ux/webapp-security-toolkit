'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  parseUrl,
  checkUrl,
  isNonRoutableIpV4,
  isNonRoutableIpV6,
} = require('../src/scope');

const defaultCfg = (host, options) => ({
  authorizedHosts: new Set([host]),
  options: {
    allowLoopback: false,
    allowPrivate: false,
    allowLinkLocal: false,
    followRedirects: false,
    maxHops: 5,
    ...(options || {}),
  },
});

test('parseUrl: accepts http and https', () => {
  const a = parseUrl('https://example.com/');
  assert.equal(a.ok, true);
  assert.equal(a.value.protocol, 'https:');
  const b = parseUrl('http://example.com/');
  assert.equal(b.ok, true);
  assert.equal(b.value.protocol, 'http:');
});

test('parseUrl: rejects ftp', () => {
  const r = parseUrl('ftp://example.com/');
  assert.equal(r.ok, false);
  assert.match(r.error, /http or https/);
});

test('parseUrl: rejects malformed', () => {
  const r = parseUrl('not-a-url');
  assert.equal(r.ok, false);
});

test('parseUrl: rejects empty', () => {
  assert.equal(parseUrl('').ok, false);
  assert.equal(parseUrl(undefined).ok, false);
});

test('isNonRoutableIpV4: private and loopback ranges', () => {
  for (const ip of ['10.0.0.1', '172.16.5.5', '172.31.255.255', '192.168.1.10', '127.0.0.1', '127.255.255.254', '169.254.0.5', '0.0.0.0', '224.1.2.3', '100.64.0.1']) {
    assert.equal(isNonRoutableIpV4(ip), true, ip);
  }
});

test('isNonRoutableIpV4: public range is not private', () => {
  for (const ip of ['8.8.8.8', '1.1.1.1', '9.9.9.9', '93.184.216.34']) {
    assert.equal(isNonRoutableIpV4(ip), false, ip);
  }
});

test('isNonRoutableIpV6: link-local, ULA, loopback are private', () => {
  for (const ip of ['::1', '::', 'fe80::1', 'fc00::1', 'fd00::beef', 'ff02::1']) {
    assert.equal(isNonRoutableIpV6(ip), true, ip);
  }
  assert.equal(isNonRoutableIpV6('2606:4700:4700::1111'), false);
});

test('checkUrl: refuses hosts not in allow-list', () => {
  const u = new URL('https://example.com/');
  const d = checkUrl(u, defaultCfg('example.com'));
  assert.equal(d.allowed, true);
  const d2 = checkUrl(u, defaultCfg('other.example.com'));
  assert.equal(d2.allowed, false);
  assert.match(d2.reason, /not in the operator's allow-list/);
});

test('checkUrl: blocks loopback by default', () => {
  const u = new URL('http://127.0.0.1:8000/');
  const d = checkUrl(u, defaultCfg('127.0.0.1'));
  assert.equal(d.allowed, false);
  assert.match(d.reason, /loopback/);
});

test('checkUrl: allows loopback only with flag', () => {
  const u = new URL('http://127.0.0.1:8000/');
  const cfg = defaultCfg('127.0.0.1', { allowLoopback: true });
  const d = checkUrl(u, cfg);
  assert.equal(d.allowed, true);
});

test('checkUrl: blocks RFC1918 with explicit msg', () => {
  const u = new URL('http://10.0.0.1/');
  const d = checkUrl(u, defaultCfg('10.0.0.1'));
  assert.equal(d.allowed, false);
  assert.match(d.reason, /private/);
});

test('checkUrl: allows RFC1918 only with --allow-private', () => {
  const u = new URL('http://10.0.0.1/');
  const cfg = defaultCfg('10.0.0.1', { allowPrivate: true });
  assert.equal(checkUrl(u, cfg).allowed, true);
});

test('checkUrl: blocks link-local separately', () => {
  const u = new URL('http://169.254.169.254/');
  const cfg = defaultCfg('169.254.169.254', { allowPrivate: true });
  const d = checkUrl(u, cfg);
  assert.equal(d.allowed, false);
  assert.match(d.reason, /link-local/);

  const cfg2 = defaultCfg('169.254.169.254', { allowPrivate: true, allowLinkLocal: true });
  assert.equal(checkUrl(u, cfg2).allowed, true);
});

test('checkUrl: refuses URLs with userinfo', () => {
  const u = new URL('https://user:pass@example.com/'); // URL will normalize user/pass
  const cfg = defaultCfg('example.com');
  const d = checkUrl(u, cfg);
  assert.equal(d.allowed, false);
  assert.match(d.reason, /userinfo/);
});

test('checkUrl: public IP is allowed', () => {
  const u = new URL('https://93.184.216.34/');
  const cfg = defaultCfg('93.184.216.34');
  const d = checkUrl(u, cfg);
  assert.equal(d.allowed, true);
});
