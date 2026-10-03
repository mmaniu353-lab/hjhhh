import fs from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';

const source = fs.readFileSync(new URL('../worker.mjs', import.meta.url), 'utf8');
const host = 'fgfg.opopoiovcc.kdns.fr';
const uuid = '11111111-1111-4111-8111-111111111111';
const payload = '{"mixed-port":10808,"proxies":[],"rules":["MATCH,DIRECT"]}';

function fixture(value = payload) {
  const reads = [];
  const context = vm.createContext({
    URL, URLSearchParams, Request, Response, Headers, TextEncoder, TextDecoder,
    crypto: webcrypto, console, setTimeout, clearTimeout,
    btoa: value => Buffer.from(value, 'binary').toString('base64'),
    atob: value => Buffer.from(value, 'base64').toString('binary'),
    fetch: async () => new Response('original endpoint', { status: 404 }),
  });
  vm.runInContext(source.replace('export default {', 'globalThis.worker = {'), context);
  context.MD5MD5 = async value => value === host + uuid ? 'owner-token' : 'backend-token';
  context.getResidentialSubscription = async () => new Response('original residential configuration');
  const env = { ADMIN: 'test-admin', UUID: uuid, KV: { async get(key) { reads.push(key); return value; } } };
  const call = async query => {
    const request = new Request('https://' + host + '/sub?' + query, { headers: { 'User-Agent': 'v2rayN/7.17' } });
    request.cf = { colo: 'NRT' };
    return context.worker.fetch(request, env, { waitUntil() {} });
  };
  return { call, reads };
}

test('owner receives the exact private acceleration configuration', async () => {
  const { call, reads } = fixture();
  const response = await call('token=owner-token&target=clash&profile=japan-relay');
  assert.equal(response.status, 200);
  assert.equal(await response.text(), payload);
  assert.deepEqual(reads, ['subscription-japan-relay.json']);
  assert.equal(response.headers.get('Cache-Control'), 'private, no-store');
  assert.match(response.headers.get('Content-Type'), /application\/json/);
});

for (const token of ['', 'wrong-token', 'backend-token']) {
  test('private profile rejects non-owner token: ' + (token || 'missing'), async () => {
    const { call, reads } = fixture();
    const response = await call('token=' + token + '&profile=japan-relay');
    assert.equal(response.status, 403);
    assert.equal(reads.length, 0);
    assert.ok(!(await response.text()).includes('mixed-port'));
  });
}

test('missing stored profile fails without returning an unrelated subscription', async () => {
  const { call } = fixture(null);
  const response = await call('token=owner-token&profile=japan-relay');
  assert.equal(response.status, 503);
});

test('ordinary residential subscription keeps its existing behavior', async () => {
  const { call, reads } = fixture();
  const response = await call('token=owner-token&target=clash');
  assert.equal(response.status, 200);
  assert.equal(await response.text(), 'original residential configuration');
  assert.equal(reads.length, 0);
});
