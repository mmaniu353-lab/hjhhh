const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { webcrypto } = require('node:crypto');

const file = process.argv[2] || path.join(__dirname, '../checker.mjs');
const source = fs.readFileSync(file, 'utf8');
const encode = value => new TextEncoder().encode(value);
const TEST_METADATA_KEY = 'test-fixture-key-for-exit-metadata-authentication-only';
const fixture = {
  ip: '8.8.8.8', ipType: 'ipv4', colo: 'NRT', asn: 2516,
  asOrganization: 'KDDI CORPORATION', country: 'JP', continent: 'AS',
  region: 'Tokyo', city: 'Tokyo', timezone: 'Asia/Tokyo',
};

async function metadataSignature(payload, key = TEST_METADATA_KEY) {
  const cryptoKey = await webcrypto.subtle.importKey('raw', encode(key),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return Buffer.from(await webcrypto.subtle.sign('HMAC', cryptoKey, encode(JSON.stringify(payload)))).toString('hex');
}

function harness(body = fixture, {
  status = 200, chunked = false, invalidJson = false, unsigned = false,
  metadataKey = TEST_METADATA_KEY, signingKey = TEST_METADATA_KEY,
  beforeSign = value => value, afterSign = value => value,
} = {}) {
  const calls = [], requests = [], tlsOptions = [];
  let closes = 0;
  const tunnel = { close() { closes++; } };
  class TargetTls {
    constructor(socket, options) {
      assert.equal(socket, tunnel, 'target TLS must use the selected proxy tunnel');
      tlsOptions.push(options);
      this.chunks = [];
    }
    async handshake() {}
    async write(bytes) {
      const request = new TextDecoder().decode(bytes);
      requests.push(request);
      const requestPath = request.split(' ')[1];
      const nonce = new URL(requestPath, 'https://ch.opopoiovcc.kdns.fr').searchParams.get('nonce');
      let response = body;
      if (!unsigned && !invalidJson) {
        const payload = beforeSign({ metadata: body, nonce, issued_at: Date.now() });
        response = afterSign({ ...payload, signature: await metadataSignature(payload, signingKey) });
      }
      const text = invalidJson ? String(body) : JSON.stringify(response);
      const responseBytes = encode(text);
      const wire = chunked
        ? encode(`HTTP/1.1 ${status} Test\r\nTransfer-Encoding: chunked\r\n\r\n${responseBytes.byteLength.toString(16)}\r\n${text}\r\n0\r\n\r\n`)
        : encode(`HTTP/1.1 ${status} Test\r\nContent-Length: ${responseBytes.byteLength}\r\n\r\n${text}`);
      this.chunks = [wire.subarray(0, 5), wire.subarray(5, 42), wire.subarray(42)];
    }
    async read() { return this.chunks.shift() || null; }
    close() { closes++; }
  }
  const context = vm.createContext({
    TextEncoder, TextDecoder, Uint8Array, Uint16Array, Uint32Array, DataView,
    URL, URLSearchParams, Request, Response, Headers, ReadableStream, WritableStream,
    crypto: webcrypto, console, setTimeout, clearTimeout, atob, btoa,
    __TargetTls: TargetTls,
    connect() { throw Error('unexpected direct Worker socket'); },
    fetch() { throw Error('unexpected direct Worker fetch'); },
  });
  vm.runInContext(source.replace(/^import \{ connect \} from 'cloudflare:sockets';\r?\n/, '')
    .replace('export default {', 'const worker = {')
    + '\nTlsClient = __TargetTls; globalThis.worker = worker;', context, { filename: file });
  for (const name of ['socks5Connect', 'httpConnect', 'httpsConnect', 'turnConnect', 'sstpConnect']) {
    context[name] = async (...args) => { calls.push({ name, args }); return tunnel; };
  }
  return {
    context, calls, requests, tlsOptions,
    get closes() { return closes; },
    check(type = 'sstp', value = 'vpn:vpn@vpn100000.opengw.net:443') {
      return context.checkProxy({ type, value }, 'NRT', metadataKey);
    },
  };
}

test('proxy result normalizes Cloudflare metadata to the existing exit API', async () => {
  const h = harness();
  const result = await h.check();
  assert.equal(result.success, true, result.error);
  assert.equal(result.exit.ip, fixture.ip);
  assert.equal(result.exit.country_code, 'JP');
  assert.equal(result.exit.country, 'Japan');
  assert.equal(result.exit.city, 'Tokyo');
  assert.equal(result.exit.asn.asn, 2516);
  assert.equal(result.exit.asn.name, fixture.asOrganization);
  assert.equal(result.exit.asn.org, fixture.asOrganization);
  assert.equal(result.exit.asn.descr, fixture.asOrganization);
  assert.equal(result.exit.asn.type, null);
  assert.equal(result.username, 'vpn');
  assert.equal(result.password, 'vpn');
  assert.equal(result.colo, 'NRT');
  assert.ok(Number.isFinite(result.responseTime));
});

test('every supported proxy sends the metadata request through its selected tunnel', async () => {
  const cases = [
    ['socks5', 'vpn:vpn@relay.example:1080', 'socks5Connect'],
    ['http', 'vpn:vpn@relay.example:80', 'httpConnect'],
    ['https', 'vpn:vpn@relay.example:443', 'httpConnect'],
    ['https', 'vpn:vpn@8.8.8.8:443', 'httpsConnect'],
    ['turn', 'vpn:vpn@relay.example:3478', 'turnConnect'],
    ['sstp', 'vpn:vpn@vpn100000.opengw.net:443', 'sstpConnect'],
  ];
  for (const [type, address, connector] of cases) {
    const h = harness();
    const result = await h.check(type, address);
    assert.equal(result.success, true, result.error);
    assert.equal(h.calls.length, 1);
    assert.equal(h.calls[0].name, connector);
    assert.equal(h.calls[0].args[1], 'ch.opopoiovcc.kdns.fr');
    assert.equal(h.calls[0].args[2], 443);
    assert.equal(h.tlsOptions[0].serverName, 'ch.opopoiovcc.kdns.fr');
    assert.match(h.requests[0], /^GET \/ip\.json\?nonce=[a-f0-9]{64} HTTP\/1\.1\r\nHost: ch\.opopoiovcc\.kdns\.fr\r\n/);
    assert.doesNotMatch(h.requests[0], /(?:CF-Connecting-IP|X-Forwarded-For|asOrganization|country_code)/);
    assert.ok(h.closes >= 2, 'both target TLS and proxy tunnel must be closed');
  }
});

test('unsigned or forged exit metadata cannot become a successful proxy exit', async () => {
  const options = [
    { unsigned: true },
    { afterSign: value => ({ ...value, metadata: { ...value.metadata, ip: '1.1.1.1', country: 'US' } }) },
    { afterSign: value => ({ ...value, signature: '00'.repeat(32) }) },
    { afterSign: value => ({ ...value, signature: 'not-hex' }) },
    { afterSign: value => ({ ...value, signature: null }) },
    { signingKey: 'a-different-test-only-signing-key' },
  ];
  for (const settings of options) {
    const h = harness(fixture, settings);
    const result = await h.check();
    assert.equal(result.success, false);
    assert.equal(result.exit, undefined);
    assert.match(result.error, /authenticat|signature|signed metadata/i);
    assert.ok(h.closes >= 2);
  }
});

test('signed metadata must match the request nonce and its fresh timestamp', async () => {
  const invalid = [
    value => ({ ...value, nonce: '00'.repeat(32) }),
    value => ({ ...value, nonce: null }),
    value => ({ ...value, issued_at: Date.now() - 61000 }),
    value => ({ ...value, issued_at: Date.now() + 61000 }),
    value => ({ ...value, issued_at: 'not-a-timestamp' }),
    value => ({ ...value, issued_at: null }),
    value => ({ ...value, issued_at: Infinity }),
  ];
  for (const beforeSign of invalid) {
    const result = await harness(fixture, { beforeSign }).check();
    assert.equal(result.success, false);
    assert.equal(result.exit, undefined);
    assert.match(result.error, /nonce|timestamp|fresh|authenticat/i);
  }
});

test('proxy checks fail closed without an exit metadata authentication key', async () => {
  for (const metadataKey of [undefined, null, '', '   ', 123]) {
    const h = harness(fixture, { metadataKey, unsigned: true });
    const result = await h.context.checkProxy({ type: 'sstp', value: 'vpn:vpn@vpn100000.opengw.net:443' }, 'NRT', metadataKey);
    assert.equal(result.success, false);
    assert.equal(result.exit, undefined);
    assert.match(result.error, /authentication key|not configured/i);
    assert.equal(h.calls.length, 0, 'missing-key checks must fail before opening a proxy tunnel');
  }
});

test('each metadata check generates a new cryptographic request nonce', async () => {
  const h = harness();
  assert.equal((await h.check()).success, true);
  assert.equal((await h.check()).success, true);
  const nonces = h.requests.map(request => new URL(request.split(' ')[1], 'https://ch.opopoiovcc.kdns.fr').searchParams.get('nonce'));
  assert.ok(nonces.every(nonce => /^[a-f0-9]{64}$/.test(nonce)));
  assert.notEqual(nonces[0], nonces[1]);
});

test('/check passes the configured key to metadata authentication', async () => {
  const h = harness();
  const request = new Request('https://ch.opopoiovcc.kdns.fr/check?sstp=vpn:vpn@vpn100000.opengw.net:443');
  const response = await h.context.worker.fetch(request, { EXIT_METADATA_KEY: TEST_METADATA_KEY }, {});
  assert.equal((await response.json()).success, true);
  assert.equal(h.calls.length, 1);
});

test('Cloudflare does not supply hosting or privacy intelligence, so flags stay unknown', async () => {
  const h = harness({ ...fixture, is_datacenter: false, privacy: { is_hosting: false } });
  const result = await h.check();
  assert.equal(result.success, true, result.error);
  for (const flag of ['is_datacenter', 'is_crawler', 'is_bogon', 'is_proxy', 'is_vpn', 'is_tor', 'is_abuser', 'is_mobile', 'is_satellite']) {
    assert.equal(result.exit[flag], null, flag);
  }
  for (const flag of ['is_hosting', 'is_bogon', 'is_proxy', 'is_vpn', 'is_tor', 'is_abuser']) {
    assert.equal(result.exit.privacy[flag], null, flag);
  }
});

test('missing or malformed exit metadata fails the proxy check', async () => {
  const invalid = [
    null, [], {}, { ...fixture, ip: null }, { ...fixture, ip: 123 },
    { ...fixture, ip: 'proxy.example' }, { ...fixture, ip: '999.1.1.1' },
    { ...fixture, ip: '8.8.8.8, 1.1.1.1' }, { ...fixture, ip: '008.8.8.8' },
    { ...fixture, country: null }, { ...fixture, country: 'Japan' },
    { ...fixture, country: 'ZZ' }, { ...fixture, country: 'XX' },
    { ...fixture, asn: null }, { ...fixture, asn: 0 }, { ...fixture, asn: -1 },
    { ...fixture, asn: 1.5 }, { ...fixture, asn: 4294967296 },
    { ...fixture, asn: 'AS2516' }, { ...fixture, asn: {} },
    { ...fixture, asOrganization: null }, { ...fixture, asOrganization: '  ' },
    { ...fixture, asOrganization: 123 },
  ];
  for (const metadata of invalid) {
    const h = harness(metadata);
    const result = await h.check();
    assert.equal(result.success, false, JSON.stringify(metadata));
    assert.equal(result.exit, undefined);
    assert.match(result.error, /metadata|IP|country|ASN|organization/i);
    assert.ok(h.closes >= 2);
  }
});

test('special-use and nonpublic IPs cannot become successful proxy exits', async () => {
  const invalid = [
    '0.0.0.0', '10.1.2.3', '100.64.0.1', '127.0.0.1', '169.254.1.2',
    '172.16.0.1', '192.168.1.1', '192.0.2.1', '198.18.0.1',
    '198.51.100.1', '203.0.113.1', '224.0.0.1', '255.255.255.255',
    '::', '::1', 'fc00::1', 'fe80::1', 'ff02::1', '2001:db8::1',
    '3fff::1', '::ffff:192.168.1.1', '[2606:4700:4700::1111]',
  ];
  for (const ip of invalid) {
    const result = await harness({ ...fixture, ip }).check();
    assert.equal(result.success, false, ip);
    assert.match(result.error, /public exit IP/i);
  }
});

test('public IPv6, mapped IPv4, and numeric ASN strings normalize correctly', async () => {
  for (const ip of ['2606:4700:4700::1111', '::ffff:8.8.8.8']) {
    const result = await harness({ ...fixture, ip, asn: '2516', country: 'jp' }).check();
    assert.equal(result.success, true, result.error);
    assert.equal(result.exit.ipType, 'ipv6');
    assert.equal(result.exit.asn.asn, 2516);
    assert.equal(result.exit.country_code, 'JP');
  }
});

test('/ip.json uses the same observed Cloudflare connection for IP and geographic metadata', async () => {
  const h = harness();
  const request = new Request('https://ch.opopoiovcc.kdns.fr/ip.json?ip=1.1.1.1&country=US&asn=15169', {
    headers: { 'CF-Connecting-IP': fixture.ip, 'X-Forwarded-For': '1.1.1.1', 'X-Real-IP': '1.1.1.1', 'True-Client-IP': '1.1.1.1' },
  });
  Object.defineProperty(request, 'cf', { value: fixture });
  const response = await h.context.worker.fetch(request, {}, {});
  assert.equal(response.status, 200);
  const result = await response.json();
  assert.equal(result.ip, fixture.ip);
  assert.equal(result.asn, fixture.asn);
  assert.equal(result.asOrganization, fixture.asOrganization);
  assert.equal(result.country, fixture.country);
  assert.equal(result.city, fixture.city);
  assert.match(response.headers.get('Cache-Control'), /no-store/);
});

test('/ip.json cannot substitute query or forwarding headers when CF-Connecting-IP is missing', async () => {
  const h = harness();
  const request = new Request('https://ch.opopoiovcc.kdns.fr/ip.json?ip=1.1.1.1', {
    headers: { 'X-Forwarded-For': '1.1.1.1', 'X-Real-IP': '1.1.1.1', 'True-Client-IP': '1.1.1.1' },
  });
  Object.defineProperty(request, 'cf', { value: fixture });
  const result = await (await h.context.worker.fetch(request, {}, {})).json();
  assert.equal(result.ip, null);
  assert.equal((await harness(result).check()).success, false);
});

test('/ip.json signs only observed Cloudflare metadata for a valid nonce', async () => {
  const h = harness();
  const nonce = 'ab'.repeat(32);
  const request = new Request(`https://ch.opopoiovcc.kdns.fr/ip.json?nonce=${nonce}&ip=1.1.1.1&country=US&asn=15169`, {
    headers: { 'CF-Connecting-IP': fixture.ip, 'X-Forwarded-For': '1.1.1.1' },
  });
  Object.defineProperty(request, 'cf', { value: fixture });
  const response = await h.context.worker.fetch(request, { EXIT_METADATA_KEY: TEST_METADATA_KEY }, {});
  assert.equal(response.status, 200);
  const result = await response.json();
  assert.ok(result.metadata, 'nonce requests must return a signed metadata envelope');
  assert.equal(result.metadata.ip, fixture.ip);
  assert.equal(result.metadata.asn, fixture.asn);
  assert.equal(result.metadata.country, fixture.country);
  assert.equal(result.nonce, nonce);
  assert.ok(Number.isFinite(result.issued_at) && Math.abs(Date.now() - result.issued_at) < 5000);
  assert.match(result.signature, /^[a-f0-9]{64}$/);
  assert.equal(result.signature, await metadataSignature({ metadata: result.metadata, nonce, issued_at: result.issued_at }));
  assert.match(response.headers.get('Cache-Control'), /no-store/);
  assert.equal(JSON.stringify(result).includes(TEST_METADATA_KEY), false);
});

test('/ip.json rejects malformed nonces with HTTP 400', async () => {
  const h = harness();
  for (const nonce of ['', 'ab', 'a'.repeat(63), 'a'.repeat(65), 'g'.repeat(64)]) {
    const response = await h.context.worker.fetch(new Request(`https://ch.opopoiovcc.kdns.fr/ip.json?nonce=${nonce}`),
      { EXIT_METADATA_KEY: TEST_METADATA_KEY }, {});
    assert.equal(response.status, 400, `nonce length ${nonce.length}`);
    const result = await response.json();
    assert.equal(result.metadata, undefined);
    assert.equal(result.signature, undefined);
  }
});

test('/ip.json refuses signed responses when its secret is missing', async () => {
  const h = harness();
  for (const EXIT_METADATA_KEY of [undefined, null, '', '   ', 123]) {
    const response = await h.context.worker.fetch(new Request(`https://ch.opopoiovcc.kdns.fr/ip.json?nonce=${'ab'.repeat(32)}`),
      { EXIT_METADATA_KEY }, {});
    assert.equal(response.status, 503);
    const result = await response.json();
    assert.equal(result.metadata, undefined);
    assert.equal(result.signature, undefined);
  }
});

test('HTTP errors and invalid JSON fail instead of producing exit metadata', async () => {
  for (const options of [{ status: 429 }, { invalidJson: true }]) {
    const h = harness(options.invalidJson ? 'not-json' : fixture, options);
    const result = await h.check();
    assert.equal(result.success, false);
    assert.equal(result.exit, undefined);
    assert.match(result.error, /\/ip\.json/);
    assert.ok(h.closes >= 2);
  }
});

test('existing chunked HTTP response handling still accepts valid metadata', async () => {
  const result = await harness(fixture, { chunked: true }).check();
  assert.equal(result.success, true, result.error);
  assert.equal(result.exit.country_code, 'JP');
});

test('unknown hosting and privacy flags display as unknown in the existing detail panel', () => {
  const start = source.indexOf('function buildExitStateBadge(');
  const end = source.indexOf('function buildExitDetailRow(', start);
  const context = vm.createContext({});
  vm.runInContext(source.slice(start, end), context);
  assert.match(context.buildExitStateBadge(null, 'warn'), /未知/);
  assert.match(context.buildExitStateBadge(undefined, 'danger'), /未知/);
  assert.match(context.buildExitStateBadge(false, 'warn'), />否</);
  assert.match(context.buildExitStateBadge(true, 'warn'), />是</);
  assert.equal(/buildExitStateBadge\(Boolean\(exitData\?\./.test(source), false, 'detail panel must preserve unknown flags');
});

test('checker has no quota-bound IPLocate lookup dependency', () => {
  assert.equal(/iplocate\.io|\/api\/lookup/i.test(source), false, 'quota-bound lookup dependency is still present');
});
