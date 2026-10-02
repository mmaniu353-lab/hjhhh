const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const test = require('node:test');
const source = fs.readFileSync(require('node:path').join(__dirname, '../worker.mjs'), 'utf8');
const start = source.indexOf('const RESIDENTIAL_CONFIG_URL =');
const end = source.indexOf('function Clash订阅配置文件热补丁(', start);
assert(start >= 0 && end > start, 'Residential subscription handler is missing');
const context = vm.createContext({ URL, Response, Headers, AbortController, TextEncoder,
  setTimeout: (fn, milliseconds) => setTimeout(fn, Math.min(milliseconds, 30)), clearTimeout });
vm.runInContext(source.slice(start, end), context);
const headers = new Headers();
const url = query => new URL('https://fgfg.opopoiovcc.kdns.fr/sub?token=private-token' + query);
const profile = 'mixed-port: 2087\ntun:\n  strict-route: true\ndns:\n  nameserver:\n  - tcp://8.8.4.4:53#住宅出口\nproxy-providers:\n  住宅节点:\n    url: https://mmaniu353-lab.github.io/hjhhh/proxies.yaml\n';
test('subscription access requires the existing user authentication and project host', () => {
  assert.equal(context.isResidentialSubscription('fgfg.opopoiovcc.kdns.fr', false, url(''), 'FlClash', headers), false);
  assert.equal(context.isResidentialSubscription('other.example', true, url(''), 'FlClash', headers), false);
  assert.equal(context.isResidentialSubscription('fgfg.opopoiovcc.kdns.fr', true, url(''), 'FlClash', headers), true);
});
test('explicit format is honored, and browsers can request the full Clash profile', () => {
  assert.equal(context.isResidentialSubscription('fgfg.opopoiovcc.kdns.fr', true, url('&target=clash'), 'Mozilla/5.0', headers), true);
  assert.equal(context.isResidentialSubscription('fgfg.opopoiovcc.kdns.fr', true, url('&target=mixed'), 'FlClash', headers), false);
  assert.equal(context.isResidentialSubscription('fgfg.opopoiovcc.kdns.fr', true, url(''), 'sing-box', headers), false);
});
test('converter and custom source requests preserve the legacy format path', () => {
  for (const query of ['&b64', '&base64', '&sub=other.example']) {
    assert.equal(context.isResidentialSubscription('fgfg.opopoiovcc.kdns.fr', true, url(query), 'FlClash', headers), false);
  }
  assert.equal(context.isResidentialSubscription('fgfg.opopoiovcc.kdns.fr', true, url(''), 'Subconverter Clash', headers), false);
  assert.equal(context.isResidentialSubscription('fgfg.opopoiovcc.kdns.fr', true, url(''), 'Clash', new Headers({'subconverter-request':'1'})), false);
});
test('authenticated subscription delivers the strict profile without forwarding the token', async () => {
  let requested;
  const result = await context.getResidentialSubscription({'Subscription-Userinfo':'upload=0; download=0'}, async (address, options) => {
    requested={address, options}; return new Response(profile);
  });
  assert.equal(result.status, 200);
  assert.equal(await result.text(), profile);
  assert.equal(requested.address, 'https://mmaniu353-lab.github.io/hjhhh/mihomo.yaml');
  assert.equal(requested.options.redirect, 'manual', 'Cloudflare fetch only supports manual or follow');
  assert(!JSON.stringify(requested).includes('private-token'));
  assert.equal(result.headers.get('Content-Type'), 'application/x-yaml; charset=utf-8');
  assert.equal(result.headers.get('Cache-Control'), 'no-store');
  assert.equal(result.headers.get('Profile-Update-Interval'), '1');
});
test('upstream failure returns retryable failure instead of the old DNS template', async () => {
  const result = await context.getResidentialSubscription({}, async () => new Response('offline', {status:503}));
  assert.equal(result.status, 503);
  assert.equal(result.headers.get('Retry-After'), '60');
  assert(!(await result.text()).includes('fallback:'));
});
test('HTML or malformed upstream output is rejected', async () => {
  const result = await context.getResidentialSubscription({}, async () => new Response('<html>error</html>'));
  assert.equal(result.status, 503);
});
test('the total deadline covers a stalled response body and aborts the upstream', async () => {
  let signal;
  const result = await context.getResidentialSubscription({}, async (_address, options) => {
    signal=options.signal;
    return {ok:true, text:()=>new Promise(()=>{})};
  });
  assert.equal(result.status, 503);
  assert(signal.aborted);
});
