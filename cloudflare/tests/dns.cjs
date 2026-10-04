const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const { webcrypto } = require('node:crypto');
const file = process.argv[2] || require('node:path').join(__dirname, '../worker.mjs');
const source = fs.readFileSync(file, 'utf8');
function between(start, end) {
  const a = source.indexOf(start), b = source.indexOf(end, a + start.length);
  assert(a >= 0 && b > a, start);
  return source.slice(a, b);
}
const udp = between('async function forwardataudp(', 'function closeSocketQuietly(');
const resolver = between('\t\tconst target = stripIPv6Brackets(targetHost);', '\t\tconst sourcePort = 10000 +');
const helperStart = source.indexOf('const SSTP_DNS_TIMEOUT_MS =');
const helpers = helperStart < 0 ? '' : source.slice(helperStart, source.indexOf('const SSTP_TCP_MSS =', helperStart));
const writes = [], rawCalls = [], chainCalls = [], sends = [], dohCalls = [];
let failChain = false, closeCount = 0;
const query = Uint8Array.from([0x12,0x34,1,0,0,1,0,0,0,0,0,0,3,100,110,115,7,101,120,97,109,112,108,101,0,0,1,0,1]);
const cat = (...a) => Buffer.concat(a.map(v => Buffer.from(v)));
function dnsReply(q) {
  const ans = Buffer.from([0xc0,0x0c,0,1,0,1,0,0,0,30,0,4,203,0,113,7]);
  const out = cat(q,ans); out[2]=0x81; out[3]=0x80; out[7]=1;
  return out;
}
function socket() {
  let ctl;
  return { opened:Promise.resolve(), closed:Promise.resolve(), close(){closeCount++;try{ctl.close()}catch{}},
    writable:new WritableStream({write(buf){
      writes.push(Buffer.from(buf));
      const wire=dnsReply(Buffer.from(buf).subarray(2));
      const packet=cat(Uint8Array.from([wire.length>>>8,wire.length&255]),wire);
      ctl.enqueue(packet.subarray(0,1)); ctl.enqueue(packet.subarray(1,8)); ctl.enqueue(packet.subarray(8));
      ctl.close();
    }}), readable:new ReadableStream({start(c){ctl=c}})
  };
}
const ctx = vm.createContext({
  Uint8Array,Uint16Array,DataView,TextEncoder,TextDecoder,ReadableStream,WritableStream,
  WeakMap,Map,Set,Promise,Error,Date,URL,crypto:webcrypto,console,
  textEncoder:new TextEncoder(),textDecoder:new TextDecoder(),
  log(){},WebSocket:{OPEN:1},
  '数据转Uint8Array':v=>Uint8Array.from(v), '拼接字节数据':(...a)=>Uint8Array.from(cat(...a)),
  'WebSocket发送并等待':async(_ws,v)=>sends.push(Buffer.from(v)),
  '创建请求TCP连接器':()=>opts=>{rawCalls.push(opts);return socket()},
  sstpConnect:async(proxy,host,port)=>{chainCalls.push({proxy,host,port});if(failChain)throw Error('node offline');return socket()},
  'DoH查询':async(...args)=>{dohCalls.push(args);return [{type:1,data:'203.0.113.7'}]},
  stripIPv6Brackets:v=>String(v).replace(/^\[|\]$/g,''),isIPv4:v=>/^\d+\.\d+\.\d+\.\d+$/.test(v),
  randomSstpUint16:()=>0x1234,
  withTimeout:async p=>p
});
vm.runInContext(helpers+'\n'+udp+'\nasync function auditResolve(targetHost,proxy,TCP连接){'+resolver+'return targetIp}',ctx);
async function test(name,fn){try{await fn();console.log('PASS',name)}catch(e){console.error('FAIL',name,e.message);process.exitCode=1}}
(async()=>{
  const proxy={hostname:'vpn.example',port:443,username:'vpn',password:'vpn'};
  const route={'代理类型':'sstp','代理参数':proxy,'代理全局':true};
  const framed=Uint8Array.from(cat([query.length>>>8,query.length&255],query));
  await test('SSTP UDP DNS does not use direct Worker socket and preserves response header',async()=>{
    await ctx.forwardataudp(framed,{readyState:1},new Uint8Array([0,0]),{},null,route);
    assert.equal(rawCalls.length,0,'direct DNS socket was opened');
    assert.equal(chainCalls.length,1,'SSTP DNS was not called');
    assert.equal(chainCalls[0].host,'8.8.4.4');
    assert.deepEqual(sends[0],cat([0,0],[0,dnsReply(query).length],dnsReply(query)));
  });
  await test('SSTP domain resolves over its exit without Worker DoH',async()=>{
    assert.equal(await ctx.auditResolve('dns.example',proxy,()=>{throw Error('raw DNS bypass')}),'203.0.113.7');
    assert.equal(dohCalls.length,0,'Worker DoH was used');
  });
  await test('IPv4 target does not perform DNS',async()=>{
    const count=chainCalls.length; assert.equal(await ctx.auditResolve('1.1.1.1',proxy,()=>{}),'1.1.1.1');assert.equal(chainCalls.length,count);
  });
  await test('primary resolver failure retries a second resolver over the same residential exit',async()=>{
    const original=ctx.sstpConnect, calls=[], before=rawCalls.length;
    ctx.sstpConnect=async(p,host,port)=>{
      calls.push({p,host,port});
      if(host==='8.8.4.4')throw Error('primary DNS unreachable');
      return socket();
    };
    try{
      const response=await ctx.exchangeSstpDns(query,proxy,()=>{throw Error('direct DNS bypass')});
      assert.deepEqual(Buffer.from(response),dnsReply(query));
      assert.deepEqual(calls.map(c=>c.host),['8.8.4.4','8.8.8.8']);
      assert.ok(calls.every(c=>c.p===proxy && c.port===53));
      assert.equal(rawCalls.length,before);
    }finally{ctx.sstpConnect=original}
  });
  await test('SERVFAIL response retries the secondary resolver instead of failing domain resolution',async()=>{
    const original=ctx.sstpConnect, calls=[];
    ctx.sstpConnect=async(_p,host)=>{
      calls.push(host);
      if(host!=='8.8.4.4')return socket();
      let controller;
      return {close(){try{controller.close()}catch{}},closed:Promise.resolve(),
        readable:new ReadableStream({start(c){controller=c}}),
        writable:new WritableStream({write(buf){
          const reply=dnsReply(Buffer.from(buf).subarray(2));reply[3]=0x82;
          controller.enqueue(Uint8Array.from(cat([reply.length>>>8,reply.length&255],reply)));controller.close();
        }})};
    };
    try{
      assert.deepEqual(Buffer.from(await ctx.exchangeSstpDns(query,proxy,()=>{})),dnsReply(query));
      assert.deepEqual(calls,['8.8.4.4','8.8.8.8']);
    }finally{ctx.sstpConnect=original}
  });
  await test('valid NXDOMAIN is returned without an unnecessary secondary query',async()=>{
    const original=ctx.sstpConnect, calls=[];
    ctx.sstpConnect=async(_p,host)=>{
      calls.push(host);let controller;
      return {close(){try{controller.close()}catch{}},closed:Promise.resolve(),
        readable:new ReadableStream({start(c){controller=c}}),
        writable:new WritableStream({write(buf){
          const reply=Buffer.from(buf).subarray(2);reply[2]=0x81;reply[3]=0x83;
          controller.enqueue(Uint8Array.from(cat([reply.length>>>8,reply.length&255],reply)));controller.close();
        }})};
    };
    try{
      const response=await ctx.exchangeSstpDns(query,proxy,()=>{});
      assert.equal(response[3]&15,3);assert.deepEqual(calls,['8.8.4.4']);
    }finally{ctx.sstpConnect=original}
  });
  await test('primary timeout closes its transport and retries within the original total time budget',async()=>{
    const original=ctx.sstpConnect, originalTimeout=ctx.withTimeout;
    const calls=[],budgets=[],before=closeCount;
    ctx.sstpConnect=async(_p,host,_port,connector)=>{
      calls.push(host);
      if(host==='8.8.4.4'){connector({hostname:host,port:53});return new Promise(()=>{})}
      return socket();
    };
    ctx.withTimeout=(p,ms,message)=>new Promise((resolve,reject)=>{
      budgets.push(ms);const timer=setTimeout(()=>reject(Error(message)),10);
      Promise.resolve(p).then(v=>{clearTimeout(timer);resolve(v)},e=>{clearTimeout(timer);reject(e)});
    });
    try{
      assert.deepEqual(Buffer.from(await ctx.exchangeSstpDns(query,proxy,ctx['创建请求TCP连接器']())),dnsReply(query));
      assert.deepEqual(calls,['8.8.4.4','8.8.8.8']);
      assert.ok(budgets.every(b=>b>0));assert.ok(budgets.reduce((a,b)=>a+b,0)<=12000);
      assert.ok(closeCount>=before+2);
    }finally{ctx.sstpConnect=original;ctx.withTimeout=originalTimeout}
  });
  await test('DNS failure is propagated without direct fallback',async()=>{
    failChain=true; const before=rawCalls.length;
    await assert.rejects(ctx.forwardataudp(framed,{readyState:1},null,{},null,route));
    assert.equal(rawCalls.length,before);
    failChain=false;
  });
  if(helpers){
    await test('DNS framing survives split input and multiple messages',async()=>{
      const ws={readyState:1}, before=chainCalls.length;
      await ctx.forwardataudp(framed.subarray(0,1),ws,new Uint8Array([0,0]),{},null,route);
      assert.equal(chainCalls.length,before);
      await ctx.forwardataudp(Uint8Array.from(cat(framed.subarray(1),framed)),ws,null,{},null,route);
      assert.equal(chainCalls.length,before+2);
    });
    await test('DNS response rejects mismatched ID and malformed compression',async()=>{
      const wrong=dnsReply(query);wrong[1]^=1;
      assert.throws(()=>ctx.parseSstpDnsA(wrong,query),/ID/);
      const bad=dnsReply(query);bad[query.length]=0xc0;bad[query.length+1]=0xff;
      assert.throws(()=>ctx.parseSstpDnsA(bad,query));
    });
    await test('setup timeout closes captured raw transport and rejects within total deadline',async()=>{
      const before=closeCount;
      const original=ctx.sstpConnect, originalTimeout=ctx.withTimeout;
      ctx.sstpConnect=async(_proxy,host,port,connector)=>{connector({hostname:host,port});return new Promise(()=>{})};
      ctx.withTimeout=(p,ms,message)=>new Promise((resolve,reject)=>{
        const timer=setTimeout(()=>reject(Error(message)),20);
        Promise.resolve(p).then(v=>{clearTimeout(timer);resolve(v)},e=>{clearTimeout(timer);reject(e)});
      });
      try{
        await assert.rejects(Promise.race([ctx.exchangeSstpDns(query,proxy,ctx['创建请求TCP连接器']()),new Promise((_,r)=>setTimeout(()=>r(Error('no total deadline')),70))]),/timed out/);
        assert.ok(closeCount>before,'raw socket was left open');
      }finally{ctx.sstpConnect=original;ctx.withTimeout=originalTimeout}
    });
    await test('late setup socket is closed after deadline',async()=>{
      const before=closeCount, original=ctx.sstpConnect, originalTimeout=ctx.withTimeout;
      ctx.sstpConnect=async(_proxy,host,port,connector)=>{
        connector({hostname:host,port}); await new Promise(r=>setTimeout(r,40)); return socket();
      };
      ctx.withTimeout=(p,ms,message)=>new Promise((resolve,reject)=>{
        const timer=setTimeout(()=>reject(Error(message)),15);
        Promise.resolve(p).then(v=>{clearTimeout(timer);resolve(v)},e=>{clearTimeout(timer);reject(e)});
      });
      try{
        await assert.rejects(ctx.exchangeSstpDns(query,proxy,ctx['创建请求TCP连接器']()),/timed out/);
        await new Promise(r=>setTimeout(r,55));
        assert.ok(closeCount>=before+2,'late socket was left open');
      }finally{ctx.sstpConnect=original;ctx.withTimeout=originalTimeout}
    });
    await test('a stalled stream cancel cannot delay successful response or cleanup',async()=>{
      const original=ctx.sstpConnect, before=closeCount;
      ctx.sstpConnect=async()=>{
        let controller;
        return {close(){closeCount++},closed:Promise.resolve(),
          readable:new ReadableStream({start(c){controller=c},cancel(){return new Promise(()=>{})}}),
          writable:new WritableStream({write(buf){
            const wire=dnsReply(Buffer.from(buf).subarray(2));
            controller.enqueue(Uint8Array.from(cat([wire.length>>>8,wire.length&255],wire)));
          }})};
      };
      try{
        const response=await Promise.race([ctx.exchangeSstpDns(query,proxy,()=>{}),new Promise((_,r)=>setTimeout(()=>r(Error('cancel blocked')),30))]);
        assert.deepEqual(Buffer.from(response),dnsReply(query));
        assert.ok(closeCount>before);
      }finally{ctx.sstpConnect=original}
    });
  }
})();
