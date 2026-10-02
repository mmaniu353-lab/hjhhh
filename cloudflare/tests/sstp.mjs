import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, socketMock, loadSection, control, ppp, remoteTcp, encode, pause, consume, lastAck, concat, decode } from './harness.mjs';

test('data followed by a coalesced link echo reaches application without another TCP packet', async () => {
  const value = await fixture();
  try {
    const reader = value.conn.readable.getReader();
    value.mock.push(concat(remoteTcp(value.mock.sourcePort, 1001, 0x18, encode('AAA')), control(8)));
    const next = await Promise.race([reader.read(), pause(30).then(() => null)]);
    assert.ok(next, 'application must receive data before another packet or idle timeout');
    assert.equal(decode(next.value), 'AAA');
    reader.releaseLock();
  } finally { value.cleanup(); }
});

test('writable abort rejects the closed promise', async () => {
  const value = await fixture();
  try {
    const rejection = assert.rejects(value.conn.closed, /test abort/);
    await value.conn.writable.abort(new Error('test abort'));
    await rejection;
  } finally { value.cleanup(); }
});

test('local FIN consumes one sequence before later ACK', async () => {
  const value = await fixture();
  try {
    await value.conn.writable.getWriter().close();
    const fin = value.mock.tcpWrites.find(item => item.flags & 1);
    value.mock.push(remoteTcp(value.mock.sourcePort, 1001, 0x18, encode('AAA')));
    await pause(4);
    const ack = value.mock.tcpWrites.at(-1);
    assert.equal(ack.sequence, (fin.sequence + 1) >>> 0);
  } finally { value.cleanup(); }
});

for (const stageEcho of ['ppp', 'tcp', 'established']) {
  test(`answers PPP and SSTP echo during ${stageEcho}`, async () => {
    const value = await fixture({ stageEcho });
    try {
      if (stageEcho === 'established') {
        value.mock.push(control(8));
        value.mock.push(ppp(0xc021, 9, 99, new Uint8Array([1, 2, 3, 4, 65, 66])));
      }
      await pause(4);
      assert.ok(value.mock.linkWrites.some(item => item.type === 9), 'SSTP EchoResponse must be sent');
      const echo = value.mock.linkWrites.find(item => item.protocol === 0xc021 && item.code === 10);
      assert.ok(echo, 'LCP EchoReply must be sent');
      assert.equal(echo.id, 99);
      assert.deepEqual([...echo.payload], [0, 0, 0, 0, 65, 66], 'local Magic-Number is zero; trailing echo data is preserved');
    } finally { value.cleanup(); }
  });
}

test('ordered data and piggyback FIN still deliver exactly once', async () => {
  const value = await fixture();
  try {
    value.mock.push(remoteTcp(value.mock.sourcePort, 1001, 0x18, encode('AAA')));
    value.mock.push(remoteTcp(value.mock.sourcePort, 1004, 0x19, encode('BBB')));
    assert.equal(await consume(value.conn), 'AAABBB');
    assert.equal(lastAck(value.mock), 1008);
  } finally { value.cleanup(); }
});

test('duplicate TCP data is acknowledged without duplicate application bytes', async () => {
  const value = await fixture();
  try {
    value.mock.push(remoteTcp(value.mock.sourcePort, 1001, 0x18, encode('AAA')));
    value.mock.push(remoteTcp(value.mock.sourcePort, 1001, 0x18, encode('AAA')));
    value.mock.push(remoteTcp(value.mock.sourcePort, 1004, 0x19, encode('BBB')));
    assert.equal(await consume(value.conn), 'AAABBB');
  } finally { value.cleanup(); }
});

test('out-of-order data does not ACK or deliver across the missing range', async () => {
  const value = await fixture();
  try {
    value.mock.push(remoteTcp(value.mock.sourcePort, 1004, 0x18, encode('BBB')));
    await pause(3);
    assert.equal(lastAck(value.mock), 1001, 'gap requires duplicate cumulative ACK');
    value.mock.push(remoteTcp(value.mock.sourcePort, 1001, 0x18, encode('AAA')));
    value.mock.push(remoteTcp(value.mock.sourcePort, 1004, 0x18, encode('BBB')));
    value.mock.push(remoteTcp(value.mock.sourcePort, 1007, 0x11));
    assert.equal(await consume(value.conn), 'AAABBB');
    const acks = value.mock.tcpWrites.filter(item => item.flags & 16).map(item => item.ack);
    assert.ok(acks.every((ack, index) => index === 0 || ((ack - acks[index - 1]) | 0) >= 0), 'ACK must not move backward');
  } finally { value.cleanup(); }
});

test('overlapping retransmission trims already-delivered bytes', async () => {
  const value = await fixture();
  try {
    value.mock.push(remoteTcp(value.mock.sourcePort, 1001, 0x18, encode('AAA')));
    value.mock.push(remoteTcp(value.mock.sourcePort, 1003, 0x19, encode('ABBB')));
    assert.equal(await consume(value.conn), 'AAABBB');
    assert.equal(lastAck(value.mock), 1008);
  } finally { value.cleanup(); }
});

test('buffered overlaps merge without duplicate bytes', async () => {
  const value = await fixture();
  try {
    value.mock.push(remoteTcp(value.mock.sourcePort, 1005, 0x18, encode('BB')));
    value.mock.push(remoteTcp(value.mock.sourcePort, 1004, 0x18, encode('BBB')));
    value.mock.push(remoteTcp(value.mock.sourcePort, 1001, 0x18, encode('AAA')));
    value.mock.push(remoteTcp(value.mock.sourcePort, 1007, 0x11));
    assert.equal(await consume(value.conn), 'AAABBB');
  } finally { value.cleanup(); }
});

test('FIN arriving before missing data waits for its contiguous sequence', async () => {
  const value = await fixture();
  try {
    let closed = false;
    value.conn.closed.finally(() => { closed = true; }).catch(() => {});
    value.mock.push(remoteTcp(value.mock.sourcePort, 1007, 0x11));
    await pause(3);
    assert.equal(closed, false, 'out-of-order FIN must not truncate the stream');
    value.mock.push(remoteTcp(value.mock.sourcePort, 1004, 0x18, encode('BBB')));
    value.mock.push(remoteTcp(value.mock.sourcePort, 1001, 0x18, encode('AAA')));
    assert.equal(await consume(value.conn), 'AAABBB');
    assert.equal(lastAck(value.mock), 1008);
  } finally { value.cleanup(); }
});

test('TCP receive ordering and FIN survive32-bit sequence wrap', async () => {
  const value = await fixture({ remoteIsn: 0xfffffff9 });
  try {
    value.mock.push(remoteTcp(value.mock.sourcePort, 0xfffffffd, 0x18, encode('BBB')));
    value.mock.push(remoteTcp(value.mock.sourcePort, 0xfffffffa, 0x18, encode('AAA')));
    value.mock.push(remoteTcp(value.mock.sourcePort, 0, 0x11));
    assert.equal(await consume(value.conn), 'AAABBB');
    assert.equal(lastAck(value.mock), 1);
  } finally { value.cleanup(); }
});

for (const type of [3, 5, 6]) {
  test(`SSTP terminal control0x${type.toString(16)} rejects promptly`, async () => {
    const value = await fixture();
    try {
      const observed = value.conn.closed.then(() => null, error => error);
      value.mock.push(control(type));
      const result = await Promise.race([observed, pause(8).then(() => 'late')]);
      assert.notEqual(result, 'late', 'terminal control must not wait for the read timeout');
      assert.ok(result instanceof Error);
      if (type === 6) assert.ok(value.mock.linkWrites.some(item => item.type === 7), 'DisconnectAck must be sent');
    } finally { value.cleanup(); }
  });
}

test('LCP TerminateRequest is acknowledged and closes promptly', async () => {
  const value = await fixture();
  try {
    const observed = value.conn.closed.then(() => null, error => error);
    value.mock.push(ppp(0xc021, 5, 88, encode('bye')));
    const result = await Promise.race([observed, pause(8).then(() => 'late')]);
    assert.notEqual(result, 'late');
    assert.ok(result instanceof Error);
    const ack = value.mock.linkWrites.find(item => item.protocol === 0xc021 && item.code === 6);
    assert.ok(ack); assert.equal(ack.id, 88);
  } finally { value.cleanup(); }
});

test('LCP termination during setup is explicit rather than a later timeout', async () => {
  const runtime = loadSection(), mock = socketMock({ setupTerminate: true });
  try {
    await assert.rejects(runtime.connect({ hostname: 'mock.invalid', port: 443, username: 'vpn', password: 'vpn' }, '203.0.113.1', 443, () => mock.socket).then(conn => { conn.closed.catch(() => {}); return conn; }), /terminat/i);
    assert.ok(mock.linkWrites.some(item => item.protocol === 0xc021 && item.code === 6));
  } finally { mock.socket.close(); runtime.cleanup(); }
});

test('acceptable TCP RST rejects the connection promptly', async () => {
  const value = await fixture();
  try {
    const observed = value.conn.closed.then(() => null, error => error);
    value.mock.push(remoteTcp(value.mock.sourcePort, 1001, 0x14));
    const result = await Promise.race([observed, pause(8).then(() => 'late')]);
    assert.notEqual(result, 'late');
    assert.match(result?.message || '', /reset/i);
  } finally { value.cleanup(); }
});

test('lost initial SYN is resent with the same ISN and one pending read', async () => {
  const value = await fixture({ dropInitialSyn: true });
  try {
    const syns = value.mock.tcpWrites.filter(item => item.flags === 2);
    assert.ok(syns.length >= 2);
    assert.ok(syns.every(item => item.sequence === syns[0].sequence), 'retransmissions must reuse the ISN');
    assert.equal(value.mock.metrics.maxActiveReads, 1, 'only one socket read may remain pending');
  } finally { value.cleanup(); }
});

test('SYNACK with the wrong ACK cannot establish the connection', async () => {
  const runtime = loadSection(), mock = socketMock({ malformedSynAck: true });
  try {
    await assert.rejects(runtime.connect({ hostname: 'mock.invalid', port: 443, username: 'vpn', password: 'vpn' }, '203.0.113.1', 443, () => mock.socket).then(conn => { conn.closed.catch(() => {}); return conn; }), /timeout|timed out/i);
  } finally { mock.socket.close(); runtime.cleanup(); }
});
