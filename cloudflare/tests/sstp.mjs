import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, socketMock, loadSection, control, ppp, remoteTcp, encode, pause, consume, lastAck, concat, decode, flushTasks } from './harness.mjs';

const outgoingData = mock => mock.tcpWrites.filter(item => item.bytes.byteLength);
const acknowledge = (value, ack, window = 65535, sequence = 1001) => value.mock.push(remoteTcp(value.mock.sourcePort, sequence, 0x10, new Uint8Array(), ack >>> 0, window));

test('target TCP keepalive prevents an eighty-second NAT expiry while PPP remains alive', async () => {
  const value = await fixture({ manualTimers: true });
  const reader = value.conn.readable.getReader();
  try {
    const first = encode('data:start\n\n'), last = encode('data:finish\n\n');
    const nextRemoteSequence = 1001 + first.byteLength;
    value.mock.push(remoteTcp(value.mock.sourcePort, 1001, 0x18, first, value.mock.localSequence));
    assert.equal(decode((await reader.read()).value), decode(first));
    let lastTcpActivitySecond = 0, observedWrites = value.mock.tcpWrites.length, expired = false;
    for (let second = 1; second <= 90; second++) {
      // SoftEther PPP keepalives remain active even when target TCP is idle.
      if (second % 5 === 0) value.mock.push(ppp(0xc021, 9, 77, new Uint8Array([1, 2, 3, 4])));
      await value.runtime.advance(1000);
      if (value.mock.tcpWrites.length !== observedWrites) {
        observedWrites = value.mock.tcpWrites.length;
        lastTcpActivitySecond = second;
      }
      if (second - lastTcpActivitySecond >= 80) {
        expired = true;
        value.mock.push(remoteTcp(value.mock.sourcePort, nextRemoteSequence, 0x04));
        await flushTasks();
        break;
      }
    }
    assert.equal(expired, false, 'link echoes alone must not leave target TCP idle until the NAT sends RST');
    value.mock.push(remoteTcp(value.mock.sourcePort, nextRemoteSequence, 0x18, last, value.mock.localSequence));
    assert.equal(decode((await reader.read()).value), decode(last));
    assert.equal(value.mock.receivedBytes.byteLength, 0, 'keepalive must not add application data');
  } finally { reader.releaseLock(); value.cleanup(); }
});

test('an idle TCP probe uses SND.NXT minus one across wrap without consuming sequence space', async () => {
  const value = await fixture({ manualTimers: true, autoEcho: true, localIsn: 0xffffffff });
  try {
    const before = value.mock.tcpWrites.length;
    await value.runtime.advance(19999);
    assert.equal(value.mock.tcpWrites.length, before);
    await value.runtime.advance(1);
    const probe = value.mock.tcpWrites.at(-1);
    assert.equal(probe.flags, 0x10);
    assert.equal(probe.sequence, 0xffffffff);
    assert.equal(probe.ack, 1001);
    assert.equal(probe.bytes.byteLength, 0);
    await value.conn.writable.getWriter().write(encode('next'));
    assert.equal(outgoingData(value.mock)[0].sequence, 0, 'probe must not consume SND.NXT');
  } finally { value.cleanup(); }
});

test('target TCP activity postpones idle probes while PPP activity does not', async () => {
  const value = await fixture({ manualTimers: true, autoEcho: true, autoAckData: true });
  try {
    await value.runtime.advance(15000);
    await value.conn.writable.getWriter().write(encode('request'));
    await flushTasks();
    const before = value.mock.tcpWrites.length;
    await value.runtime.advance(5000);
    assert.equal(value.mock.tcpWrites.length, before, 'recent target TX/ACK keeps the TCP flow active');
    await value.runtime.advance(20000);
    assert.equal(value.mock.tcpWrites.length, before + 1, 'PPP/SSTP echoes cannot postpone an idle target TCP probe');
    const afterProbe = value.mock.tcpWrites.length;
    acknowledge(value, outgoingData(value.mock)[0].sequence + 7);
    await value.runtime.advance(10000);
    acknowledge(value, outgoingData(value.mock)[0].sequence + 7);
    await value.runtime.advance(10000);
    assert.equal(value.mock.tcpWrites.length, afterProbe, 'recent target RX postpones the next probe');
  } finally { value.cleanup(); }
});

test('pending payload and local FIN suppress TCP keepalive probes', async () => {
  const pending = await fixture({ manualTimers: true, autoEcho: true });
  try {
    await pending.conn.writable.getWriter().write(encode('unacknowledged'));
    const ackCount = pending.mock.tcpWrites.filter(item => item.flags === 0x10).length;
    await pending.runtime.advance(20000);
    assert.equal(pending.mock.tcpWrites.filter(item => item.flags === 0x10).length, ackCount);
    await pending.runtime.advance(3000);
    assert.equal(pending.runtime.timers.size, 0, 'keepalive cannot mask the real data ACK deadline');
  } finally { pending.cleanup(); }
  const finished = await fixture({ manualTimers: true, autoEcho: true });
  try {
    await finished.conn.writable.getWriter().close();
    const before = finished.mock.tcpWrites.length;
    await finished.runtime.advance(40000);
    assert.equal(finished.mock.tcpWrites.length, before, 'a local FIN stops TCP keepalive');
  } finally { finished.cleanup(); }
});

test('a zero-payload peer keepalive is ACKed across wrap without delivering or consuming bytes', async () => {
  const value = await fixture({ manualTimers: true, localIsn: 0xffffffff, remoteIsn: 0xfffffffe });
  try {
    const before = value.mock.tcpWrites.length;
    value.mock.push(remoteTcp(value.mock.sourcePort, 0xfffffffe, 0x10, new Uint8Array(), 0));
    await flushTasks();
    assert.equal(value.mock.tcpWrites.length, before + 1);
    const response = value.mock.tcpWrites.at(-1);
    assert.equal(response.sequence, 0);
    assert.equal(response.ack, 0xffffffff);
    assert.equal(response.flags, 0x10);
    assert.equal(response.bytes.byteLength, 0);
    await value.conn.writable.getWriter().write(encode('next'));
    assert.equal(outgoingData(value.mock)[0].sequence, 0);
    value.mock.push(remoteTcp(value.mock.sourcePort, 0xffffffff, 0x18, encode('reply'), 4));
    const reader = value.conn.readable.getReader();
    assert.equal(decode((await reader.read()).value), 'reply');
    reader.releaseLock();
  } finally { value.cleanup(); }
});

test('ordinary pure ACKs do not cause ACK loops or advance unacknowledged data', async () => {
  const value = await fixture({ manualTimers: true, peerWindow: 6 });
  try {
    await value.conn.writable.getWriter().write(encode('abcdef'));
    const before = value.mock.tcpWrites.length, base = outgoingData(value.mock)[0].sequence;
    acknowledge(value, base);
    acknowledge(value, base + 6, 6, 1000); // Keepalive sequence is outside the receive window.
    await flushTasks();
    assert.equal(value.mock.tcpWrites.length, before + 1, 'reply only to the keepalive, not ordinary ACK');
    await value.runtime.advance(1000);
    assert.equal(outgoingData(value.mock).length, 2, 'out-of-window keepalive ACK cannot acknowledge application data');
  } finally { value.cleanup(); }
});

test('SoftEther user-mode keepalive with current receive sequence and previous ACK gets a reply', async () => {
  const value = await fixture({ manualTimers: true, autoEcho: true, localIsn: 0xffffffff });
  try {
    const before = value.mock.tcpWrites.length;
    for (let tick = 0; tick < 4; tick++) {
      await value.runtime.advance(5000);
      acknowledge(value, 0xffffffff);
      await flushTasks();
    }
    const responses = value.mock.tcpWrites.slice(before);
    assert.equal(responses.length, 4, 'user-mode TCP probes must refresh the NAT even while suppressing idle probes');
    assert.ok(responses.every(item => item.flags === 0x10 && item.sequence === 0 && item.ack === 1001 && item.bytes.byteLength === 0));
    await value.conn.writable.getWriter().write(encode('next'));
    assert.equal(outgoingData(value.mock)[0].sequence, 0);
  } finally { value.cleanup(); }
});

test('SoftEther previous-ACK keepalive cannot acknowledge pending data or shrink its send window', async () => {
  const value = await fixture({ manualTimers: true, peerWindow: 6 });
  try {
    await value.conn.writable.getWriter().write(encode('abcdef'));
    const before = value.mock.tcpWrites.length, base = outgoingData(value.mock)[0].sequence;
    acknowledge(value, base - 1, 0);
    await flushTasks();
    assert.equal(value.mock.tcpWrites.length, before + 1, 'reply to the user-mode probe');
    await value.runtime.advance(1000);
    assert.deepEqual(outgoingData(value.mock).map(item => [item.sequence, item.payload]), [[base, 'abcdef'], [base, 'abcdef']]);
  } finally { value.cleanup(); }
});

test('native asynchronous TCP keepalive stops after external close', { timeout: 2000 }, async () => {
  const value = await fixture({ autoEcho: true, localIsn: 0xffffffff });
  try {
    const before = value.mock.tcpWrites.length;
    for (let attempt = 0; attempt < 30 && value.mock.tcpWrites.length === before; attempt++) await pause(20);
    assert.ok(value.mock.tcpWrites.length > before, 'native timer must send a TCP keepalive');
    const probe = value.mock.tcpWrites.at(-1);
    assert.equal(probe.flags, 0x10);
    assert.equal(probe.sequence, 0xffffffff);
    assert.equal(probe.bytes.byteLength, 0);
    value.conn.close();
    await flushTasks();
    const closedWrites = value.mock.tcpWrites.length;
    await pause(220);
    assert.equal(value.mock.tcpWrites.length, closedWrites);
    assert.equal(value.runtime.timers.size, 0);
  } finally { value.cleanup(); }
});

test('TCP keepalive write failure closes both streams and clears deadlines', async () => {
  const runtime = loadSection({ manualTimers: true }), mock = socketMock({ autoEcho: true });
  const originalGetWriter = mock.socket.writable.getWriter.bind(mock.socket.writable);
  let failKeepalive = false;
  mock.socket.writable = { getWriter() {
    const writer = originalGetWriter();
    return {
      write(frame) {
        if (failKeepalive && frame.byteLength === 48 && frame[6] === 0 && frame[7] === 33 && frame[41] === 0x10) return Promise.reject(new Error('mock TCP keepalive write failed'));
        return writer.write(frame);
      },
      close: () => writer.close(), releaseLock: () => writer.releaseLock()
    };
  } };
  const conn = await runtime.connect({ hostname: 'mock.invalid', port: 443, username: 'vpn', password: 'vpn' }, '203.0.113.1', 443, () => mock.socket);
  try {
    const closedFailed = conn.closed.then(() => null, error => error);
    const readFailed = conn.readable.getReader().read().then(() => null, error => error);
    failKeepalive = true;
    await runtime.advance(20000);
    assert.match((await closedFailed)?.message || '', /keepalive write failed/);
    assert.match((await readFailed)?.message || '', /keepalive write failed/);
    await assert.rejects(conn.writable.getWriter().write(encode('later')), /keepalive write failed/);
    assert.equal(runtime.timers.size, 0);
    assert.equal(mock.metrics.activeReads, 0);
  } finally { conn.close(); runtime.cleanup(); }
});

test('a dropped outgoing segment is retransmitted with its original sequence after one second', async () => {
  const value = await fixture({ manualTimers: true, autoAckData: true, dropDataSegments: [1] });
  try {
    await value.conn.writable.getWriter().write(encode('ClientHello'));
    assert.equal(decode(value.mock.receivedBytes), '');
    await value.runtime.advance(999);
    assert.equal(outgoingData(value.mock).length, 1);
    await value.runtime.advance(1);
    assert.equal(outgoingData(value.mock).length, 2, 'lost ClientHello must be resent instead of hanging until EOF');
    assert.equal(outgoingData(value.mock)[1].sequence, outgoingData(value.mock)[0].sequence);
    assert.equal(decode(value.mock.receivedBytes), 'ClientHello');
    await value.runtime.advance(8000);
    assert.equal(outgoingData(value.mock).length, 2, 'cumulative ACK cancels further retries');
  } finally { value.cleanup(); }
});

test('a lost data ACK retransmits without duplicate peer application bytes', async () => {
  const value = await fixture({ manualTimers: true, autoAckData: true, dropDataAcks: [1] });
  try {
    await value.conn.writable.getWriter().write(encode('hello'));
    await value.runtime.advance(1000);
    assert.equal(outgoingData(value.mock).length, 2);
    assert.equal(decode(value.mock.receivedBytes), 'hello');
  } finally { value.cleanup(); }
});

test('native asynchronous timers recover a dropped segment while streaming across sequence wrap', { timeout: 2000 }, async () => {
  const value = await fixture({ autoAckData: true, dropDataSegments: [1], peerWindow: 4200, localIsn: 0xfffffff0 });
  try {
    const payload = 'stream-bytes'.repeat(1050);
    await value.conn.writable.getWriter().write(encode(payload));
    await flushTasks();
    assert.equal(decode(value.mock.receivedBytes), payload);
    const segments = outgoingData(value.mock);
    assert.ok(segments.filter(item => item.sequence === 0xfffffff1).length >= 2, 'native retry reuses the dropped sequence');
    assert.ok(segments.some(item => item.sequence < 0xfffffff1), 'stream wraps its sequence');
    assert.equal(value.mock.metrics.maxActiveReads, 1);
  } finally { value.cleanup(); }
});

test('outgoing transport sends several segments before waiting for ACK', async () => {
  const value = await fixture({ manualTimers: true });
  try {
    await value.conn.writable.getWriter().write(encode('x'.repeat(4200)));
    assert.deepEqual(outgoingData(value.mock).map(item => item.bytes.byteLength), [1400, 1400, 1400]);
  } finally { value.cleanup(); }
});

test('partial ACK retains only the unacknowledged suffix at its original sequence', async () => {
  const value = await fixture({ manualTimers: true, peerWindow: 6 });
  try {
    await value.conn.writable.getWriter().write(encode('abcdef'));
    const base = outgoingData(value.mock)[0].sequence;
    acknowledge(value, base + 3, 6);
    await value.runtime.advance(1000);
    assert.deepEqual(outgoingData(value.mock).map(item => [item.sequence, item.payload]), [[base, 'abcdef'], [(base + 3) >>> 0, 'def']]);
    acknowledge(value, base + 6, 6);
    await value.runtime.advance(8000);
    assert.equal(outgoingData(value.mock).length, 2);
  } finally { value.cleanup(); }
});

test('future and stale ACKs cannot release a full outgoing receive window', async () => {
  const value = await fixture({ manualTimers: true, peerWindow: 6 });
  try {
    const writer = value.conn.writable.getWriter();
    let finished = false;
    const writing = writer.write(encode('abcdefghi')).then(() => { finished = true; });
    await flushTasks();
    const base = outgoingData(value.mock)[0].sequence;
    assert.equal(outgoingData(value.mock).map(item => item.payload).join(''), 'abcdef');
    acknowledge(value, base + 100, 65535);
    acknowledge(value, base - 1, 65535);
    await flushTasks();
    assert.equal(finished, false, 'invalid ACK must not free the send window');
    assert.equal(outgoingData(value.mock).map(item => item.payload).join(''), 'abcdef');
    acknowledge(value, base + 6, 6);
    await writing;
    assert.equal(outgoingData(value.mock).at(-1).payload, 'ghi');
  } finally { value.cleanup(); }
});

test('outgoing partial and cumulative ACK validation survives sequence wrap', async () => {
  const value = await fixture({ manualTimers: true, localIsn: 0xfffffffc, peerWindow: 6 });
  try {
    await value.conn.writable.getWriter().write(encode('abcdef'));
    acknowledge(value, 4, 6); // One byte beyond SND.NXT.
    acknowledge(value, 0xfffffffc, 6); // Before SND.UNA.
    acknowledge(value, 0xffffffff, 6);
    await value.runtime.advance(1000);
    assert.deepEqual(outgoingData(value.mock).map(item => [item.sequence, item.payload]), [[0xfffffffd, 'abcdef'], [0xffffffff, 'cdef']]);
    acknowledge(value, 3, 6);
    await value.runtime.advance(8000);
    assert.equal(outgoingData(value.mock).length, 2);
  } finally { value.cleanup(); }
});

test('a healthy idle SSTP link answers proactive echoes and stays open beyond sixty seconds', async () => {
  const value = await fixture({ manualTimers: true, autoEcho: true });
  try {
    let closed = false;
    value.conn.closed.finally(() => { closed = true; }).catch(() => {});
    await value.runtime.advance(61000);
    assert.equal(closed, false, 'healthy idle tunnel must survive the old sixty-second read deadline');
    assert.equal(value.mock.linkWrites.filter(item => item.type === 8).length, 3, 'send link echo every twenty seconds');
    assert.equal(value.mock.metrics.maxActiveReads, 1);
  } finally { value.cleanup(); }
});

test('an idle SSTP peer that never answers is still closed within sixty seconds', async () => {
  const value = await fixture({ manualTimers: true });
  try {
    const failed = value.conn.closed.then(() => null, error => error);
    await value.runtime.advance(60001);
    assert.match((await failed)?.message || '', /timeout|timed out/i);
    assert.ok(value.mock.linkWrites.some(item => item.type === 8));
    assert.equal(value.runtime.timers.size, 0);
  } finally { value.cleanup(); }
});

test('missing outgoing ACKs back off at one, two, four and eight seconds then fail and wake blocked writes', async () => {
  const value = await fixture({ manualTimers: true, peerWindow: 6 });
  try {
    const writer = value.conn.writable.getWriter();
    const writingFailed = writer.write(encode('abcdefghi')).then(() => null, error => error);
    const closedFailed = value.conn.closed.then(() => null, error => error);
    const readFailed = value.conn.readable.getReader().read().then(() => null, error => error);
    await flushTasks();
    for (const [milliseconds, count] of [[1000, 2], [2000, 3], [4000, 4], [8000, 5]]) {
      await value.runtime.advance(milliseconds);
      assert.equal(outgoingData(value.mock).length, count);
    }
    await value.runtime.advance(8000);
    assert.match((await closedFailed)?.message || '', /ACK|retransmi|timed out/i);
    assert.ok(await writingFailed instanceof Error, 'failed transport must release writer waiting for window space');
    assert.ok(await readFailed instanceof Error, 'failed transport must error the readable');
    assert.equal(value.runtime.timers.size, 0, 'failure cancels retry, echo and pending read timers');
    assert.equal(value.mock.metrics.activeReads, 0);
  } finally { value.cleanup(); }
});

test('outgoing pending bytes stay bounded while a large write waits for ACK', async () => {
  const value = await fixture({ manualTimers: true });
  try {
    const writing = value.conn.writable.getWriter().write(encode('x'.repeat(200000))).then(() => null, error => error);
    await flushTasks();
    assert.equal(outgoingData(value.mock).reduce((sum, item) => sum + item.bytes.byteLength, 0), 65535);
    value.conn.close();
    assert.ok(await writing instanceof Error);
    await flushTasks();
    assert.equal(value.runtime.timers.size, 0);
  } finally { value.cleanup(); }
});

test('zero peer window blocks writes until a valid window update', async () => {
  const value = await fixture({ manualTimers: true, peerWindow: 0 });
  try {
    const writing = value.conn.writable.getWriter().write(encode('data'));
    await flushTasks();
    assert.equal(outgoingData(value.mock).length, 0);
    const base = (value.mock.tcpWrites.find(item => item.flags === 2).sequence + 1) >>> 0;
    acknowledge(value, base, 4);
    await writing;
    assert.equal(outgoingData(value.mock)[0].payload, 'data');
  } finally { value.cleanup(); }
});

test('a peer that keeps its window at zero has a bounded write deadline', async () => {
  const value = await fixture({ manualTimers: true, peerWindow: 0, autoEcho: true });
  try {
    const writingFailed = value.conn.writable.getWriter().write(encode('data')).then(() => null, error => error);
    const closedFailed = value.conn.closed.then(() => null, error => error);
    await value.runtime.advance(30001);
    assert.match((await writingFailed)?.message || '', /window|timed out/i);
    assert.ok(await closedFailed instanceof Error);
    assert.equal(value.runtime.timers.size, 0);
  } finally { value.cleanup(); }
});

test('normal external close finishes the readable and releases a blocked writer without later retries', async () => {
  const value = await fixture({ manualTimers: true, peerWindow: 3 });
  try {
    const reading = value.conn.readable.getReader().read();
    const writing = value.conn.writable.getWriter().write(encode('abcdef')).then(() => null, error => error);
    await flushTasks();
    value.conn.close();
    assert.equal((await reading).done, true);
    assert.ok(await writing instanceof Error);
    await value.conn.closed;
    await value.runtime.advance(61000);
    assert.equal(outgoingData(value.mock).length, 1);
    assert.equal(value.runtime.timers.size, 0);
  } finally { value.cleanup(); }
});

test('closing during a stalled tunnel write cancels its deadline and settles the writer', async () => {
  const value = await fixture({ manualTimers: true, stallDataWrites: true });
  try {
    const writing = value.conn.writable.getWriter().write(encode('data')).then(() => null, error => error);
    await flushTasks();
    value.conn.close();
    await flushTasks();
    assert.equal(value.runtime.timers.size, 0, 'stalled tunnel write must not retain its timeout after close');
    assert.ok(await writing instanceof Error);
  } finally { value.cleanup(); }
});

test('writer abort immediately cancels a write blocked on peer window space', async () => {
  const value = await fixture({ manualTimers: true, peerWindow: 3 });
  try {
    const writer = value.conn.writable.getWriter();
    const writing = writer.write(encode('abcdef')).then(() => null, error => error);
    await flushTasks();
    const aborting = writer.abort(new Error('cancel blocked write'));
    await flushTasks();
    assert.equal(value.mock.closingCalls, 1, 'abort must wake an in-flight sink write before waiting for it');
    await aborting;
    assert.match((await writing)?.message || '', /cancel blocked write/);
    await assert.rejects(value.conn.closed, /cancel blocked write/);
    assert.equal(value.runtime.timers.size, 0);
  } finally { value.cleanup(); }
});

test('a shrinking peer window also bounds retransmitted data', async () => {
  const value = await fixture({ manualTimers: true, peerWindow: 6 });
  try {
    await value.conn.writable.getWriter().write(encode('abcdef'));
    const base = outgoingData(value.mock)[0].sequence;
    acknowledge(value, base, 2);
    await value.runtime.advance(1000);
    assert.equal(outgoingData(value.mock).at(-1).payload, 'ab');
    acknowledge(value, base, 0);
    await value.runtime.advance(2000);
    assert.equal(outgoingData(value.mock).length, 2, 'zero-window peer must not receive another full data retry');
    acknowledge(value, base, 6);
    await value.runtime.advance(4000);
    assert.equal(outgoingData(value.mock).at(-1).payload, 'abcdef');
  } finally { value.cleanup(); }
});

test('duplicate zero-window ACKs cannot postpone the bounded write deadline', async () => {
  const value = await fixture({ manualTimers: true, peerWindow: 0, autoEcho: true });
  try {
    const writing = value.conn.writable.getWriter().write(encode('data')).then(() => null, error => error);
    const base = (value.mock.tcpWrites.find(item => item.flags === 2).sequence + 1) >>> 0;
    for (let index = 0; index < 3; index++) {
      await value.runtime.advance(9000);
      acknowledge(value, base, 0);
      await flushTasks();
    }
    await value.runtime.advance(3001);
    assert.equal(value.mock.closingCalls, 1, 'no-progress duplicate ACKs must not keep a stalled write alive');
    assert.match((await writing)?.message || '', /window|timed out/i);
  } finally { value.cleanup(); }
});

test('TCP packets without ACK or outside the receive window cannot free outgoing bytes', async () => {
  const value = await fixture({ manualTimers: true, peerWindow: 3 });
  try {
    const writing = value.conn.writable.getWriter().write(encode('abcdef'));
    await flushTasks();
    const base = outgoingData(value.mock)[0].sequence;
    value.mock.push(remoteTcp(value.mock.sourcePort, 1001, 0, new Uint8Array(), (base + 3) >>> 0));
    acknowledge(value, base + 3, 65535, 1001 + 65535);
    await flushTasks();
    assert.equal(outgoingData(value.mock).length, 1);
    acknowledge(value, base + 3, 3);
    await writing;
    assert.equal(outgoingData(value.mock).at(-1).payload, 'def');
  } finally { value.cleanup(); }
});

for (const options of [{ failDataWrites: true }, { failEchoWrites: true }]) {
  test(`${Object.keys(options)[0]} rejects the connection and clears transport timers`, async () => {
    const value = await fixture({ manualTimers: true, ...options });
    try {
      const failed = value.conn.closed.then(() => null, error => error);
      if (options.failDataWrites) await assert.rejects(value.conn.writable.getWriter().write(encode('data')), /mock data write failed/);
      else await value.runtime.advance(20000);
      assert.match((await failed)?.message || '', /mock.*write failed/);
      await flushTasks();
      assert.equal(value.runtime.timers.size, 0);
      assert.equal(value.mock.metrics.activeReads, 0);
    } finally { value.cleanup(); }
  });
}

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
