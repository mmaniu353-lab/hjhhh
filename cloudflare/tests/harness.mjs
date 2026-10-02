import fs from 'node:fs';
import vm from 'node:vm';
import { webcrypto } from 'node:crypto';
import assert from 'node:assert/strict';

export const encode = value => new TextEncoder().encode(value);
export const decode = value => new TextDecoder().decode(value);
export const pause = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
export const concat = (...parts) => {
  const bytes = new Uint8Array(parts.reduce((sum, part) => sum + part.byteLength, 0));
  let offset = 0;
  for (const part of parts) { bytes.set(part, offset); offset += part.byteLength; }
  return bytes;
};

export function control(type) {
  return new Uint8Array([0x10, 1, 0, 8, 0, type, 0, 0]);
}

export function ppp(protocol, code, id, payload = new Uint8Array()) {
  const bytes = new Uint8Array(12 + payload.byteLength);
  const view = new DataView(bytes.buffer);
  bytes.set([0x10, 0, (bytes.byteLength >> 8) & 15, bytes.byteLength & 255, 255, 3]);
  view.setUint16(6, protocol);
  bytes[8] = code; bytes[9] = id;
  view.setUint16(10, 4 + payload.byteLength);
  bytes.set(payload, 12);
  return bytes;
}

function checksum(bytes) {
  let sum = 0;
  for (let index = 0; index < bytes.byteLength; index += 2) sum += (bytes[index] << 8) | (bytes[index + 1] ?? 0);
  while (sum >> 16) sum = (sum & 65535) + (sum >> 16);
  return (~sum) & 65535;
}

export function remoteTcp(localPort, sequence, flags, payload = new Uint8Array(), ack = 0, window = 65535) {
  const bytes = new Uint8Array(48 + payload.byteLength);
  const view = new DataView(bytes.buffer);
  bytes.set([0x10, 0, (bytes.byteLength >> 8) & 15, bytes.byteLength & 255, 255, 3, 0, 33]);
  bytes[8] = 0x45; bytes[16] = 64; bytes[17] = 6;
  bytes.set([203, 0, 113, 1], 20); bytes.set([10, 0, 0, 2], 24);
  view.setUint16(10, 40 + payload.byteLength);
  view.setUint16(28, 443); view.setUint16(30, localPort);
  view.setUint32(32, sequence); view.setUint32(36, ack);
  bytes[40] = 0x50; bytes[41] = flags; view.setUint16(42, window);
  bytes.set(payload, 48);
  view.setUint16(18, checksum(bytes.subarray(8, 28)));
  const pseudo = new Uint8Array(32 + payload.byteLength);
  pseudo.set(bytes.subarray(20, 28)); pseudo[9] = 6;
  new DataView(pseudo.buffer).setUint16(10, 20 + payload.byteLength);
  pseudo.set(bytes.subarray(28), 12);
  view.setUint16(44, checksum(pseudo));
  return bytes;
}

export function loadSection() {
  const sectionPath = process.env.SSTP_SECTION_PATH || new URL('./section.txt', import.meta.url);
  const section = fs.readFileSync(sectionPath, 'utf8');
  const actualWorker = fs.readFileSync(new URL('../worker.mjs', import.meta.url), 'utf8');
  const timeoutStart = actualWorker.indexOf('async function withTimeout(');
  const timeoutEnd = actualWorker.indexOf('function turnStunPadding(', timeoutStart);
  const nativeStart = Date.now(), virtualStart = nativeStart;
  const timers = new Set();
  const context = vm.createContext({
    crypto: webcrypto, Uint8Array, DataView, TextEncoder, TextDecoder, ReadableStream, WritableStream, Promise, Error, Math,
    Date: class extends Date { static now() { return virtualStart + (Date.now() - nativeStart) * 100; } },
    textEncoder: new TextEncoder(), textDecoder: new TextDecoder(), CONNECT_TIMEOUT_MS: 9999,
    setTimeout(callback, milliseconds) {
      let timer;
      timer = setTimeout(() => { timers.delete(timer); callback(); }, Math.max(1, milliseconds / 100));
      timers.add(timer);
      return timer;
    },
    clearTimeout(timer) { timers.delete(timer); clearTimeout(timer); },
    '数据转Uint8Array': value => value instanceof Uint8Array ? value : new Uint8Array(value),
    '拼接字节数据': concat,
    stripIPv6Brackets: value => value.replace(/^\[|\]$/g, ''),
  });
  const connect = vm.runInContext(actualWorker.slice(timeoutStart, timeoutEnd) + section + '\nsstpConnect;', context);
  return { connect, timers, cleanup() { for (const timer of timers) clearTimeout(timer); timers.clear(); } };
}

export function socketMock({ stageEcho = '', dropInitialSyn = false, remoteIsn = 1000, setupTerminate = false, malformedSynAck = false } = {}) {
  let streamController, ended = false, sourcePort, localSequence, ipcpNakSent = false, closingCalls = 0;
  const writes = [], tcpWrites = [], linkWrites = [];
  const metrics = { activeReads: 0, maxActiveReads: 0 };
  const push = bytes => { if (!ended) streamController.enqueue(bytes); };
  const echoFrames = () => concat(control(8), ppp(0xc021, 9, 99, new Uint8Array([1, 2, 3, 4, 65, 66])));
  const rawReadable = new ReadableStream({ start(controller) { streamController = controller; }, cancel() { ended = true; } });
  const readable = { getReader() {
    const reader = rawReadable.getReader();
    return {
      read() {
        metrics.activeReads++;
        metrics.maxActiveReads = Math.max(metrics.maxActiveReads, metrics.activeReads);
        return reader.read().finally(() => { metrics.activeReads--; });
      },
      cancel: (...args) => reader.cancel(...args), releaseLock: () => reader.releaseLock()
    };
  } };
  const writable = new WritableStream({ write(chunk) {
    writes.push(new Uint8Array(chunk));
    if (decode(chunk.subarray(0, 16)) === 'SSTP_DUPLEX_POST') {
      push(concat(encode('HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\n\r\n'), control(2),
        ...(stageEcho === 'ppp' ? [echoFrames()] : []),
        ...(setupTerminate ? [ppp(0xc021, 5, 88)] : []),
        ppp(0xc021, 1, 8, new Uint8Array([3, 4, 0xc0, 0x23])), ppp(0xc021, 2, 1, new Uint8Array([1, 4, 5, 220]))));
      return;
    }
    for (let offset = 0; offset + 4 <= chunk.byteLength;) {
      const length = ((chunk[offset + 2] << 8) | chunk[offset + 3]) & 4095;
      assert.ok(length >= 4);
      const frame = chunk.subarray(offset, offset + length);
      if (frame[1] & 1) linkWrites.push({ type: (frame[4] << 8) | frame[5], frame: new Uint8Array(frame) });
      else if (frame[6] === 0 && frame[7] === 33) {
        const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
        sourcePort = view.getUint16(28); localSequence = view.getUint32(32);
        const record = { sequence: localSequence, ack: view.getUint32(36), flags: frame[41], payload: decode(frame.subarray(48)) };
        tcpWrites.push(record);
        if (record.flags === 2 && (!dropInitialSyn || tcpWrites.filter(item => item.flags === 2).length > 1)) {
          push(concat(...(stageEcho === 'tcp' ? [echoFrames()] : []), remoteTcp(sourcePort, remoteIsn, 0x12, new Uint8Array(), (localSequence + (malformedSynAck ? 2 : 1)) >>> 0)));
        }
      } else {
        const protocol = (frame[6] << 8) | frame[7];
        const code = frame[8], id = frame[9];
        linkWrites.push({ protocol, code, id, payload: new Uint8Array(frame.subarray(12)), frame: new Uint8Array(frame) });
        if (protocol === 0xc023 && code === 1) push(ppp(0xc023, 2, id, new Uint8Array([0])));
        if (protocol === 0x8021 && code === 1) {
          push(ppp(0x8021, ipcpNakSent ? 2 : 3, id, new Uint8Array([3, 6, 10, 0, 0, 2])));
          ipcpNakSent = true;
        }
      }
      offset += length;
    }
  } });
  const socket = { readable, writable, opened: Promise.resolve(), close() {
    closingCalls++;
    if (!ended) { ended = true; try { streamController.close(); } catch {} }
    return Promise.resolve();
  } };
  return { socket, push, writes, tcpWrites, linkWrites, metrics, get sourcePort() { return sourcePort; }, get localSequence() { return localSequence; }, get closingCalls() { return closingCalls; } };
}

export async function fixture(options = {}) {
  const runtime = loadSection();
  const mock = socketMock(options);
  let conn;
  try { conn = await runtime.connect({ hostname: 'mock.invalid', port: 443, username: 'vpn', password: 'vpn' }, '203.0.113.1', 443, () => mock.socket); }
  catch (error) { mock.socket.close(); runtime.cleanup(); throw error; }
  conn.closed.catch(() => {});
  return { runtime, mock, conn, cleanup() { conn.close(); runtime.cleanup(); } };
}

export async function consume(conn) {
  const reader = conn.readable.getReader();
  let result = '';
  try { for (;;) { const chunk = await reader.read(); if (chunk.done) break; result += decode(chunk.value); } }
  finally { reader.releaseLock(); }
  return result;
}

export function lastAck(mock) { return mock.tcpWrites.at(-1)?.ack; }
