import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const source = fs.readFileSync(new URL('../worker.mjs', import.meta.url), 'utf8');
const start = source.indexOf('const SSTP_TCP_MSS =');
const end = source.indexOf('//////////////////////////////////////////////////', start + 1);
if (start < 0 || end <= start) throw new Error('Worker SSTP section markers missing');
const state = new URL('../../.test-state/', import.meta.url);
fs.mkdirSync(state, { recursive: true });
const section = new URL('section.txt', state);
fs.writeFileSync(section, source.slice(start, end));
const result = spawnSync(process.execPath, ['--test', '--test-concurrency=1',
  fileURLToPath(new URL('./sstp.mjs', import.meta.url)),
  fileURLToPath(new URL('./subscription-profile.mjs', import.meta.url))], {
  encoding: 'utf8', env: { ...process.env, SSTP_SECTION_PATH: fileURLToPath(section) }
});
process.stdout.write(`${result.stdout || ''}${result.stderr || ''}`);
process.exitCode = result.status ?? 1;
