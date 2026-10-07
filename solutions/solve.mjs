import fs from 'node:fs';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import assert from 'node:assert/strict';
import {decryptBlock} from '../tools/generate.mjs';

// Recover from the distributed PE; the answer/config files are NOT read.
const here = path.dirname(fileURLToPath(import.meta.url));
const data = fs.readFileSync(process.argv[2] ?? path.join(here, '../dist/empty_city.exe'));
const pe = data.readUInt32LE(0x3C), opt = pe + 24;
assert.equal(data.readUInt16LE(opt), 0x10B);
const base = data.readUInt32LE(opt+28);
const sectionTable = opt + data.readUInt16LE(pe+20);
const sections = Array.from({length: data.readUInt16LE(pe+6)}, (_, i) => {
  const s = sectionTable + 40*i;
  return {va: data.readUInt32LE(s+12), size: Math.max(data.readUInt32LE(s+8),data.readUInt32LE(s+16)), raw: data.readUInt32LE(s+20)};
});
function raw(rva) {
  const s = sections.find(s => s.va <= rva && rva < s.va+s.size);
  assert(s, 'Unmapped RVA');
  return s.raw+rva-s.va;
}
const tls = raw(data.readUInt32LE(opt+96+9*8));
const callbacks = raw(data.readUInt32LE(tls+12)-base);
const blob = raw(data.readUInt32LE(callbacks)-base);
const key = Array.from({length: 4}, (_, i) => data.readUInt32LE(blob+0x800+i*4));
// Published puzzle has seven blocks; this value is recoverable from its loop.
const encrypted = data.subarray(blob+0x810, blob+0x810+56);
const padded = Buffer.concat(Array.from({length: encrypted.length/8}, (_, i) => decryptBlock(encrypted.subarray(i*8,i*8+8),key)));
const pad = padded.at(-1);
assert(pad >= 1 && pad <= 8 && padded.subarray(-pad).every(b => b === pad));
const flag = padded.subarray(0, -pad).toString('ascii');
assert.match(flag, /^PKWCTF\{.+\}$/);
console.log(flag);
