import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import assert from 'node:assert/strict';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const exe = path.join(root, 'dist/empty_city.exe');
const data = fs.readFileSync(exe);
const config = JSON.parse(fs.readFileSync(path.join(root, 'config/challenge.json'), 'utf8'));
const pe = data.readUInt32LE(0x3c), opt = pe + 24;
assert.equal(data.readUInt16LE(0), 0x5a4d);
assert.equal(data.readUInt32LE(pe), 0x00004550);
assert.equal(data.readUInt16LE(pe+4), 0x14c, 'Expected x86');
assert.equal(data.readUInt16LE(opt), 0x10b, 'Expected PE32');
assert.equal(data.readUInt16LE(opt+68), 2, 'Expected GUI subsystem');
assert.equal(data.readUInt16LE(opt+70) & 0x100, 0, 'NX_COMPAT must be clear');
assert.equal(data.readUInt32LE(pe+12), 0, 'No COFF symbol table');
const base = data.readUInt32LE(opt+28);
const table = opt + data.readUInt16LE(pe+20);
const sections = Array.from({length: data.readUInt16LE(pe+6)}, (_, i) => {
  const s = table + i*40;
  return {
    name: data.subarray(s,s+8).toString('ascii').replace(/\0.*$/, ''),
    size: data.readUInt32LE(s+8), rva: data.readUInt32LE(s+12),
    rawSize: data.readUInt32LE(s+16), raw: data.readUInt32LE(s+20),
    flags: data.readUInt32LE(s+36)
  };
});
function raw(rva) {
  const section = sections.find(s => rva >= s.rva && rva < s.rva+s.rawSize);
  assert(section, `Unmapped RVA ${rva.toString(16)}`);
  return section.raw + rva - section.rva;
}
function cstring(offset) {
  const end = data.indexOf(0, offset);
  assert(end >= offset);
  return data.subarray(offset, end).toString('ascii');
}
const text = sections.find(s => s.name === '.text');
const blobSection = sections.find(s => s.name === '.data');
assert.equal(text.size, 7);
assert.equal(data.readUInt32LE(opt+16), text.rva);
assert.equal(data.subarray(text.raw,text.raw+text.size).toString('hex'), '558bec33c05dc3');
assert.equal(blobSection.flags, 0xc0000040, 'Expected ordinary read/write data');
assert(!sections.some(s => s.name === '.CRT' || s.name === '.pdata'));
const tls = raw(data.readUInt32LE(opt+96+9*8));
const callbacks = raw(data.readUInt32LE(tls+12)-base);
const callbackRva = data.readUInt32LE(callbacks)-base;
assert.equal(callbackRva, blobSection.rva);
assert.equal(data.readUInt32LE(callbacks+4), 0);
assert.deepEqual(data.subarray(raw(callbackRva),raw(callbackRva)+0x1000),
  fs.readFileSync(path.join(root, 'build/blob.bin')));

// Check the assembled transfer itself, not just the source spelling.
const listing = fs.readFileSync(path.join(root, 'build/blob.lst'), 'utf8').split(/\r?\n/);
function labelOffset(label) {
  const line = listing.findIndex(line => line.trimEnd().endsWith(` ${label}:`));
  assert(line >= 0, `Missing assembly label: ${label}`);
  for (let i = line+1; i < listing.length; i++) {
    const match = listing[i].match(/^\s*\d+\s+([0-9A-F]{8})\s+[0-9A-F]/i);
    if (match) return parseInt(match[1], 16);
  }
  assert.fail(`No instruction following ${label}`);
}
const transfer = labelOffset('.block');
const resume = labelOffset('.block_done');
const ready = labelOffset('.transfer_ready');
const badStack = labelOffset('.transfer_bad_stack');
const xtea = labelOffset('xtea_encrypt_block');
const imageBlob = raw(callbackRva);
assert.equal(data.subarray(imageBlob+transfer,imageBlob+transfer+7).toString('hex'),
  '9c5131c985c975', 'Expected balanced saved state and opaque branch');
assert.equal(transfer+8+data.readInt8(imageBlob+transfer+7), badStack);
assert.equal(data[imageBlob+transfer+8], 0xb8, 'Expected encoded target in EAX');
assert.equal(data[imageBlob+transfer+13], 0x35, 'Expected XOR target decoder');
const encodedTarget = data.readUInt32LE(imageBlob+transfer+9);
const targetMask = data.readUInt32LE(imageBlob+transfer+14);
assert.equal((encodedTarget ^ targetMask) >>> 0, xtea);
assert.equal(data.subarray(imageBlob+transfer+18,imageBlob+transfer+26).toString('hex'),
  '01f0c1c009c1c809', 'Expected ASLR-aware base addition and rotate pair');
assert.equal(data.subarray(imageBlob+ready,imageBlob+resume).toString('hex'),
  '599d52ffe0', 'Expected state restore, PUSH EDX, indirect JMP EAX');
assert.equal(data[imageBlob+xtea], 0x9c, 'XTEA must start with the entry junk block');

const imports = [];
let descriptor = raw(data.readUInt32LE(opt+96+8));
while (data.readUInt32LE(descriptor+12)) {
  const dll = cstring(raw(data.readUInt32LE(descriptor+12)));
  const lookup = data.readUInt32LE(descriptor) || data.readUInt32LE(descriptor+16);
  let slot = raw(lookup);
  for (let entry; (entry = data.readUInt32LE(slot)) !== 0; slot += 4) {
    assert.equal(entry >>> 31, 0, 'Expected named imports');
    imports.push(`${dll}!${cstring(raw(entry)+2)}`);
  }
  descriptor += 20;
}
assert.deepEqual(imports.map(s => s.split('!')[1]).sort(), [
  'AddVectoredExceptionHandler', 'CloseHandle', 'CreateFileW',
  'ExitProcess', 'MessageBoxW', 'ReadFile'
].sort());

const strings = ['flag', 'PKWCTF{', config.flag, config.title,
  ...config.message.split(/\r?\n/).filter(Boolean)];
for (const value of strings) {
  for (const encoding of ['utf8', 'utf16le']) {
    assert.equal(data.indexOf(Buffer.from(value, encoding)), -1,
      `Unexpected plaintext (${encoding}): ${value}`);
  }
}
const report = {
  executable: exe, bytes: data.length,
  sha256: createHash('sha256').update(data).digest('hex'),
  machine: 'x86 PE32', subsystem: 'Windows GUI', nxCompat: false,
  textBytes: text.size, textContainsOnlyMain: true,
  tlsCallbackInData: true, dataReadWriteNonExecutable: true,
  xteaTransfer: 'encoded relative target + junk + push edx; jmp eax',
  xteaTransferRealPathInstructions: 17, xteaEntryJunkPresent: true,
  imports, challengePlaintextScanPassed: true,
  note: 'Static PE checks do not assert the function list of any IDA version.'
};
fs.mkdirSync(path.join(root, 'build/reports'), {recursive: true});
fs.writeFileSync(path.join(root, 'build/reports/binary-check.json'), JSON.stringify(report, null, 2)+'\n');
console.log(JSON.stringify(report, null, 2));
