import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import assert from 'node:assert/strict';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const build = path.join(root, 'build');

export function encryptBlock(block, key) {
  let v0 = block.readUInt32LE(0), v1 = block.readUInt32LE(4), sum = 0;
  for (let i = 0; i < 32; i++) {
    const a = ((((v1 << 4) ^ (v1 >>> 5)) + v1) >>> 0);
    v0 = (v0 + (a ^ ((sum + key[sum & 3]) >>> 0))) >>> 0;
    sum = (sum + 0x9E3779B9) >>> 0;
    const b = ((((v0 << 4) ^ (v0 >>> 5)) + v0) >>> 0);
    v1 = (v1 + (b ^ ((sum + key[(sum >>> 11) & 3]) >>> 0))) >>> 0;
  }
  const result = Buffer.alloc(8);
  result.writeUInt32LE(v0, 0);
  result.writeUInt32LE(v1, 4);
  return result;
}

export function decryptBlock(block, key) {
  let v0 = block.readUInt32LE(0), v1 = block.readUInt32LE(4), sum = 0xC6EF3720;
  for (let i = 0; i < 32; i++) {
    const b = ((((v0 << 4) ^ (v0 >>> 5)) + v0) >>> 0);
    v1 = (v1 - (b ^ ((sum + key[(sum >>> 11) & 3]) >>> 0))) >>> 0;
    sum = (sum - 0x9E3779B9) >>> 0;
    const a = ((((v1 << 4) ^ (v1 >>> 5)) + v1) >>> 0);
    v0 = (v0 - (a ^ ((sum + key[sum & 3]) >>> 0))) >>> 0;
  }
  const result = Buffer.alloc(8);
  result.writeUInt32LE(v0, 0);
  result.writeUInt32LE(v1, 4);
  return result;
}

function constants() {
  fs.mkdirSync(path.join(build, 'author'), {recursive: true});
  const config = JSON.parse(fs.readFileSync(path.join(root, 'config/challenge.json'), 'utf8'));
  assert.match(config.flag, /^PKWCTF\{[\x21-\x7E]+\}$/);
  const raw = Buffer.from(config.flag, 'ascii');
  assert(raw.length > 0 && raw.length <= 80, 'Keep the fixed payload stack buffer in bounds.');
  assert.equal(config.key.length, 4);
  const key = config.key.map(k => { assert.match(k, /^[0-9a-fA-F]{8}$/); return parseInt(k, 16); });
  const pad = 8 - (raw.length % 8);
  const padded = Buffer.concat([raw, Buffer.alloc(pad, pad)]);
  const ciphertext = Buffer.concat(Array.from({length: padded.length / 8}, (_, i) =>
    encryptBlock(padded.subarray(i * 8, i * 8 + 8), key)));
  const recovered = Buffer.concat(Array.from({length: ciphertext.length / 8}, (_, i) =>
    decryptBlock(ciphertext.subarray(i * 8, i * 8 + 8), key)));
  assert.deepEqual(recovered, padded);
  const bytes = b => [...b].map(n => '0x' + n.toString(16).padStart(2, '0')).join(', ');
  const wide = text => Buffer.from(text + '\0', 'utf16le');
  // Hide literal strings in the distributed image, not just their C syntax.
  let state = 0x6C8E9CF5;
  const hide = plain => Buffer.from([...plain].map(b => {
    state = (state ^ (state << 13)) >>> 0;
    state = (state ^ (state >>> 17)) >>> 0;
    state = (state ^ (state << 5)) >>> 0;
    return b ^ (state & 255);
  }));
  const fileName = hide(wide('flag'));
  const title = hide(wide(config.title));
  const message = hide(wide(config.message));
  fs.writeFileSync(path.join(build, 'constants.inc'), [
    `; Generated build data: key and ciphertext only, never the flag plaintext.`,
    `%define FLAG_LENGTH ${raw.length}`,
    `%define PAD_LENGTH ${pad}`,
    `%define PADDED_LENGTH ${padded.length}`,
    `%define STRING_SEED 0x6C8E9CF5`,
    `%macro EMIT_CONSTANTS 0`,
    `xtea_key: dd ${key.map(n => '0x' + n.toString(16)).join(', ')}`,
    `expected_ciphertext: db ${bytes(ciphertext)}`,
    `encoded_strings:`,
    `file_name: db ${bytes(fileName)}`,
    `message_title: db ${bytes(title)}`,
    `message_text: db ${bytes(message)}`,
    `encoded_strings_end:`,
    `%endmacro`, ''
  ].join('\n'));
  fs.writeFileSync(path.join(build, 'author/flag'), raw);
  fs.writeFileSync(path.join(build, 'author/answer.json'), JSON.stringify({
    ...config, flagLength: raw.length, padding: 'PKCS#7', wordOrder: 'little-endian',
    cycles: 32, mode: 'independent 8-byte blocks (ECB)',
    paddedLength: padded.length, ciphertext: ciphertext.toString('hex'),
    blobOffsetOfKey: 0x800, blobOffsetOfCiphertext: 0x810
  }, null, 2) + '\n');
  console.log(`Generated XTEA constants: ${raw.length} input bytes, ${padded.length} encrypted bytes.`);
}

function embed() {
  const data = fs.readFileSync(path.join(build, 'blob.bin'));
  assert.equal(data.length, 0x1000, 'The C IAT layout requires exactly 4096 blob bytes.');
  const rows = [];
  for (let i = 0; i < data.length; i += 16)
    rows.push([...data.subarray(i, i+16)].map(b => '0x' + b.toString(16).padStart(2, '0')).join(', ') + ',');
  fs.writeFileSync(path.join(build, 'blob_bytes.inc'), rows.join('\n') + '\n');
  console.log(`Embedded ${data.length} machine-code/data bytes as a C global initializer.`);
}

if (process.argv[2] === 'constants') constants();
else if (process.argv[2] === 'embed') embed();
