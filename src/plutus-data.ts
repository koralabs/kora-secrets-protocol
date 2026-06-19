// Minimal PlutusData CBOR codec, byte-compatible with Aiken's `cbor.serialise`.
//
// Aiken/Plutus encode data as: constructor `i` -> CBOR tag (121 + i for 0..6), followed by
// the fields as an INDEFINITE array (0x9f .. 0xff) when there are fields, or a DEFINITE empty
// array (0x80) when there are none. Lists are indefinite arrays. Ints are standard CBOR major
// types 0/1; byte strings are major type 2. We hand-roll this (rather than use a generic CBOR
// or @cardano-sdk encoder) because we need to reproduce Aiken's exact bytes — the P2-T1
// fixtures pin them.

export type PlutusData =
  | { kind: 'constr'; index: number; fields: PlutusData[] }
  | { kind: 'int'; value: bigint }
  | { kind: 'bytes'; value: Uint8Array }
  | { kind: 'list'; items: PlutusData[] };

export const PD = {
  constr: (index: number, fields: PlutusData[]): PlutusData => ({ kind: 'constr', index, fields }),
  int: (value: number | bigint): PlutusData => ({ kind: 'int', value: BigInt(value) }),
  bytes: (value: Uint8Array): PlutusData => ({ kind: 'bytes', value }),
  list: (items: PlutusData[]): PlutusData => ({ kind: 'list', items })
};

// ---- encoding -----------------------------------------------------------------

class ByteSink {
  private chunks: number[] = [];
  push(...bytes: number[]): void {
    for (const b of bytes) this.chunks.push(b & 0xff);
  }
  pushBytes(bytes: Uint8Array): void {
    for (const b of bytes) this.chunks.push(b);
  }
  toUint8Array(): Uint8Array {
    return Uint8Array.from(this.chunks);
  }
}

// Major-type header: (majorType << 5) | additional, with minimal-length argument encoding.
function writeHead(sink: ByteSink, major: number, arg: number | bigint): void {
  const n = BigInt(arg);
  const m = major << 5;
  if (n < 24n) {
    sink.push(m | Number(n));
  } else if (n < 0x100n) {
    sink.push(m | 24, Number(n));
  } else if (n < 0x10000n) {
    sink.push(m | 25, Number(n >> 8n) & 0xff, Number(n) & 0xff);
  } else if (n < 0x100000000n) {
    sink.push(m | 26, Number((n >> 24n) & 0xffn), Number((n >> 16n) & 0xffn), Number((n >> 8n) & 0xffn), Number(n & 0xffn));
  } else {
    const bytes: number[] = [];
    let v = n;
    for (let i = 0; i < 8; i++) {
      bytes.unshift(Number(v & 0xffn));
      v >>= 8n;
    }
    sink.push(m | 27, ...bytes);
  }
}

function encodeInto(sink: ByteSink, d: PlutusData): void {
  switch (d.kind) {
    case 'int': {
      if (d.value >= 0n) {
        writeHead(sink, 0, d.value);
      } else {
        writeHead(sink, 1, -d.value - 1n);
      }
      return;
    }
    case 'bytes': {
      // Plutus chunks byte strings longer than 64 bytes; SSR datum fields never exceed that.
      if (d.value.length > 64) {
        throw new Error('plutus-data: byte strings over 64 bytes require chunking (unused by SSR)');
      }
      writeHead(sink, 2, d.value.length);
      sink.pushBytes(d.value);
      return;
    }
    case 'list': {
      sink.push(0x9f); // indefinite array
      for (const item of d.items) encodeInto(sink, item);
      sink.push(0xff);
      return;
    }
    case 'constr': {
      writeConstrTag(sink, d.index);
      if (d.fields.length === 0) {
        sink.push(0x80); // definite empty array
      } else {
        sink.push(0x9f);
        for (const f of d.fields) encodeInto(sink, f);
        sink.push(0xff);
      }
      return;
    }
  }
}

// Constructor tag per Plutus: 0..6 -> 121..127, 7..127 -> 1280..1400, else general form 102.
function writeConstrTag(sink: ByteSink, index: number): void {
  if (index < 0) throw new Error('plutus-data: negative constructor index');
  if (index <= 6) {
    writeHead(sink, 6, 121 + index);
  } else if (index <= 127) {
    writeHead(sink, 6, 1280 + (index - 7));
  } else {
    // General form: tag 102, [index, fields-array] — not needed by SSR (all indices <= 6).
    throw new Error('plutus-data: constructor index > 127 unsupported (unused by SSR)');
  }
}

export function encodePlutusData(d: PlutusData): Uint8Array {
  const sink = new ByteSink();
  encodeInto(sink, d);
  return sink.toUint8Array();
}

// ---- decoding -----------------------------------------------------------------

class ByteReader {
  private readonly buf: Uint8Array;
  private pos: number;
  constructor(buf: Uint8Array) {
    this.buf = buf;
    this.pos = 0;
  }
  byte(): number {
    if (this.pos >= this.buf.length) throw new Error('plutus-data: unexpected end of input');
    return this.buf[this.pos++]!;
  }
  peek(): number {
    if (this.pos >= this.buf.length) throw new Error('plutus-data: unexpected end of input');
    return this.buf[this.pos]!;
  }
  take(n: number): Uint8Array {
    if (this.pos + n > this.buf.length) throw new Error('plutus-data: unexpected end of input');
    const out = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }
  get done(): boolean {
    return this.pos >= this.buf.length;
  }
}

function readArg(reader: ByteReader, additional: number): bigint {
  if (additional < 24) return BigInt(additional);
  if (additional === 24) return BigInt(reader.byte());
  let bytes = 0;
  if (additional === 25) bytes = 2;
  else if (additional === 26) bytes = 4;
  else if (additional === 27) bytes = 8;
  else throw new Error(`plutus-data: unsupported additional info ${additional}`);
  let v = 0n;
  for (const b of reader.take(bytes)) v = (v << 8n) | BigInt(b);
  return v;
}

function decodeFrom(reader: ByteReader): PlutusData {
  const initial = reader.byte();
  const major = initial >> 5;
  const additional = initial & 0x1f;

  switch (major) {
    case 0:
      return { kind: 'int', value: readArg(reader, additional) };
    case 1:
      return { kind: 'int', value: -1n - readArg(reader, additional) };
    case 2: {
      const len = Number(readArg(reader, additional));
      return { kind: 'bytes', value: Uint8Array.from(reader.take(len)) };
    }
    case 4: {
      // array — only indefinite lists are produced by our encoder
      if (additional !== 31) throw new Error('plutus-data: only indefinite lists supported');
      const items: PlutusData[] = [];
      while (reader.peek() !== 0xff) items.push(decodeFrom(reader));
      reader.byte(); // consume 0xff
      return { kind: 'list', items };
    }
    case 6: {
      const tag = Number(readArg(reader, additional));
      const index = constrIndexFromTag(tag);
      const fields = readConstrFields(reader);
      return { kind: 'constr', index, fields };
    }
    default:
      throw new Error(`plutus-data: unsupported CBOR major type ${major}`);
  }
}

function constrIndexFromTag(tag: number): number {
  if (tag >= 121 && tag <= 127) return tag - 121;
  if (tag >= 1280 && tag <= 1400) return tag - 1280 + 7;
  throw new Error(`plutus-data: unsupported constructor tag ${tag}`);
}

function readConstrFields(reader: ByteReader): PlutusData[] {
  const head = reader.byte();
  if (head === 0x80) return []; // definite empty array
  if (head === 0x9f) {
    const fields: PlutusData[] = [];
    while (reader.peek() !== 0xff) fields.push(decodeFrom(reader));
    reader.byte();
    return fields;
  }
  // definite non-empty array (major 4 with length) — accept for robustness when decoding
  // data produced by other encoders.
  const major = head >> 5;
  if (major === 4) {
    const len = head & 0x1f;
    const fields: PlutusData[] = [];
    for (let i = 0; i < len; i++) fields.push(decodeFrom(reader));
    return fields;
  }
  throw new Error(`plutus-data: malformed constructor body byte 0x${head.toString(16)}`);
}

export function decodePlutusData(bytes: Uint8Array): PlutusData {
  return decodeFrom(new ByteReader(bytes));
}
