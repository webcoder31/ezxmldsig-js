/**
 * A DER writer and reader for the test helpers, written apart from
 * src/core/der.ts so that the structures the library is tested on do not come
 * from the code under test.
 */

export function der(tag: number, ...content: Buffer[]): Buffer {
  const body = Buffer.concat(content);
  const length = body.length < 128 ? Buffer.from([body.length]) : body.length < 256 ? Buffer.from([0x81, body.length]) : Buffer.from([0x82, body.length >> 8, body.length & 0xff]);
  return Buffer.concat([Buffer.from([tag]), length, body]);
}
export const seq = (...c: Buffer[]) => der(0x30, ...c);
export const set = (...c: Buffer[]) => der(0x31, ...c);
export const octets = (b: Buffer) => der(0x04, b);
export const int = (n: number | Buffer) => {
  const bytes = typeof n === 'number' ? Buffer.from([n]) : n;
  return der(0x02, bytes[0]! & 0x80 ? Buffer.concat([Buffer.from([0]), bytes]) : bytes);
};
export function oid(dotted: string): Buffer {
  const [a, b, ...rest] = dotted.split('.').map(Number);
  const bytes = [a! * 40 + b!];
  for (const arc of rest) {
    const group = [arc & 0x7f];
    for (let v = arc >> 7; v > 0; v >>= 7) group.unshift((v & 0x7f) | 0x80);
    bytes.push(...group);
  }
  return der(0x06, Buffer.from(bytes));
}
export function children(buffer: Buffer): { tag: number; content: Buffer }[] {
  const out = [];
  for (let i = 0; i < buffer.length;) {
    const tag = buffer[i++]!;
    let length = buffer[i++]!;
    if (length & 0x80) {
      const n = length & 0x7f;
      length = 0;
      for (let k = 0; k < n; k++) length = length * 256 + buffer[i++]!;
    }
    const start = i;
    i += length;
    out.push({ tag, content: buffer.subarray(start, i) });
  }
  return out;
}

/** A Time: UTCTime up to 2049, GeneralizedTime after (RFC 5280, 4.1.2.5). */
export function time(date: Date): Buffer {
  const text = date.toISOString().replace(/[-:T]/g, '').replace(/\.\d{3}Z$/, 'Z');
  return date.getUTCFullYear() < 2050 ? der(0x17, Buffer.from(text.slice(2))) : der(0x18, Buffer.from(text));
}
