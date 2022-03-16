export function uint8ArrayToReader(arr: Uint8Array) {
  let offset = 0;
  return {
    read(p: Uint8Array) {
      if (offset >= arr.length) {
        return Promise.resolve(null);
      }
      const n = Math.min(p.length, arr.length - offset);
      p.set(arr.subarray(offset, offset + n));
      offset += n;
      return Promise.resolve(n);
    },
  };
}

export async function readN(
  reader: Deno.Reader,
  n: number,
): Promise<Uint8Array> {
  const out = new Uint8Array(n);
  let nRead = 0;
  while (nRead < n) {
    const m = await reader.read(out.subarray(nRead));
    if (m === null) {
      throw new Deno.errors.UnexpectedEof(
        `reached EOF but we expected to read ${n - nRead} more bytes`,
      );
    }
    nRead += m;
  }
  return out;
}
