/**
 * Zero-dependency RFC 7914 scrypt implementation leveraging Web Crypto API PBKDF2.
 * Used for decrypting Aegis Authenticator mobile encrypted backups.
 */

function rotl(a: number, b: number): number {
  return ((a << b) | (a >>> (32 - b))) >>> 0;
}

function salsa20_8(out: Uint32Array, input: Uint32Array) {
  const x = new Uint32Array(16);
  for (let i = 0; i < 16; i++) x[i] = input[i];

  for (let i = 0; i < 8; i += 2) {
    // Column round
    x[4] = (x[4] ^ rotl((x[0] + x[12]) >>> 0, 7)) >>> 0;
    x[8] = (x[8] ^ rotl((x[4] + x[0]) >>> 0, 9)) >>> 0;
    x[12] = (x[12] ^ rotl((x[8] + x[4]) >>> 0, 13)) >>> 0;
    x[0] = (x[0] ^ rotl((x[12] + x[8]) >>> 0, 18)) >>> 0;

    x[9] = (x[9] ^ rotl((x[5] + x[1]) >>> 0, 7)) >>> 0;
    x[13] = (x[13] ^ rotl((x[9] + x[5]) >>> 0, 9)) >>> 0;
    x[1] = (x[1] ^ rotl((x[13] + x[9]) >>> 0, 13)) >>> 0;
    x[5] = (x[5] ^ rotl((x[1] + x[13]) >>> 0, 18)) >>> 0;

    x[14] = (x[14] ^ rotl((x[10] + x[6]) >>> 0, 7)) >>> 0;
    x[2] = (x[2] ^ rotl((x[14] + x[10]) >>> 0, 9)) >>> 0;
    x[6] = (x[6] ^ rotl((x[2] + x[14]) >>> 0, 13)) >>> 0;
    x[10] = (x[10] ^ rotl((x[6] + x[2]) >>> 0, 18)) >>> 0;

    x[3] = (x[3] ^ rotl((x[15] + x[11]) >>> 0, 7)) >>> 0;
    x[7] = (x[7] ^ rotl((x[3] + x[15]) >>> 0, 9)) >>> 0;
    x[11] = (x[11] ^ rotl((x[7] + x[3]) >>> 0, 13)) >>> 0;
    x[15] = (x[15] ^ rotl((x[11] + x[7]) >>> 0, 18)) >>> 0;

    // Row round
    x[1] = (x[1] ^ rotl((x[0] + x[3]) >>> 0, 7)) >>> 0;
    x[2] = (x[2] ^ rotl((x[1] + x[0]) >>> 0, 9)) >>> 0;
    x[3] = (x[3] ^ rotl((x[2] + x[1]) >>> 0, 13)) >>> 0;
    x[0] = (x[0] ^ rotl((x[3] + x[2]) >>> 0, 18)) >>> 0;

    x[6] = (x[6] ^ rotl((x[5] + x[4]) >>> 0, 7)) >>> 0;
    x[7] = (x[7] ^ rotl((x[6] + x[5]) >>> 0, 9)) >>> 0;
    x[4] = (x[4] ^ rotl((x[7] + x[6]) >>> 0, 13)) >>> 0;
    x[5] = (x[5] ^ rotl((x[4] + x[7]) >>> 0, 18)) >>> 0;

    x[11] = (x[11] ^ rotl((x[10] + x[9]) >>> 0, 7)) >>> 0;
    x[8] = (x[8] ^ rotl((x[11] + x[10]) >>> 0, 9)) >>> 0;
    x[9] = (x[9] ^ rotl((x[8] + x[11]) >>> 0, 13)) >>> 0;
    x[10] = (x[10] ^ rotl((x[9] + x[8]) >>> 0, 18)) >>> 0;

    x[12] = (x[12] ^ rotl((x[15] + x[14]) >>> 0, 7)) >>> 0;
    x[13] = (x[13] ^ rotl((x[12] + x[15]) >>> 0, 9)) >>> 0;
    x[14] = (x[14] ^ rotl((x[13] + x[12]) >>> 0, 13)) >>> 0;
    x[15] = (x[15] ^ rotl((x[14] + x[13]) >>> 0, 18)) >>> 0;
  }

  for (let i = 0; i < 16; i++) {
    out[i] = (x[i] + input[i]) >>> 0;
  }
}

function blockMix(out: Uint32Array, input: Uint32Array, r: number) {
  const X = new Uint32Array(16);
  // X = B[2*r - 1]
  const lastChunkOffset = (2 * r - 1) * 16;
  for (let i = 0; i < 16; i++) X[i] = input[lastChunkOffset + i];

  const Y = new Uint32Array(32 * r);
  const temp = new Uint32Array(16);

  for (let i = 0; i < 2 * r; i++) {
    const chunkOffset = i * 16;
    for (let j = 0; j < 16; j++) {
      temp[j] = (X[j] ^ input[chunkOffset + j]) >>> 0;
    }
    salsa20_8(X, temp);

    // Destination index: even i -> Y[i/2], odd i -> Y[r + (i-1)/2]
    const destChunk = i % 2 === 0 ? (i / 2) : (r + (i - 1) / 2);
    const destOffset = destChunk * 16;
    for (let j = 0; j < 16; j++) {
      Y[destOffset + j] = X[j];
    }
  }

  for (let i = 0; i < 32 * r; i++) {
    out[i] = Y[i];
  }
}

function sMix(B: Uint32Array, r: number, N: number) {
  const chunkLen = 32 * r; // in 32-bit words
  const V = new Uint32Array(N * chunkLen);
  const X = new Uint32Array(chunkLen);
  const T = new Uint32Array(chunkLen);

  // X = B
  for (let i = 0; i < chunkLen; i++) X[i] = B[i];

  // 1: for i = 0 to N - 1 do V[i] = X; X = BlockMix(X)
  for (let i = 0; i < N; i++) {
    const vOffset = i * chunkLen;
    for (let j = 0; j < chunkLen; j++) V[vOffset + j] = X[j];
    blockMix(T, X, r);
    for (let j = 0; j < chunkLen; j++) X[j] = T[j];
  }

  // 2: for i = 0 to N - 1 do
  for (let i = 0; i < N; i++) {
    // j = Integerify(X) mod N = X[2*r - 1][0] mod N
    const lastChunk = (2 * r - 1) * 16;
    const j = (X[lastChunk] >>> 0) % N;
    const vOffset = j * chunkLen;

    for (let k = 0; k < chunkLen; k++) {
      T[k] = (X[k] ^ V[vOffset + k]) >>> 0;
    }
    blockMix(X, T, r);
  }

  // B = X
  for (let i = 0; i < chunkLen; i++) B[i] = X[i];

  // Purge large intermediate buffers (up to 32MB) to immediately free memory
  V.fill(0);
  T.fill(0);
  X.fill(0);
}

async function pbkdf2HmacSha256(
  passwordBytes: Uint8Array,
  saltBytes: Uint8Array,
  iterations: number,
  lengthBytes: number
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    'raw',
    passwordBytes as unknown as BufferSource,
    'PBKDF2',
    false,
    ['deriveBits']
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: saltBytes as unknown as BufferSource,
      iterations,
      hash: 'SHA-256',
    },
    key,
    lengthBytes * 8
  );

  return new Uint8Array(bits);
}

/**
 * Pure TypeScript scrypt implementation
 */
export async function scrypt(
  password: string | Uint8Array,
  salt: Uint8Array,
  N: number,
  r: number,
  p: number,
  dkLen: number
): Promise<Uint8Array> {
  const encoder = new TextEncoder();
  const pwdBytes = typeof password === 'string' ? encoder.encode(password) : password;

  // 1. Initial PBKDF2 to derive B
  const bByteLen = p * 128 * r;
  const B_bytes = await pbkdf2HmacSha256(pwdBytes, salt, 1, bByteLen);

  // Convert to 32-bit words for fast bitwise ops
  const B_words = new Uint32Array(
    B_bytes.buffer,
    B_bytes.byteOffset,
    B_bytes.byteLength / 4
  );

  const wordsPerBlock = 32 * r;

  // 2. SMix each block of size 128*r
  for (let i = 0; i < p; i++) {
    const block = B_words.subarray(i * wordsPerBlock, (i + 1) * wordsPerBlock);
    sMix(block, r, N);
  }

  // 3. Final PBKDF2
  const finalKey = await pbkdf2HmacSha256(pwdBytes, B_bytes, 1, dkLen);
  return finalKey;
}
