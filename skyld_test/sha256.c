/*
 * Skyld SDK — Standalone SHA-256 Engine
 *
 * Formal Specifications:
 *   - NIST FIPS PUB 180-4: Secure Hash Standard (SHS)
 *     Section 4.1.2 (Functions), Section 4.2.2 (Constants),
 *     Section 5.1.1 (Padding), Section 6.2.2 (Calculation)
 *
 * Algorithmic Lineage & Design Patterns:
 *   - Colin Percival (FreeBSD Security Officer, sys/crypto/sha2/sha256c.c)
 *   - Brad Conte (crypto-algorithms, public domain reference engine)
 *   - Linux Kernel Crypto API (crypto/sha256_generic.c)
 *
 * Validation:
 *   - Compliant with NIST CAVP (Cryptographic Algorithm Validation
 * Program)
 *   - Byte-for-byte verified against OpenSSL 3.x EVP/SHA256
 */

#include "sha256.h"
#include <string.h>

#define ROTRIGHT(a, b) (((a) >> (b)) | ((a) << (32 - (b))))

#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x, 2) ^ ROTRIGHT(x, 13) ^ ROTRIGHT(x, 22))
#define EP1(x) (ROTRIGHT(x, 6) ^ ROTRIGHT(x, 11) ^ ROTRIGHT(x, 25))
#define SIG0(x) (ROTRIGHT(x, 7) ^ ROTRIGHT(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x, 17) ^ ROTRIGHT(x, 19) ^ ((x) >> 10))

/* External linkage prevents Polaris GlobalsEncryption (gvenc) from injecting
   redundant runtime decryption calls on hot SHA-256 transformations. */
const uint32_t sk_sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

/*
 * Unaligned 32-bit big-endian load:
 * - Uses __builtin_memcpy to strictly prevent aliasing & alignment UB.
 * - Fixed 4-byte size is inlined into a single load (mov/movbe); no libc symbol
 *  is emitted (immune to LD_PRELOAD hooking and leaves .dynsym clean).
 * - Using memcpy adds non-negligible overhead because it prevents inlining
 *  and forces a full function call.
 */
static inline uint32_t load_be32(const uint8_t *p) {
  uint32_t val;
  __builtin_memcpy(&val, p, sizeof(val));
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
  return val;
#else
  return __builtin_bswap32(val);
#endif
}

#define RND(a, b, c, d, e, f, g, h, k, w)                                      \
  do {                                                                         \
    uint32_t t1 = (h) + EP1(e) + CH((e), (f), (g)) + (k) + (w);                \
    uint32_t t2 = EP0(a) + MAJ((a), (b), (c));                                 \
    (d) += t1;                                                                 \
    (h) = t1 + t2;                                                             \
  } while (0)

#define SCHEDULE(i)                                                            \
  (w[(i) & 15] +=                                                              \
   SIG1(w[((i) - 2) & 15]) + w[((i) - 7) & 15] + SIG0(w[((i) - 15) & 15]))

#define ROUND8(base)                                                           \
  RND(a, b, c, d, e, f, g, h, sk_sha256_k[(base) + 0], SCHEDULE((base) + 0));  \
  RND(h, a, b, c, d, e, f, g, sk_sha256_k[(base) + 1], SCHEDULE((base) + 1));  \
  RND(g, h, a, b, c, d, e, f, sk_sha256_k[(base) + 2], SCHEDULE((base) + 2));  \
  RND(f, g, h, a, b, c, d, e, sk_sha256_k[(base) + 3], SCHEDULE((base) + 3));  \
  RND(e, f, g, h, a, b, c, d, sk_sha256_k[(base) + 4], SCHEDULE((base) + 4));  \
  RND(d, e, f, g, h, a, b, c, sk_sha256_k[(base) + 5], SCHEDULE((base) + 5));  \
  RND(c, d, e, f, g, h, a, b, sk_sha256_k[(base) + 6], SCHEDULE((base) + 6));  \
  RND(b, c, d, e, f, g, h, a, sk_sha256_k[(base) + 7], SCHEDULE((base) + 7))

static void sk_sha256_transform(sk_sha256_ctx *ctx,
                                const uint8_t data[SK_SHA256_BLOCK_SIZE]) {
  uint32_t a = ctx->state[0];
  uint32_t b = ctx->state[1];
  uint32_t c = ctx->state[2];
  uint32_t d = ctx->state[3];
  uint32_t e = ctx->state[4];
  uint32_t f = ctx->state[5];
  uint32_t g = ctx->state[6];
  uint32_t h = ctx->state[7];

  uint32_t w[16];

  /* Rounds 0 to 7: direct load */
  w[0] = load_be32(data + 0);
  RND(a, b, c, d, e, f, g, h, sk_sha256_k[0], w[0]);
  w[1] = load_be32(data + 4);
  RND(h, a, b, c, d, e, f, g, sk_sha256_k[1], w[1]);
  w[2] = load_be32(data + 8);
  RND(g, h, a, b, c, d, e, f, sk_sha256_k[2], w[2]);
  w[3] = load_be32(data + 12);
  RND(f, g, h, a, b, c, d, e, sk_sha256_k[3], w[3]);
  w[4] = load_be32(data + 16);
  RND(e, f, g, h, a, b, c, d, sk_sha256_k[4], w[4]);
  w[5] = load_be32(data + 20);
  RND(d, e, f, g, h, a, b, c, sk_sha256_k[5], w[5]);
  w[6] = load_be32(data + 24);
  RND(c, d, e, f, g, h, a, b, sk_sha256_k[6], w[6]);
  w[7] = load_be32(data + 28);
  RND(b, c, d, e, f, g, h, a, sk_sha256_k[7], w[7]);

  /* Rounds 8 to 15: direct load */
  w[8] = load_be32(data + 32);
  RND(a, b, c, d, e, f, g, h, sk_sha256_k[8], w[8]);
  w[9] = load_be32(data + 36);
  RND(h, a, b, c, d, e, f, g, sk_sha256_k[9], w[9]);
  w[10] = load_be32(data + 40);
  RND(g, h, a, b, c, d, e, f, sk_sha256_k[10], w[10]);
  w[11] = load_be32(data + 44);
  RND(f, g, h, a, b, c, d, e, sk_sha256_k[11], w[11]);
  w[12] = load_be32(data + 48);
  RND(e, f, g, h, a, b, c, d, sk_sha256_k[12], w[12]);
  w[13] = load_be32(data + 52);
  RND(d, e, f, g, h, a, b, c, sk_sha256_k[13], w[13]);
  w[14] = load_be32(data + 56);
  RND(c, d, e, f, g, h, a, b, sk_sha256_k[14], w[14]);
  w[15] = load_be32(data + 60);
  RND(b, c, d, e, f, g, h, a, sk_sha256_k[15], w[15]);

  /* Rounds 16 to 63: circular 16-word schedule with 8-round cyclic unrolling */
  ROUND8(16);
  ROUND8(24);
  ROUND8(32);
  ROUND8(40);
  ROUND8(48);
  ROUND8(56);

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}

void sk_sha256_init(sk_sha256_ctx *ctx) {
  ctx->datalen = 0;
  ctx->bitlen = 0;
  ctx->state[0] = 0x6a09e667;
  ctx->state[1] = 0xbb67ae85;
  ctx->state[2] = 0x3c6ef372;
  ctx->state[3] = 0xa54ff53a;
  ctx->state[4] = 0x510e527f;
  ctx->state[5] = 0x9b05688c;
  ctx->state[6] = 0x1f83d9ab;
  ctx->state[7] = 0x5be0cd19;
}

void sk_sha256_update(sk_sha256_ctx *ctx, const uint8_t *data, size_t len) {
  if (len == 0) {
    return;
  }

  ctx->bitlen += (uint64_t)len * 8;

  /* If leftover bytes exist in buffer, complete the block first */
  if (ctx->datalen > 0) {
    size_t needed = SK_SHA256_BLOCK_SIZE - ctx->datalen;
    if (len < needed) {
      memcpy(ctx->buffer + ctx->datalen, data, len);
      ctx->datalen += len;
      return;
    }
    memcpy(ctx->buffer + ctx->datalen, data, needed);
    sk_sha256_transform(ctx, ctx->buffer);
    data += needed;
    len -= needed;
    ctx->datalen = 0;
  }

  /* Process full 64-byte blocks directly from source memory (no byte-by-byte
   * copy) */
  while (len >= SK_SHA256_BLOCK_SIZE) {
    sk_sha256_transform(ctx, data);
    data += SK_SHA256_BLOCK_SIZE;
    len -= SK_SHA256_BLOCK_SIZE;
  }

  /* Store remaining trailing bytes into buffer */
  if (len > 0) {
    memcpy(ctx->buffer, data, len);
    ctx->datalen = len;
  }
}

void sk_sha256_final(sk_sha256_ctx *ctx, uint8_t hash[SK_SHA256_DIGEST_SIZE]) {
  size_t i = ctx->datalen;

  /* Pad with 0x80 then zeroes */
  if (ctx->datalen < 56) {
    ctx->buffer[i++] = 0x80;
    while (i < 56) {
      ctx->buffer[i++] = 0x00;
    }
  } else {
    ctx->buffer[i++] = 0x80;
    while (i < SK_SHA256_BLOCK_SIZE) {
      ctx->buffer[i++] = 0x00;
    }
    sk_sha256_transform(ctx, ctx->buffer);
    for (size_t b = 0; b < 56; ++b) {
      ctx->buffer[b] = 0x00;
    }
  }

  uint64_t total_bits = ctx->bitlen;
  ctx->buffer[56] = (uint8_t)(total_bits >> 56);
  ctx->buffer[57] = (uint8_t)(total_bits >> 48);
  ctx->buffer[58] = (uint8_t)(total_bits >> 40);
  ctx->buffer[59] = (uint8_t)(total_bits >> 32);
  ctx->buffer[60] = (uint8_t)(total_bits >> 24);
  ctx->buffer[61] = (uint8_t)(total_bits >> 16);
  ctx->buffer[62] = (uint8_t)(total_bits >> 8);
  ctx->buffer[63] = (uint8_t)(total_bits);
  sk_sha256_transform(ctx, ctx->buffer);

  for (i = 0; i < 4; ++i) {
    hash[i] = (uint8_t)((ctx->state[0] >> (24 - i * 8)) & 0xff);
    hash[i + 4] = (uint8_t)((ctx->state[1] >> (24 - i * 8)) & 0xff);
    hash[i + 8] = (uint8_t)((ctx->state[2] >> (24 - i * 8)) & 0xff);
    hash[i + 12] = (uint8_t)((ctx->state[3] >> (24 - i * 8)) & 0xff);
    hash[i + 16] = (uint8_t)((ctx->state[4] >> (24 - i * 8)) & 0xff);
    hash[i + 20] = (uint8_t)((ctx->state[5] >> (24 - i * 8)) & 0xff);
    hash[i + 24] = (uint8_t)((ctx->state[6] >> (24 - i * 8)) & 0xff);
    hash[i + 28] = (uint8_t)((ctx->state[7] >> (24 - i * 8)) & 0xff);
  }
}

void sk_sha256(const uint8_t *data, size_t len,
               uint8_t hash[SK_SHA256_DIGEST_SIZE]) {
  sk_sha256_ctx ctx;
  sk_sha256_init(&ctx);
  sk_sha256_update(&ctx, data, len);
  sk_sha256_final(&ctx, hash);
}