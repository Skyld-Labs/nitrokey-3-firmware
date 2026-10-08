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
 *   - Fully compliant with NIST CAVP (Cryptographic Algorithm Validation
 * Program)
 *   - Byte-for-byte verified against OpenSSL 3.x EVP/SHA256
 *
 * Properties:
 *   - Zero third-party runtime dependencies (no OpenSSL static linkage)
 *   - Direct 64-byte block streaming (zero intermediate buffer copying on bulk
 * chunks)
 *   - Fast endianness decoding via compiler builtins (__builtin_bswap32 / rev)
 *   - 8-round cyclic macro unrolling maintaining state in registers (A..H)
 *   - Circular 16-word sliding message schedule (w[16]) in L1 cache
 *   - Secure state destruction via clearMemory()
 */

#ifndef SK_SHA256_H
#define SK_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define SK_SHA256_BLOCK_SIZE 64
#define SK_SHA256_DIGEST_SIZE 32

typedef struct {
  uint32_t state[8];
  uint64_t bitlen;
  uint8_t buffer[SK_SHA256_BLOCK_SIZE];
  size_t datalen;
} sk_sha256_ctx;

void sk_sha256_init(sk_sha256_ctx *ctx);
void sk_sha256_update(sk_sha256_ctx *ctx, const uint8_t *data, size_t len);
void sk_sha256_final(sk_sha256_ctx *ctx, uint8_t hash[SK_SHA256_DIGEST_SIZE]);
void sk_sha256(const uint8_t *data, size_t len,
               uint8_t hash[SK_SHA256_DIGEST_SIZE]);

#endif /* SK_SHA256_H */