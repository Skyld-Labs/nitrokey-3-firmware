/*
GIFT-128 (bitslice) implementations
Prepared by: Siang Meng Sim
Email: crypto.s.m.sim@gmail.com
Date: 23 Mar 2019
*/
#include "gift128.h"

#include <stdint.h>
#include <string.h>


typedef unsigned char block[16];
typedef unsigned char half_block[8];

/*Round constants*/
const unsigned char GIFT_RC[40] = {
    0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B, 0x37, 0x2F,
    0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E, 0x1D, 0x3A, 0x35, 0x2B,
    0x16, 0x2C, 0x18, 0x30, 0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E,
    0x1C, 0x38, 0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A};

uint32_t rowperm(uint32_t S, int B0_pos, int B1_pos, int B2_pos, int B3_pos) {
  uint32_t T = 0;
  int b;
  for (b = 0; b < 8; b++) {
    T |= ((S >> (4 * b + 0)) & 0x1) << (b + 8 * B0_pos);
    T |= ((S >> (4 * b + 1)) & 0x1) << (b + 8 * B1_pos);
    T |= ((S >> (4 * b + 2)) & 0x1) << (b + 8 * B2_pos);
    T |= ((S >> (4 * b + 3)) & 0x1) << (b + 8 * B3_pos);
  }
  return T;
}

void giftb128(uint8_t P[16], const uint8_t K[16], uint8_t C[16]) {
  int round;
  uint32_t S[4], T;
  uint16_t W[8], T6, T7;

  S[0] = ((uint32_t)P[0] << 24) | ((uint32_t)P[1] << 16) |
         ((uint32_t)P[2] << 8) | (uint32_t)P[3];
  S[1] = ((uint32_t)P[4] << 24) | ((uint32_t)P[5] << 16) |
         ((uint32_t)P[6] << 8) | (uint32_t)P[7];
  S[2] = ((uint32_t)P[8] << 24) | ((uint32_t)P[9] << 16) |
         ((uint32_t)P[10] << 8) | (uint32_t)P[11];
  S[3] = ((uint32_t)P[12] << 24) | ((uint32_t)P[13] << 16) |
         ((uint32_t)P[14] << 8) | (uint32_t)P[15];

  W[0] = ((uint16_t)K[0] << 8) | (uint16_t)K[1];
  W[1] = ((uint16_t)K[2] << 8) | (uint16_t)K[3];
  W[2] = ((uint16_t)K[4] << 8) | (uint16_t)K[5];
  W[3] = ((uint16_t)K[6] << 8) | (uint16_t)K[7];
  W[4] = ((uint16_t)K[8] << 8) | (uint16_t)K[9];
  W[5] = ((uint16_t)K[10] << 8) | (uint16_t)K[11];
  W[6] = ((uint16_t)K[12] << 8) | (uint16_t)K[13];
  W[7] = ((uint16_t)K[14] << 8) | (uint16_t)K[15];

  for (round = 0; round < 40; round++) {
    /*===SubCells===*/
    S[1] ^= S[0] & S[2];
    S[0] ^= S[1] & S[3];
    S[2] ^= S[0] | S[1];
    S[3] ^= S[2];
    S[1] ^= S[3];
    S[3] ^= 0xffffffff;
    S[2] ^= S[0] & S[1];

    T = S[0];
    S[0] = S[3];
    S[3] = T;

    /*===PermBits===*/
    S[0] = rowperm(S[0], 0, 3, 2, 1);
    S[1] = rowperm(S[1], 1, 0, 3, 2);
    S[2] = rowperm(S[2], 2, 1, 0, 3);
    S[3] = rowperm(S[3], 3, 2, 1, 0);

    /*===AddRoundKey===*/
    S[2] ^= ((uint32_t)W[2] << 16) | (uint32_t)W[3];
    S[1] ^= ((uint32_t)W[6] << 16) | (uint32_t)W[7];

    /*Add round constant*/
    S[3] ^= 0x80000000 ^ GIFT_RC[round];

    /*===Key state update===*/
    T6 = (W[6] >> 2) | (W[6] << 14);
    T7 = (W[7] >> 12) | (W[7] << 4);
    W[7] = W[5];
    W[6] = W[4];
    W[5] = W[3];
    W[4] = W[2];
    W[3] = W[1];
    W[2] = W[0];
    W[1] = T7;
    W[0] = T6;
  }

  C[0] = S[0] >> 24;
  C[1] = S[0] >> 16;
  C[2] = S[0] >> 8;
  C[3] = S[0];
  C[4] = S[1] >> 24;
  C[5] = S[1] >> 16;
  C[6] = S[1] >> 8;
  C[7] = S[1];
  C[8] = S[2] >> 24;
  C[9] = S[2] >> 16;
  C[10] = S[2] >> 8;
  C[11] = S[2];
  C[12] = S[3] >> 24;
  C[13] = S[3] >> 16;
  C[14] = S[3] >> 8;
  C[15] = S[3];

  return;
}

/* ------------------------------------------------------------------------- */
static void padding(block d, block s, unsigned no_of_bytes) {
  unsigned i;
  block tmp;
  if (no_of_bytes == 0) {
    for (i = 0; i < 16; i++)
      tmp[i] = 0;
    tmp[0] = 0x80;
  } else if (no_of_bytes < 16) {
    for (i = 0; i < no_of_bytes; i++)
      tmp[i] = s[i];
    tmp[no_of_bytes] = 0x80;
    for (i = no_of_bytes + 1; i < 16; i++)
      tmp[i] = 0;
  } else {
    for (i = 0; i < 16; i++)
      tmp[i] = s[i];
  }
  for (i = 0; i < 16; i++)
    d[i] = tmp[i];
}

/* ------------------------------------------------------------------------- */
static void xor_block(block d, block s1, block s2, unsigned no_of_bytes) {
  unsigned i;
  for (i = 0; i < no_of_bytes; i++)
    d[i] = s1[i] ^ s2[i];
}
static void xor_topbar_block(block d, block s1, half_block s2) {
  unsigned i;
  block tmp;
  for (i = 0; i < 8; i++)
    tmp[i] = s1[i] ^ s2[i];
  for (i = 8; i < 16; i++)
    tmp[i] = s1[i];

  for (i = 0; i < 16; i++)
    d[i] = tmp[i];
}

/* ------------------------------------------------------------------------- */
static void double_half_block(half_block d, half_block s) {
  unsigned i;
  half_block tmp;
  /*x^{64} + x^4 + x^3 + x + 1*/
  for (i = 0; i < 7; i++)
    tmp[i] = (s[i] << 1) | (s[i + 1] >> 7);
  tmp[7] = (s[7] << 1) ^ ((s[0] >> 7) * 27);

  for (i = 0; i < 8; i++)
    d[i] = tmp[i];
}
static void triple_half_block(half_block d, half_block s) {
  unsigned i;
  half_block tmp;
  double_half_block(tmp, s);
  for (i = 0; i < 8; i++)
    d[i] = s[i] ^ tmp[i];
}
/* ------------------------------------------------------------------------- */
static void G(block d, block s) {
  unsigned i;
  block tmp;
  /*Y[1],Y[2] -> Y[2],Y[1]<<<1*/
  for (i = 0; i < 8; i++) {
    tmp[i] = s[8 + i];
  }
  for (i = 0; i < 7; i++) {
    tmp[i + 8] = s[i] << 1 | s[i + 1] >> 7;
  }
  tmp[7 + 8] = s[7] << 1 | s[0] >> 7;

  for (i = 0; i < 16; i++)
    d[i] = tmp[i];
}
static void pho1(block d, block Y, block M, int no_of_bytes) {
  block tmpM;
  G(Y, Y);
  padding(tmpM, M, no_of_bytes);
  xor_block(d, Y, tmpM, 16);
}
static void pho(block Y, block M, block X, block C, int no_of_bytes) {
  xor_block(C, Y, M, no_of_bytes);
  pho1(X, Y, M, no_of_bytes);
}
static void phoprime(block Y, block C, block X, block M, int no_of_bytes) {
  xor_block(M, Y, C, no_of_bytes);
  pho1(X, Y, M, no_of_bytes);
}

/* ------------------------------------------------------------------------- */
int cofb_crypt(unsigned char *out, unsigned char *k, unsigned char *n,
               unsigned char *a, unsigned alen, unsigned char *in,
               unsigned inlen, int encrypting) {
  unsigned i;
  unsigned emptyA, emptyM;

  if (!encrypting) {
    if (inlen < TAGBYTES)
      return -1;
    inlen -= TAGBYTES;
  }

  if (alen == 0)
    emptyA = 1;
  else
    emptyA = 0;

  if (inlen == 0)
    emptyM = 1;
  else
    emptyM = 0;

  /*Mask-Gen*/
  block Y, input;
  half_block offset;
  /*nonce is 128-bit*/
  for (i = 0; i < 16; i++)
    input[i] = n[i];

  giftb128(input, k, Y);
  for (i = 0; i < 8; i++)
    offset[i] = Y[i];

  /*Process AD*/
  /*non-empty A*/
  /*full blocks*/
  while (alen > 16) {
    /* X[i] = (A[i] + G(Y[i-1])) + offset */
    pho1(input, Y, a, 16);
    /* offset = 2*offset */
    double_half_block(offset, offset);
    xor_topbar_block(input, input, offset);
    /* Y[i] = E(X[i]) */
    giftb128(input, k, Y);

    a = a + 16;
    alen -= 16;
  }

  /* last block */
  /* full block: offset = 3*offset */
  /* partial block: offset = 3^2*offset */
  triple_half_block(offset, offset);
  if ((alen % 16 != 0) || (emptyA)) {
    triple_half_block(offset, offset);
  }

  if (emptyM) {
    /* empty M: offset = 3^2*offset */
    triple_half_block(offset, offset);
    triple_half_block(offset, offset);
  }

  /* X[i] = (pad(A[i]) + G(Y[i-1])) + offset */
  pho1(input, Y, a, alen);

  xor_topbar_block(input, input, offset);
  /* Y[a] = E(X[a]) */
  giftb128(input, k, Y);

  /* Process M */
  /* full blocks */
  while (inlen > 16) {
    double_half_block(offset, offset);
    /* C[i] = Y[i+a-1] + M[i]*/
    /* X[i] = M[i] + G(Y[i+a-1]) + offset */
    if (encrypting) {
      pho(Y, in, input, out, 16);
    } else {
      phoprime(Y, in, input, out, 16);
    }

    xor_topbar_block(input, input, offset);
    /* Y[i] = E(X[i+a]) */
    giftb128(input, k, Y);

    in = in + 16;
    out = out + 16;
    inlen -= 16;
  }

  if (!emptyM) {
    /* full block: offset = 3*offset */
    /* empty data / partial block: offset = 3^2*offset */
    triple_half_block(offset, offset);
    if (inlen % 16 != 0) {
      triple_half_block(offset, offset);
    }
    /* last block */
    /* C[m] = Y[m+a-1] + M[m]*/
    /* X[a+m] = M[m] + G(Y[m+a-1]) + offset */
    if (encrypting) {
      pho(Y, in, input, out, inlen);
      out += inlen;
    } else {
      phoprime(Y, in, input, out, inlen);
      in += inlen;
    }

    xor_topbar_block(input, input, offset);
    /* T = E(X[m+a]) */
    giftb128(input, k, Y);
  }

  if (encrypting) {
    memcpy(out, Y, TAGBYTES);
    return 0;
  } else
    return (memcmp(in, Y, TAGBYTES) ? -1 : 0); /* Check for validity */
}