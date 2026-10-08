/*
GIFT-128 implementation
Written by: Siang Meng Sim
Email: crypto.s.m.sim@gmail.com
Date: 08 Feb 2019
*/
#ifndef GIFT128_H
#define GIFT128_H

#define TAGBYTES 16
#define NONCEBYTES 16
#define KEY_SIZE 16

#define COFB_ENCRYPT 1
#define COFB_DECRYPT 0

int cofb_crypt(unsigned char *out, unsigned char *k, unsigned char *n,
                      unsigned char *a, unsigned alen, unsigned char *in,
                      unsigned inlen, int encrypting);

#endif // GIFT128_H