#ifndef _SPECK_H_
#define _SPECK_H_

#ifdef MAVLINK_USE_CXX_NAMESPACE
namespace mavlink {
#endif

#ifndef MAVLINK_HELPER
#define MAVLINK_HELPER
#endif
/*****************************************************************************/
/* Speck 128/128 in counter (CTR) mode.                                       */
/*                                                                            */
/* Beaulieu, Shors, Smith, Treatman-Clark, Weeks, Wingers, "The SIMON and     */
/* SPECK Families of Lightweight Block Ciphers", NSA, 2013, §4 / Fig. 4.4.    */
/* Used in CTR mode with a 128-bit block, key and IV, as in MAVShield         */
/* (Dixit et al., arXiv:2504.20626, §IV-B3).                                  */
/*                                                                            */
/* Same API shape as aes.h (tiny-AES-C):                                      */
/*   SPECK_init_ctx_iv(&ctx, key, iv);  SPECK_CTR_xcrypt_buffer(&ctx, buf, n); */
/* CTR is symmetric: the same call encrypts and decrypts.                     */
/*                                                                            */
/* Byte order: a 16-byte block b[0..15] is the word pair (x, y) with          */
/*   y = little-endian b[0..7],  x = little-endian b[8..15];                  */
/* the key k[0..15] is (l0, k0) with k0 = LE k[0..7], l0 = LE k[8..15].       */
/* This reproduces the paper's test vector (Appendix C, key bytes 00..0f).    */
/* The CTR counter is the 16-byte IV, incremented as a big-endian integer,    */
/* exactly like aes.h. This matches the implementation deployed in the        */
/* crypto_mavlink project (tools/ciphers/speck_ctr.h) byte for byte.          */
/*****************************************************************************/

/*****************************************************************************/
/* Includes:                                                                 */
/*****************************************************************************/
#include <string.h> // memcpy
#include <stdint.h>

#define SPECK_BLOCKLEN 16 // Block length in bytes - Speck 128/x has a 128-bit block
#define SPECK_KEYLEN   16 // Key length in bytes (Speck 128/128)
#define SPECK_ROUNDS   32 // Number of rounds T for n = 64, m = 2

struct SPECK_ctx
{
  uint64_t RoundKey[SPECK_ROUNDS];
  uint8_t  Iv[SPECK_BLOCKLEN];
};

/*****************************************************************************/
/* Defines:                                                                  */
/*****************************************************************************/
// Rotation amounts (alpha, beta) for word size n = 64.
#define SPECK_ALPHA 8
#define SPECK_BETA  3

#define SPECK_ROR(x, r) (((x) >> (r)) | ((x) << (64 - (r))))
#define SPECK_ROL(x, r) (((x) << (r)) | ((x) >> (64 - (r))))

/*****************************************************************************/
/* Private functions:                                                        */
/*****************************************************************************/
// Words are loaded/stored byte by byte: independent of host endianness and
// of buffer alignment.
static uint64_t speck_load64(const uint8_t* p)
{
  return  (uint64_t)p[0]        | ((uint64_t)p[1] << 8)  |
         ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
         ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
         ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

static void speck_store64(uint8_t* p, uint64_t v)
{
  uint8_t i;
  for (i = 0; i < 8; ++i)
  {
    p[i] = (uint8_t)(v >> (8 * i));
  }
}

// Key schedule (m = 2): the round function, with the round number as key.
//   l[i+1] = (k[i] + S^-alpha l[i]) ^ i
//   k[i+1] = S^beta k[i] ^ l[i+1]
static void SpeckKeyExpansion(uint64_t* RoundKey, const uint8_t* Key)
{
  uint64_t k = speck_load64(Key);
  uint64_t l = speck_load64(Key + 8);
  unsigned i;

  RoundKey[0] = k;
  for (i = 0; i < SPECK_ROUNDS - 1; ++i)
  {
    l = (SPECK_ROR(l, SPECK_ALPHA) + k) ^ (uint64_t)i;
    k = SPECK_ROL(k, SPECK_BETA) ^ l;
    RoundKey[i + 1] = k;
  }
}

// Speck round function, applied SPECK_ROUNDS times, in place on one block.
//   x = (S^-alpha x + y) ^ k[i]
//   y = S^beta y ^ x
static void SpeckCipher(uint8_t* block, const uint64_t* RoundKey)
{
  uint64_t y = speck_load64(block);
  uint64_t x = speck_load64(block + 8);
  unsigned i;

  for (i = 0; i < SPECK_ROUNDS; ++i)
  {
    x = (SPECK_ROR(x, SPECK_ALPHA) + y) ^ RoundKey[i];
    y = SPECK_ROL(y, SPECK_BETA) ^ x;
  }
  speck_store64(block, y);
  speck_store64(block + 8, x);
}

/*****************************************************************************/
/* Public functions:                                                         */
/*****************************************************************************/
MAVLINK_HELPER void SPECK_init_ctx(struct SPECK_ctx* ctx, const uint8_t* key)
{
  SpeckKeyExpansion(ctx->RoundKey, key);
}

MAVLINK_HELPER void SPECK_init_ctx_iv(struct SPECK_ctx* ctx, const uint8_t* key, const uint8_t* iv)
{
  SpeckKeyExpansion(ctx->RoundKey, key);
  memcpy(ctx->Iv, iv, SPECK_BLOCKLEN);
}

MAVLINK_HELPER void SPECK_ctx_set_iv(struct SPECK_ctx* ctx, const uint8_t* iv)
{
  memcpy(ctx->Iv, iv, SPECK_BLOCKLEN);
}

/* Encrypts one 16-byte block in place (ECB, single block). CTR mode does not
   need it; it is here for the known-answer test against the paper vector. */
MAVLINK_HELPER void SPECK_ECB_encrypt(const struct SPECK_ctx* ctx, uint8_t* buf)
{
  SpeckCipher(buf, ctx->RoundKey);
}

/* Symmetrical operation: same function for encrypting as for decrypting. Note any IV/nonce should never be reused with the same key */
MAVLINK_HELPER void SPECK_CTR_xcrypt_buffer(struct SPECK_ctx* ctx, uint8_t* buf, uint32_t length)
{
  uint8_t buffer[SPECK_BLOCKLEN];

  unsigned i;
  int bi;
  for (i = 0, bi = SPECK_BLOCKLEN; i < length; ++i, ++bi)
  {
    if (bi == SPECK_BLOCKLEN) /* we need to regen xor compliment in buffer */
    {
      memcpy(buffer, ctx->Iv, SPECK_BLOCKLEN);
      SpeckCipher(buffer, ctx->RoundKey);

      /* Increment Iv and handle overflow */
      for (bi = (SPECK_BLOCKLEN - 1); bi >= 0; --bi)
      {
        /* inc will overflow */
        if (ctx->Iv[bi] == 255)
        {
          ctx->Iv[bi] = 0;
          continue;
        }
        ctx->Iv[bi] += 1;
        break;
      }
      bi = 0;
    }

    buf[i] = (uint8_t)(buf[i] ^ buffer[bi]);
  }
}

#ifdef MAVLINK_USE_CXX_NAMESPACE
} // namespace mavlink
#endif
#endif // _SPECK_H_
