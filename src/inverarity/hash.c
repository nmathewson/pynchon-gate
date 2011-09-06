/* Inverarity is Copyright 2011 by Nick Mathewson.                    ____/|/|
   This is free software; see LICENSE at end of file for more info.     O \|\|
*/
#include <stdint.h>
#include <sys/types.h>

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include "consts.h"
#include "hash.h"

int
hash_eq(const uint8_t *h1, const uint8_t *h2)
{
#if HASH_LEN != 32
#error "This function assumes a 256-bit hash"
#endif

        word_t r = 0;
        const word_t *w1 = (const word_t *)h1;
        const word_t *w2 = (const word_t *)h2;

        /* We want to make this check time-invariant so as to avoid side-channel attacks.
         *
         * First, we're going to arrange for 'r' to have some of its bits set iff h1 != h2. We will
         * do this by or-ing together the results of xoring the corresponding words of h1 and h2.
         * If any bits in h1 and h2 differ, then at least one of the xors will have some bits set,
         * and so the or will have some bits set.  If no bits in h1 an h2 differ, then all the xors
         * will equal 0, so the or will also equal 0. */

#if BYTES_PER_WORD == 8
#define HALF_SHIFT 32
        r = (w1[0] ^ w2[0]) |
            (w1[1] ^ w2[1]) |
            (w1[2] ^ w2[2]) |
            (w1[3] ^ w2[3]);
#elif BYTES_PER_WORD == 4
#define HALF_SHIFT 16
        r = (w1[0] ^ w2[0]) |
            (w1[1] ^ w2[1]) |
            (w1[2] ^ w2[2]) |
            (w1[3] ^ w2[3]) |
            (w1[4] ^ w2[4]) |
            (w1[5] ^ w2[5]) |
            (w1[6] ^ w2[6]) |
            (w1[7] ^ w2[7]);
#else
#error "BYTES_PER_WORD was not 8 or 4.  What kind of architecture is this?"
#endif /* if BYTES_PER_WORD == 8 */

        /* Now we want to make it so that 'r' will have only its low-order half set, but
         * maintaining the property that it has bits set iff h1 != h2. We do this by or-ing it with
         * its top-half, shifted right (so that if any bits were set in the top half, there are now
         * sure to be bits set in the low half), and then and-ing it with 0xffffffff or 0xffff,
         * depending on its size. */


        r |= r >> HALF_SHIFT;
        r &= (((word_t) 1)<<HALF_SHIFT)-1;

        /* Finally, we want to convert the value to 0 or 1.  The expression below will do that:
         *
         * If r is has bits set (h1!=h2), then r>=1 and r<(1<<HALF_SHIFT).  So r-1 >= 0, so
         * (r-1)>>HALF_SHIFT is 0.  We will return 0, which was what we wanted.
         *
         * If r has no bits set (h1==h2), then r==0, so r-1 == 0xffff...ffff.  So (r-1)>>HALF_SHIFT
         * ends with a 1 bit, so we will return 1, which is what we wanted.
         */
        return 1 & ((r-1) >> HALF_SHIFT);
}

void
hash_digest(uint8_t *output, const uint8_t *input, size_t len)
{
        SHA256(input, len, output);
}

int
hash_pubkey(uint8_t *output, EVP_PKEY *key)
{
        int length = i2d_PublicKey(key, NULL);
        if (length < 0)
                return -1;
        unsigned char *encoded = malloc(length), *ptr = encoded;
        int length2 = i2d_PublicKey(key, &ptr);
        if (length2 != length || ptr != encoded + length2) {
                free(encoded);
                return -1;
        }
        SHA256(encoded, length, output);
        free(encoded);
        return 0;
}

int
hash_cert(uint8_t *output, X509 *cert)
{
        int length = i2d_X509(cert, NULL);
        if (length < 0)
                return -1;
        unsigned char *encoded = malloc(length), *ptr = encoded;
        int length2 = i2d_X509(cert, &ptr);
        if (length2 != length || ptr != encoded + length2) {
                free(encoded);
                return -1;
        }
        SHA256(encoded, length, output);
        free(encoded);
        return 0;
}

/*
  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to
  deal in the Software without restriction, including without limitation the
  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
  sell copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
  IN THE SOFTWARE.
*/
