/* Inverarity is Copyright 2011 by Nick Mathewson.                    ____/|/|
   This is free software; see LICENSE at end of file for more info.     O \|\|
*/
#ifndef INVERARITY_HASH_H
#define INVERARITY_HASH_H

/* Functions to compute and use cryptographic hashes.
 *
 * Right now, every hash in inverarity is SHA256. When SHA3 is announced, we'll move to that.
 */

/** The length of our hashes, in bytes. */
#define HASH_LEN 32

/**
 * Return 1 if the provided hashes are equal, and 0 if they are unequal. Runs in constant time.
 */
int hash_eq(const uint8_t *h1, const uint8_t *h2);

/**
 * Set output to contain the hash of the len-byte string at input.  Output must have enough space
 * for HASH_LEN bytes.
 */
void hash_digest(uint8_t *output, const uint8_t *input, size_t len);

struct evp_pkey_st;
/**
 * Set output to contain the hash of DER encoding of the public-key part of an EVP_PKEY.
 * Output must have enough space for HASH_LEN bytes.  Return 0 on success; -1 on failure.
 */
int hash_pubkey(uint8_t *output, struct evp_pkey_st *key);

struct x509_st;
/**
 * Set output to contain the hash of DER encoding of the public-key part of an EVP_PKEY.
 * Output must have enough space for HASH_LEN bytes.  Return 0 on success; -1 on failure.
 */
int hash_cert(uint8_t *output, struct x509_st *key);

#endif
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
