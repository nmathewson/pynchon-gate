/* Inverarity is Copyright 2011 by Nick Mathewson.                    ____/|/|
   This is free software; see LICENSE at end of file for more info.     O \|\|
*/
#ifndef INVERARITY_DIST_H
#define INVERARITY_DIST_H

/* Functions to manage _distributions.
 *
 * A distribution is one of the big files that we're distributing blocks from.
 *
 * It knows its identity, its block size, and its number of blocks, and it has
 * code to answer PIR requests.
 */
struct distribution;
struct request;
struct stat;

/**
 * Fulfil a set of PIR requests from a distribution.
 *
 * Specifically: For 0 <= i < n_reqs, sets the contents of reqs[i]->response
 * (which must already be allocated) to the XOR of every bucket B_j in d for
 * which the j'th bit of reqs[i]->request is set.
 *
 * Requires that every element of reqs have the right length of bitfield,
 * and the correct block size.
 */
void distribute(const struct distribution *d, struct request **reqs, const int n_reqs);

/**
 * Allocate and return a new distribution for the contents of the named file.
 *
 * The filename must end with ".bs" and a decimal number.  The decimal number is the block size.
 * The block size must be a multiple of 64.
 *
 * Return NULL on failure.
 */
struct distribution *load_distribution(const char *filename);

/** Release all resources held for a distribution. */
void free_distribution(struct distribution *d);

/**
 * Return a pointer to the identity of a distribution.  The distribution's identity is used to
 * refer to it by the clients.
 */
const uint8_t *distribution_get_identity(const struct distribution *d);

/** Return a distribution's block size. */
size_t distribution_get_blocksize(const struct distribution *d);

/** Return the number of blocks in a distribution. */
size_t distribution_get_n_blocks(const struct distribution *d);

#define DISTMATCH_TOO_OLD -2
#define DISTMATCH_NOT_ME -1
#define DISTMATCH_OKAY 0
/**
 * Check whether a distribution still probably matches a given file whose name is fname, and whose
 * stat() result is st.
 *
 * Return DISTMATCH_OKAY if the distribution is a perfect match; DISTMATCH_NOT_ME if this looks
 * like a distribution of something else entirely, and DISTMATCH_TOO_OLD if the file has changed
 * since the distribution was loaded.
 */
int distribution_matches_file(const struct distribution *d,
                              const char *fname,
                              const struct stat *st);

#endif /* ifndef INVERARITY_DIST_H */
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
