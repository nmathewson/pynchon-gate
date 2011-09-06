/* Inverarity is Copyright 2011 by Nick Mathewson.                    ____/|/|
   This is free software; see LICENSE at end of file for more info.     O \|\|
*/
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <string.h>
#include <sys/stat.h>

#include "consts.h"
#include "dist.h"
#include "request.h"
#include "hash.h"
#include "logging.h"

#define WORDS_PER_CLINE 8

struct distribution {
        /** The identity (hash) of this distribution. */
        uint8_t identity[32];
        /** The number of blocks in this distribution */
        size_t n_blocks;
        /** The length of each block in this distribution */
        size_t blocksize;
        /** A pointer to the data in this distribution.  This is an mmaping of the file, so it
         * should get swapped out to disk as necessary.  We don't actually require that you can fit
         * the whole distribution in memory: only that you have enough address space for it. */
        uint8_t *data;

        /** The name of the file this distribution was loaded from. */
        char *fname;
        /** The modification time that this file had when we loaded it. */
        time_t mtime;
};

/**
 * Helper: set out <- out ^ (in & mask), where out and in are arrays of
 * WORDS_PER_CLINE words. */
static void
and_xor_cline(word_t *out, word_t mask, const word_t *in)
{
        int i;
        for (i=0; i < WORDS_PER_CLINE; ++i)
                out[i] ^= in[i] & mask;
}

void
distribute(const struct distribution *d, struct request **reqs, const int n_reqs)
{
        int i, j, k;

        /* Check invariants */
        assert((d->blocksize % (BYTES_PER_WORD * WORDS_PER_CLINE)) == 0);
        assert(d->blocksize);
        for (i=0; i < n_reqs; ++i) {
                assert(reqs[i]);
                assert(reqs[i]->n_bits >= d->n_blocks);
                assert(reqs[i]->blocksize == d->blocksize);
                assert(hash_eq(reqs[i]->identity, d->identity));
        }

        for (i=0; i < d->n_blocks; ++i) {
                const uint8_t *block_in = &d->data[i * d->blocksize];
                for (j = 0; j < n_reqs; ++j) {
                        /* In this loop, we're going to set reqs[j]->mask for reach request.  If
                         * the i'th bit of reqs[j] is 1, we want to set the mask to 0xffffff...fff;
                         * if the bit is 0, we want to set the mask to 0.
                         *
                         * We're going to use this mask to do a constant-time conditional xor.  We
                         * don't want to say, "if (bit) out ^= in;", because that involves a
                         * branch, and because the timing leaks whether the bit was set.  Instead,
                         * we'll say "out ^= mask & in", which is a no-op if the mask is 0, and
                         * which is equivalent to "out ^= in" if the mask is set.
                         */

                        /* Select the i'th bit of req[j]'s request. */
                        const word_t bit = (reqs[j]->bitmask[i/8] >> (i & 7)) & 1;

                        /* At this point, we could say "mask = bit ? 0xffffffffffffffff : 0".  But
                         * that would involve a branch, which is exactly what we're trying to
                         * avoid.  So let's get sneaky.
                         *
                         * If bit is 0, then we'll set mask to ~(bit-1) == ~ -1 == 0.
                         * If bit is 1, then we'll set mask to ~(bit-1) == ~ 0 == 0xffff...fffff
                         *
                         * So this calculation expands "bit" to a full word-wide mask.
                         */
                        const word_t mask = ~(bit - 1);
                        reqs[j]->mask = mask;
                }

                /* Within each block, we go word-by-word, one CLINE at a time.  CLINE is meant to
                 * be a reasonable number of cache lines, so that the relevant portion of the block
                 * stays in the L1 cache as we iterate through the requests */
                for (j = 0; j < d->blocksize; j += (WORDS_PER_CLINE*BYTES_PER_WORD)) {
                        const word_t *cline_in = (const word_t *)&block_in[j];
                        for (k=0; k < n_reqs; ++k)
                                and_xor_cline((word_t*) &reqs[k]->result[j],
                                              reqs[k]->mask,
                                              cline_in);
                }
        }

        /* When we're done, clear information about what was in the request. */
        for (i = 0; i < n_reqs; ++i) {
                reqs[i]->mask = 0;
                memset(reqs[i]->bitmask, 0, d->n_blocks / 8);
        }
}

/**
 * If filename is a valid filename for a distribution, then set *blocksize_out
 * to its blocksize, and return 0.  Otherwise, return -1.
 */
static int
parse_distribution_fname(const char *filename, size_t *blocksize_out)
{
        const char *r = strrchr(filename, '.');
        if (strlen(r) < 4 || memcmp(r, ".bs", 3))
                return -1;
        r += 3;
        char *endptr=NULL;
        long bs = strtol(r, &endptr, 10);
        if (bs <= 0 || !endptr || *endptr || bs > SIZE_MAX)
                return -1;
        *blocksize_out = (size_t)bs;
        return 0;
}

struct distribution *
load_distribution(const char *filename)
{
        struct distribution *d;
        int fd = -1;
        struct stat st;

        if (!(d = calloc(sizeof(*d), 1)))
                return NULL;

        if (parse_distribution_fname(filename, &d->blocksize) < 0) {
                log_error("Can't parse distribution filename");
                goto err;
        }

        if ((fd = open(filename, O_RDONLY)) < 0) {
                log_perror("open()");
                goto err;
        }

        if (fstat(fd, &st) < 0) {
                log_perror("fstat()");
                goto err;
        }

        if ((st.st_size % d->blocksize) != 0)
                log_error("Not an integer number of blocks");

        d->n_blocks = st.st_size / d->blocksize;
        d->mtime = st.st_mtime;

        if (!(d->fname = strdup(filename))) {
                log_perror("strdup()");
                goto err;
        }

        if (!(d->data = mmap(NULL, st.st_size, PROT_READ, MAP_FILE|MAP_SHARED, fd, 0))) {
                log_perror("mmap()");
                goto err;
        }

        hash_digest(d->identity, d->data, st.st_size);

        close(fd);
        return d;
err:
        if (fd >= 0)
                close(fd);
        if (d) {
                if (d->fname)
                        free(d->fname);
                free(d);
        }
        return NULL;
}

void
free_distribution(struct distribution *d)
{
        munmap(d->data, d->blocksize * d->n_blocks);
        free(d->fname);
        free(d);
}

const uint8_t *
distribution_get_identity(const struct distribution *d)
{
        return d->identity;
}

size_t
distribution_get_blocksize(const struct distribution *d)
{
        return d->blocksize;
}

size_t
distribution_get_n_blocks(const struct distribution *d)
{
        return d->n_blocks;
}

int
distribution_matches_file(const struct distribution *d, const char *fname, const struct stat *st)
{
        if (strcmp(fname, d->fname))
                return DISTMATCH_NOT_ME;
        else if (st->st_mtime > d->mtime)
                return DISTMATCH_TOO_OLD;
        else
                return DISTMATCH_OKAY;
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
