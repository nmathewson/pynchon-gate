/* Inverarity is Copyright 2011 by Nick Mathewson.                    ____/|/|
   This is free software; see LICENSE at end of file for more info.     O \|\|
*/
#ifndef INVERARITY_REQUEST_H
#define INVERARITY_REQUEST_H

#include <sys/types.h>
#include <stdlib.h>

struct conn;

/* XXXX Let's make these structures more opaque some time, and make everything use accessor
 * functions instead. */

/**
 * A request is the current status of a PIR request.
 *
 * A request is owned by one thread at a time: either the network thread if we're receiving the
 * request or sending its answer back, or a worker thread if we're processing it.
 */
struct request {
        /** The identity (digest) of the distribution for this request.*/
        uint8_t identity[32];
        /** A user-selected nonce to identify this request uniquely among the user's other
         * requests */
        uint8_t req_id[32];
        /** The length of the request, in bits. */
        size_t n_bits;
        /** The block size for the request. */
        size_t blocksize;
        /** The actual PIR request. Rounded up to the nearest byte */
        uint8_t *bitmask;

        /** The connection that made this request.  The connection is reference-counted, so we
         * don't need to worry about it going away on us. */
        struct conn *conn;

        /** Used internally for answering requests; see the implementation of distribute() for more
         * info here. */
        word_t mask;

        /** A buffer to hold the answer to this request.  Holds 'blocksize' bytes. */
        uint8_t *result;
};

/** A dynamic array of requests. */
struct request_array {
        struct request **reqs;
        /** The total number of pointers allocated in 'reqs'. */
        size_t array_len;
        /** The number of pointers used in 'reqs' so far. */
        size_t n_requests;
};

/**
 * Return a newly allocated, empty request_array.
 */
struct request_array *request_array_new(void);

/**
 * Add a request to the end of a request array.
 */
int request_array_add(struct request_array *ra, struct request *r);

/**
 * Remove every member of a request array.
 */
void request_array_clear(struct request_array *ra);

/**
 * Release all storage held in a request_array.  Does not free the requests themselves.
 */
void request_array_free(struct request_array *ra);

/**
 * Release all storage held by a request.
 */
void request_free(struct request *req);

#endif /* ifndef INVERARITY_REQUEST_H */
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
