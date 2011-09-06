/* Inverarity is Copyright 2011 by Nick Mathewson.                    ____/|/|
   This is free software; see LICENSE at end of file for more info.     O \|\|
*/
#include <stdlib.h>
#include <sys/types.h>
#include <stdint.h>

#include "consts.h"
#include "request.h"

void
request_free(struct request *req)
{
        free(req->bitmask);
        free(req->result);
        free(req);
}

struct request_array *
request_array_new(void)
{
        struct request_array *ra = malloc(sizeof(*ra));
        if (!ra)
                return NULL;
        ra->array_len = 16;
        if (!(ra->reqs = malloc(ra->array_len * sizeof(struct request *)))) {
                free(ra);
                return NULL;
        }
        ra->n_requests = 0;
        return ra;
}

int
request_array_add(struct request_array *ra, struct request *r)
{
        if (ra->n_requests == ra->array_len) {
                size_t new_size = ra->array_len * 2;
                struct request **new_array = realloc(ra->reqs, sizeof(struct request*) * new_size);
                if (!new_array)
                        return -1;
                ra->reqs = new_array;
                ra->array_len = new_size;
        }

        ra->reqs[ra->n_requests++] = r;
        return ra->n_requests;
}

void
request_array_clear(struct request_array *ra)
{
        ra->n_requests = 0;
}

void
request_array_free(struct request_array *ra)
{
        free(ra->reqs);
        free(ra);
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
