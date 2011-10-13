/* Inverarity is Copyright 2011 by Nick Mathewson.                    ____/|/|
   This is free software; see LICENSE at end of file for more info.     O \|\|
*/
#ifndef INVERARITY_NET_H
#define INVERARITY_NET_H

struct request;
struct event_base;
struct ssl_ctx_st;
struct sockaddr;

/**
 * Create and start a new SSL connection to handle a new incoming network request.
 *
 * The connection will use 'base' as its Libevent IO base; 'ctx' as its SSL context; and 'fd' as
 * its network connection.  The request has come from 'srcaddr', whose length is 'srcaddr_len'.
 */
void new_connection(struct event_base *base,
                    struct ssl_ctx_st *ctx,
                    int fd,
                    struct sockaddr *srcaddr,
                    int srcaddr_len);

/**
 * Set up a response queue to be used by request_queue_reply_from_worker().  Return 0 on success,
 * -1 on failure.
 */
int init_response_queue(struct event_base *base);

/**
 * Called from a worker thread: declares that we have a response ready for a given request, and
 * that the IO thread should send the answer.
 */
void request_queue_reply_from_worker(struct request *);

/**
 * Read and return a possibly misaligned network-order unsigned 32-bit integer from 'buf'.
 *
 * We can't just do "ntohl(*(uint32_t *)buf)", since not every CPU is friendly to unaligned access.
 */
uint32_t get_uint32(void *buf);

/**
 * Set 'buf' to hold a 32-bit integer, encoding it in network order.
 *
 * We can't just do "*(uint32_t *)buf = htnol(val)", since not every CPU is friendly to unaligned access.
 */
void set_uint32(void *buf, uint32_t val);

#endif /* ifndef INVERARITY_NET_H */
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
