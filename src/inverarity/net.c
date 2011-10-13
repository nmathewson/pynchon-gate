/* Inverarity is Copyright 2011 by Nick Mathewson.                    ____/|/|
   This is free software; see LICENSE at end of file for more info.     O \|\|
*/
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>

#include <pthread.h>

#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/buffer.h>

#include <openssl/ssl.h>

#include "consts.h"
#include "request.h"
#include "worker.h"
#include "net.h"
#include "logging.h"
#include "main.h"
#include "util.h"
#include "dist.h"

static void start_request(const uint8_t *identity,
                          const uint8_t *req_id,
                          struct conn *conn,
                          size_t n_bits,
                          size_t blocksize,
                          uint8_t *bitmask);
static void free_conn(struct conn *conn);
static void eventcb(struct bufferevent *bev, short what, void *conn_);

struct conn {
        /** The bufferevent that implements this connection. */
        struct bufferevent *bev;

        /**
         * The number of requests currently being processed for this connection.  They each hold a
         * reference to this structure, so we can't free the structure until they have all been
         * finished.
         */
        int pending_requests;
};

uint32_t
get_uint32(void *buf)
{
        uint32_t u;
        memcpy(&u, buf, 4);
        return ntohl(u);
}

void
set_uint32(void *buf, uint32_t val)
{
        uint32_t u = htonl(val);
        memcpy(buf, &u, 4);
}

/**
 * Bail out if a client command is longer than this.
 *
 * XXXX This should be smarter, configurable, and dependent on the number of buckets in a distribution
 **/
size_t max_client_cmdlen = 65536;

/**
 * Bufferevent callback: drop all incoming data in a buffer.
 */
static void
discard_readcb(struct bufferevent *bev, void *arg)
{
        evbuffer_drain(bufferevent_get_input(bev), -1);
}

/**
 * Bufferevent callback: close the bufferevent if it is done flushing.
 */
static void
closeonflush_writecb(struct bufferevent *bev, void *arg)
{
        if (evbuffer_get_length(bufferevent_get_output(bev)) == 0)
                bufferevent_free(bev);
}

/**
 * Send an error message to a client connected on 'conn'.
 *
 * The error code is 'code', and it relates to the request 'req_id'.  The error message is 'msg'.
 *
 * If 'fatal' is true, we can't go on talking to the client: close the connection once the error
 * message is flushed.
 */
static void
send_err(struct conn *conn, uint32_t code, const uint8_t *req_id, const char *msg, int fatal)
{
        size_t msg_len = strlen(msg);
        char buf[20];
        struct bufferevent *bev = conn->bev;

        set_uint32(buf + 0, 0x2002);
        set_uint32(buf + 4, msg_len + 8);
        set_uint32(buf + 8, 0); /* flags */
        set_uint32(buf +12, code);
        set_uint32(buf +16, msg_len);

        if (req_id) {
                bufferevent_write(bev, req_id, 32);
        } else {
                char tmp[32];
                memset(tmp, 0, sizeof(tmp));
                bufferevent_write(bev, tmp, 32);
        }

        bufferevent_write(bev, buf, 20);
        bufferevent_write(bev, msg, msg_len);

        if (fatal) {
                conn->bev = NULL; /* Don't send more replies */
                bufferevent_setcb(bev, discard_readcb, closeonflush_writecb,
                                  eventcb, NULL);
                if (conn->pending_requests == 0)
                        free_conn(conn);
        }
}

static void
send_data(struct conn *conn, const uint8_t *req_id, uint32_t command, size_t datalen, const uint8_t *data)
{
        uint8_t header[48];
        memcpy(header, req_id, 32);
        set_uint32(header+32, command);
        set_uint32(header+36, 4+datalen);
        set_uint32(header+40, 0);/*flags*/
        set_uint32(header+44, datalen);
        bufferevent_write(conn->bev, header, 48);
        bufferevent_write(conn->bev, data, datalen);
        memset(header, 0, sizeof(header));
}

/**
 * Try to parse and handle a get request from input, removing it from the buffer.
 *
 * Return true if we should stop handling commands after this.
 */
static int
handle_get_command(struct conn *conn, const uint8_t *req_id, uint32_t flags, struct evbuffer *input, uint32_t cmd_len)
{
        /* okay, the command is a GET.  Is its header long enough? */
        if (cmd_len < 40) {
                send_err(conn, 2, req_id, "GET too short", 1);
                return 1;
        }

        /* Read and parse the get header. */
        uint8_t get_header[40];
        evbuffer_remove(input, get_header, 40);
        uint32_t n_bits = get_uint32(get_header + 32);
        uint32_t block_size = get_uint32(get_header + 36);
        uint32_t bf_len = (n_bits + 7) / 8;
        if (bf_len > cmd_len - 40) {
                send_err(conn, 3, req_id, "No room for bitfield", 1);
                return 1;
        }

        uint8_t *bits = malloc(bf_len);
        if (!bits) {
                send_err(conn, 4, req_id, "Internal error", 1);
                return 1;
        }
        evbuffer_remove(input, bits, bf_len);
        evbuffer_drain(input, cmd_len - 40 - bf_len);

        start_request(get_header, req_id, conn, n_bits, block_size, bits);

        return 0;
}

/**
 * Try to parse and handle a get_metadata request from input, removing it from the buffer.
 *
 * Return true if we should stop handling commands after this.
 */
static int
handle_get_metadata_command(struct conn *conn, const uint8_t *req_id, uint32_t flags, struct evbuffer *input, uint32_t cmd_len)
{
        /* okay, the command is a GET.  Is its header long enough? */
        if (cmd_len < 32) {
                send_err(conn, 2, req_id, "GET_METADATA too short", 1);
                return 1;
        }

        /* Read afternd parse the get header. */
        uint8_t getmeta_header[32];
        evbuffer_remove(input, getmeta_header, 32);
        const uint8_t *const dist_id = getmeta_header;
        evbuffer_drain(input, cmd_len - 32);

        struct worker *w = find_worker(dist_id);
        if (!w) {
                send_err(conn, 6, req_id, "No such distribution", 0);
                return 0;
        }
        const struct distribution *dist = worker_get_distribution(w);
        const uint8_t *metadata;
        size_t metadata_len;
        if (distribution_get_metadata(dist, &metadata, &metadata_len)<0) {
                send_err(conn, 9, req_id, "Distribution had no metadata", 0);
                return 0;
        }

        /* Send the reply. */
        /* XXXX maybe use evbuffer_add_reference for this later */
        send_data(conn, req_id, 0x2003, metadata_len, metadata);

        return 0;
}

/**
 * Try to parse and handle a list_dists request from input, removing it from the buffer.
 *
 * Return true if we should stop handling commands after this.
 */
static int
handle_list_dists_command(struct conn *conn, const uint8_t *req_id, uint32_t flags, struct evbuffer *input, uint32_t cmd_len)
{
        evbuffer_drain(input, cmd_len); /* Ignore the command body. */

        const uint8_t *dl;
        size_t sz;
        if (get_distribution_list(&dl,&sz)< 0) {
                send_err(conn, 10, req_id, "No distribution list present", 0);
                return 0;
        }
        send_data(conn, req_id, 0x2004, sz, dl);

        return 0;
}

/**
 * Bufferevent callback: invoked whenever we have read some data on a connection.
 */
static void
readcb(struct bufferevent *bev, void *conn_)
{
        struct conn *conn = conn_;
        struct evbuffer *input = bufferevent_get_input(bev);

        while (1) { /* Loop to handle as many requests as possible. */

                /* If the command header isn't here yet, give up and wait for more data. */
                if (evbuffer_get_length(input) < 44)
                        return;

                /* Parse the command header */
                uint8_t cmdheader_buf[44];
                evbuffer_copyout(input, cmdheader_buf, 44); /* nondestructive copy */
                const uint8_t * const req_id = cmdheader_buf;
                uint32_t cmd = get_uint32(cmdheader_buf+32);
                uint32_t len = get_uint32(cmdheader_buf+36);
                uint32_t flags = get_uint32(cmdheader_buf+40);
                if (len > max_client_cmdlen) {
                        send_err(conn, 1, req_id, "Command too long", 1);
                        return;
                }

                /* Wait for the whole command to arrive */
                if (evbuffer_get_length(input) < 44 + len)
                        return;  /* XXXX set a watermark */
                /* XXXX clear that watermark. */

                /* Discard the command header */
                evbuffer_drain(input, 44);

                /* We only know how to handle GET right now. */
                switch (cmd) {
                case 0x1000:
                        if (handle_get_command(conn, req_id, flags, input, len))
                                return;
                        break;
                case 0x1001:
                        if (handle_get_metadata_command(conn, req_id, flags, input, len))
                                return;
                        break;
                case 0x1002:
                        if (handle_list_dists_command(conn, req_id, flags, input, len))
                                return;
                        break;
                default:
                        evbuffer_drain(input, len);
                        send_err(conn, 2, req_id, "Unknown command", 0);
                        continue;
                }

        }
}

/**
 * Helper: launch a request for a distribution with 'identity'.  The request ID is 'req_id', the
 * connection is 'conn', and the body of the request is 'bitmask', which contains 'n_bits' bits.
 * The client expects the answer to be 'blocksize' in length.
 *
 * If we can't launch the request, send an error message, and free bitmask.
 */
static void
start_request(const uint8_t *identity,
              const uint8_t *req_id,
              struct conn *conn,
              size_t n_bits,
              size_t blocksize,
              uint8_t *bitmask)
{
        struct worker *w = find_worker(identity);

        struct request *r = calloc(sizeof(*r), 1);
        if (!r) {
                send_err(conn, 5, req_id, "Internal error", 1);
                free(bitmask);
                return;
        }
        if (!w) {
                send_err(conn, 6, req_id, "No such distribution", 0);
                free(bitmask);
                return;
        }

        /* XXXX A lot of this should probably move into a new function in request.c */

        const struct distribution *dist = worker_get_distribution(w);
        if (blocksize == 0)
                blocksize = distribution_get_blocksize(dist);
        if (distribution_get_blocksize(dist) != blocksize) {
                send_err(conn, 6, req_id, "Wrong block size", 0);
                free(bitmask);
                return;
        }
        if (n_bits < distribution_get_n_blocks(dist)) {
                send_err(conn, 7, req_id, "Not enough bits", 0);
                free(bitmask);
                return;
        }

        memcpy(r->identity, identity, 32);
        memcpy(r->req_id, req_id, 32);
        r->conn = conn;
        r->n_bits = n_bits;
        r->blocksize = blocksize;
        r->bitmask = bitmask;
        r->result = calloc(1, r->blocksize); /*XXXX check return value */

        if (queue_request_for_worker(w, r) < 0) {
                request_free(r);
                send_err(conn, 8, req_id, "Worker didn't accept request", 0);
        } else {
                ++conn->pending_requests;
        }
}

/**
 * Bufferevent callback: invoked when we have flushed the output buffer on a connection.
 */
static void
writecb(struct bufferevent *bev, void *conn_)
{
}

/**
 * Bufferevent callback: invoked when we have some event happen on a connection
 */
static void
eventcb(struct bufferevent *bev, short what, void *conn_)
{
        struct conn *conn = conn_;
        if (what & (BEV_EVENT_ERROR|BEV_EVENT_EOF)) {
                bufferevent_free(bev);
                if (conn)
                        conn->bev = NULL;
                if (conn && conn->pending_requests == 0)
                        free_conn(conn);
        }
}

/**
 * Helper: send the answer for a request back to the user, then free it.
 */
static void
request_send_reply(struct request *req)
{
        struct conn *conn = req->conn;

        --conn->pending_requests;

        if (conn->bev == NULL) {
                request_free(req);
                if (conn->pending_requests == 0)
                        free_conn(req->conn);

                return;
        }

        send_data(conn, req->req_id, 0x2001, req->blocksize, req->result);
}

/**
 * This structure is used to send responses back to the main thread from a worker thread.
 */
struct response_queue {
        pthread_mutex_t lock;
        struct request_array *requests;
        struct event *ev_notify;
};

/**
 * Libevent callback: invoked in the main thread after a worker thread adds to the response queue.
 *
 * This callback is responsible for queueing all the pending requests onto the user connections.
 **/
static void
response_queue_cb(evutil_socket_t sock_, short events_, void *arg)
{
        struct response_queue *queue = arg;
        while (1) {
                pthread_mutex_lock(&queue->lock);
                if (queue->requests->n_requests == 0) {
                        pthread_mutex_unlock(&queue->lock);
                        return;
                }

                struct request_array *ra = queue->requests;
                queue->requests = request_array_new();
                pthread_mutex_unlock(&queue->lock);


                int i;
                for (i = 0; i < ra->n_requests; ++i)
                        request_send_reply(ra->reqs[i]);

                request_array_free(ra);
        }
}

/**
 * Used to initialize a response queue to send replies on an event_base.
 */
struct response_queue *
response_queue_new(struct event_base *base)
{
        struct response_queue *rq;
        if (!(rq = calloc(sizeof(*rq), 1))) {
                log_perror("calloc");
                return NULL;
        }
        if (!(rq->requests = request_array_new())) {
                log_error("request_array_new failed");
                free(rq);
                return NULL;
        }
        if (!(rq->ev_notify = event_new(base, -1, 0, response_queue_cb, rq))) {
                log_error("event_new failed");
                request_array_free(rq->requests);
                free(rq);
                return NULL;
        }
        if (pthread_mutex_init(&rq->lock, NULL)) {
                log_error("pthread_mutex_init failed");
                event_free(rq->ev_notify);
                request_array_free(rq->requests);
                free(rq);
                return NULL;
        }

        return rq;
}

/**
 * Add an entry to a response queue.
 */
void
response_queue_enqueue(struct response_queue *queue, struct request *req)
{
        int n;
        pthread_mutex_lock(&queue->lock);
        n = request_array_add(queue->requests, req);
        if (n == 1)
                event_active(queue->ev_notify, EV_READ, 1);
        pthread_mutex_unlock(&queue->lock);
}

static struct response_queue *the_response_queue = NULL;

int
init_response_queue(struct event_base *base)
{
        assert(!the_response_queue);
        the_response_queue = response_queue_new(base);
        return the_response_queue == NULL ? -1 : 0;
}

void
request_queue_reply_from_worker(struct request *req)
{
        response_queue_enqueue(the_response_queue, req);
}

void
new_connection(struct event_base *base,
               SSL_CTX *ctx,
               int fd,
               struct sockaddr *srcaddr,
               int srcaddr_len)
{
        SSL *ssl = SSL_new(ctx);
        if (!ssl) {
                log_error("Couldn't call SSL_new!");
                close(fd);
                return;
        }
        struct bufferevent *bev = bufferevent_openssl_socket_new(base,
                                                                 fd,
                                                                 ssl,
                                                                 BUFFEREVENT_SSL_ACCEPTING,
                                                                 BEV_OPT_CLOSE_ON_FREE);
        if (!bev) {
                log_error("bufferevent_openssl_socket_new failed");
                close(fd);
                SSL_free(ssl);
                return;
        }
        struct conn *conn = calloc(1, sizeof(*conn));
        if (!conn) {
                log_error("Calloc(conn) failed");
                bufferevent_free(bev);
                return;
        }
        conn->bev = bev;
        bufferevent_setcb(bev, readcb, writecb, eventcb, conn);
        bufferevent_enable(bev, EV_READ|EV_WRITE);
        /* Set read timeout callback  XXXX */
}

static void
free_conn(struct conn *conn)
{
        assert(conn->bev == NULL);
        assert(conn->pending_requests == 0);
        free(conn);
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
