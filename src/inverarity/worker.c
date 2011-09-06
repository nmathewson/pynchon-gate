/* Inverarity is Copyright 2011 by Nick Mathewson.                    ____/|/|
   This is free software; see LICENSE at end of file for more info.     O \|\|
*/
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
#include <string.h>

#include "consts.h"
#include "worker.h"
#include "request.h"
#include "net.h"
#include "logging.h"
#include "dist.h"
#include "hash.h"

struct worker {
        /** The next worker in worker_list or in stopped_workers */
        struct worker *next_worker;

        /** The distribution this worker is serving */
        struct distribution *dist;
        /** The identity of that distribution */
        uint8_t identity[HASH_LEN];

        /** Array of requests that this worker will handle next.
         * Protected by 'lock'. */
        struct request_array *reqs_pending;

        /** Array of requests that this worker is currently processing. */
        struct request_array *reqs_working;

        /** 0 if the worker is running or not yet started; 1 if it's been told
         * to stop; 2 if it is finally done.  Protected by 'lock'. */
        int done;
        /** True if we are cleaning out unneeded workers and we han't yet
         * decided that we need this worker to stay. */
        int mark;

        /** The thread that's running this worker. */
        pthread_t thread;
        /** A lock to protect 'reqs_pending' and 'done' and 'cond' */
        pthread_mutex_t lock;
        /** A condition variable to tell us when there are more requests to
         * fulfill.  Protected by 'lock'. */
        pthread_cond_t cond;
};

struct worker *
new_worker(struct distribution *dist)
{
        struct worker *w = calloc(sizeof(*w), 1);
        if (!w)
                return NULL;

        if (!(w->reqs_pending = request_array_new())) {
                log_error("Couldn't allocate reqs_pending");
                goto err;
        }
        if (!(w->reqs_working = request_array_new())) {
                log_error("Couldn't allocate reqs_working");
                goto err;
        }

        if (pthread_mutex_init(&w->lock, NULL)) {
                log_error("Couldn't init mutex");
                goto err;
        }
        if (pthread_cond_init(&w->cond, NULL)) {
                log_error("Couldn't init cond");
                goto err;
        }
        w->dist = dist;
        memcpy(w->identity, distribution_get_identity(dist), HASH_LEN);

        return w;
err:
        if (w) {
                if (w->reqs_pending)
                        request_array_free(w->reqs_pending);
                if (w->reqs_working)
                        request_array_free(w->reqs_working);
                /* XXXX handle mutex, cond */
                free(w);
        }
        return NULL;
}

/*XXXX check return values here */
#define LOCK()                                \
        do {                                  \
                pthread_mutex_lock(&w->lock); \
        } while (0)
#define UNLOCK()                                \
        do {                                    \
                pthread_mutex_unlock(&w->lock); \
        } while (0)

int
queue_request_for_worker(struct worker *w, struct request *r)
{
        int res = 0;
        LOCK();
        if (w->done)
                res = -1;
        if (res == 0)
                res = request_array_add(w->reqs_pending, r);
        if (res >= 0 && w->reqs_pending->n_requests == 1)
                /* XXXXX Maybe we should nagle here: don't automatically start processing requests
                   until either we have a few requests, or until we've been waiting a little while.
                */
                res = pthread_cond_signal(&w->cond);

        UNLOCK();
        return res;
}

int
stop_worker(struct worker *w)
{
        int r;
        LOCK();
        w->done = 1;
        r = pthread_cond_signal(&w->cond);
        UNLOCK();
        return r;
}

static void *
run_worker(void *w_)
{
        struct worker *w = w_;

        while (1) {
                LOCK();
                while (w->reqs_pending->n_requests == 0 && !w->done) {
                        pthread_cond_wait(&w->cond, &w->lock);
                }
                if (w->done)
                        break;

                struct request_array *reqs = w->reqs_pending;
                w->reqs_pending = w->reqs_working;
                w->reqs_working = reqs;
                UNLOCK();

                distribute(w->dist, reqs->reqs, reqs->n_requests);

                int i;
                for (i=0; i < reqs->n_requests; ++i) {
                        request_queue_reply_from_worker(reqs->reqs[i]);
                }
                request_array_clear(reqs);
        }

        w->done = 2;
        UNLOCK();
        return NULL;
}

int
start_worker(struct worker *w)
{
        return pthread_create(&w->thread, NULL, run_worker, w);
}

struct distribution *
free_worker(struct worker *w)
{
        struct distribution *d = w->dist;

        request_array_free(w->reqs_pending);
        request_array_free(w->reqs_working);
        pthread_cond_destroy(&w->cond);
        pthread_mutex_destroy(&w->lock);

        free(w);

        return d;
}

void
join_worker(struct worker *w)
{
        void *val=NULL;
        if (pthread_join(w->thread, &val))
                log_error("couldn't join thread");
}

/* worker list stuff */

static struct worker *worker_list = NULL;

struct worker *
find_worker(const uint8_t *identity)
{
        uintptr_t worker_ptr = 0;
        struct worker *w;
        /* Data-invariant linear search function: sets worker_ptr to 0 if
         * idenitity isn't found; or to the last worker in sequence with that
         * identity.  Does not branch based on the identity. */
        for (w = worker_list; w; w = w->next_worker) {
                uintptr_t eq = hash_eq(identity, w->identity);
                uintptr_t neq_mask = (eq-1); /* Equal to 0 if eq==1, ~0 if eq==0 */
                worker_ptr = (worker_ptr & neq_mask) | (((uintptr_t)w) & ~neq_mask);
        }
        return (struct worker *)worker_ptr;
}

void
add_worker(struct worker *w)
{
        w->next_worker = worker_list;
        worker_list = w;
}

void
remove_worker(struct worker *w)
{
        struct worker **wptr = &worker_list;
        while (*wptr) {
                if (*wptr == w) {
                        *wptr = w->next_worker;
                        w->next_worker = NULL;
                        return;
                }
                wptr = &(*wptr)->next_worker;
        }
}

void
stop_all_workers(void)
{
        struct worker *w = worker_list;
        for (; w; w=w->next_worker) {
                stop_worker(w);
        }
}

const struct distribution *
worker_get_distribution(const struct worker *w)
{
        return w->dist;
}

struct worker *
worker_get_by_filename(const char *fname, const struct stat *st, int *replace_out)
{
        struct worker *w;
        *replace_out = 0;
        for (w = worker_list; w; w = w->next_worker) {
                int dm = distribution_matches_file(worker_get_distribution(w), fname, st);
                if (dm == DISTMATCH_OKAY) {
                        return w;
                } else if (dm == DISTMATCH_TOO_OLD) {
                        *replace_out = 1;
                        return w;
                }
        }
        return NULL;
}

void
mark_all_workers(void)
{
        struct worker *w = worker_list;
        for (; w; w=w->next_worker) {
                w->mark = 1;
        }
}

void
unmark_worker(struct worker *w)
{
        w->mark = 0;
}

static struct worker *stopped_workers = NULL;

void
sweep_marked_workers(void)
{
        struct worker **wptr = &worker_list;
        while (*wptr) {
                if ((*wptr)->mark) {
                        struct worker *victim = *wptr;
                        *wptr = victim->next_worker;
                        victim->next_worker = stopped_workers;
                        stopped_workers = victim;
                        stop_worker(victim);
                } else {
                        wptr = &(*wptr)->next_worker;
                }
        }
}

void
join_all_stopped_workers(void)
{
        struct worker **wptr = &stopped_workers;
        while (*wptr) {
                struct worker *w = *wptr;
                LOCK(); /* hold lock, since checking w->done. */
                if (w->done == 2) {
                        *wptr = w->next_worker;

                        join_worker(w);
                        struct distribution *d = free_worker(w);
                        free_distribution(d);
                } else {
                        wptr = &(*wptr)->next_worker;
                }
                UNLOCK();
        }
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
