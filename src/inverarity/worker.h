/* Inverarity is Copyright 2011 by Nick Mathewson.                    ____/|/|
   This is free software; see LICENSE at end of file for more info.     O \|\|
*/
#ifndef INVERARITY_WORKER_H
#define INVERARITY_WORKER_H

/* This module handles the work of keeping track of which worker is handling which distribution,
 * which workers currently exist, stopping workers, starting workers, and so on.
 *
 * Most functions in this module must be called only from the main thread; exceptions are noted.
 *
 * XXXX It's possibly a design mistake to have one worker per distribution.  Instead, perhaps we
 * should have one worker per CPU?
 */

struct worker;
struct distribution;
struct request;
struct stat;

/**
 * Create and return a new worker to handle the distribution 'dist'.  Do not launch the worker.
 * Return NULL on failure.
 */
struct worker *new_worker(struct distribution *dist);
/**
 * Launch a worker's thread.  Return 0 on success, -1 on failure.
 */
int start_worker(struct worker *w);
/**
 * Send the request 'r' to the worker 'w'.
 *
 * After calling this function, the caller no longer owns the request, and must not use it.
 *
 * Return 0 on success; return -1 and free 'r' on failure.
 */
int queue_request_for_worker(struct worker *w, struct request *r);

/**
 * Tell the worker 'w' to stop processing.
 *
 * This function does not stop the worker immediately; rather, we must wait for the worker to
 * finish its current round of requests.
 *
 * Return 0 on success, -1 on failure.
 */
int stop_worker(struct worker *w);

/**
 * Wait for a worker thread on which we've previously called stop_worker() to finish.
 */
void join_worker(struct worker *w);

/**
 * Look up the worker that handles distribution for a given distribution identity.
 *
 * Return NULL if we don't know any such worker.
 */
struct worker *find_worker(const uint8_t *identity);

/**
 * Add 'w' to the list of all workers so we can find it later.
 */
void add_worker(struct worker *w);

/**
 * Tell every currently running worker that it should stop.
 */
void stop_all_workers(void);

/**
 * For every worker that has stopped, join its thread so as to release pthread resources.
 */
void join_all_stopped_workers(void);

/**
 * Return the distribution that a worker is serving.
 */
const struct distribution *worker_get_distribution(const struct worker *w);

/**
 * Release all storage held by a worker, which must not be running.  Return a pointer to its
 * distribution: the worker no longer owns it.
 */
struct distribution *free_worker(struct worker *w);

/**
 * Look up and return the worker serving a given file with a given stat result.  Set *replace_out
 * to true if we should reload the file, and to false if we shouldn't.  Return 0 if 
 */
struct worker *worker_get_by_filename(const char *fname, const struct stat *st, int *replace_out);

/** Set a mark on every currently running worker */
void mark_all_workers(void);
/** Remove the mark on a given worker */
void unmark_worker(struct worker *w);
/** Tell every marked worker to stop. */
void sweep_marked_workers(void);


#endif /* ifndef INVERARITY_WORKER_H */
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
