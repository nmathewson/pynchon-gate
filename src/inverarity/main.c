/* Inverarity is Copyright 2011 by Nick Mathewson.                    ____/|/|
   This is free software; see LICENSE at end of file for more info.     O \|\|
*/
#include <signal.h>
#include <stdio.h>
#include <strings.h>
#include <assert.h>
#include <dirent.h>
#include <sys/stat.h>

#include <event2/event.h>
#include <event2/thread.h>
#include <event2/util.h>
#include <event2/listener.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/dh.h>

#include "main.h"
#include "net.h"
#include "logging.h"
#include "util.h"
#include "worker.h"
#include "dist.h"
#include "hash.h"

int load_distributed_files(const char *workdir);

/**
 * Read Diffie-Hellman parameters from the appropriate file in workdir into an SSL context.
 *
 * Return 0 on success, -1 on failure.
 */
int
load_dh(const char *workdir, SSL_CTX *ctx)
{
        char *path = printf_dup("%s/keys/dh_params", workdir);

        BIO *f = BIO_new_file(path, "r");
        if (!f)
                goto err;
        DH *dh = PEM_read_bio_DHparams(f,NULL,NULL,NULL);
        if (!dh)
                goto err;
        int codes;
        if (DH_check(dh, &codes) == 0 || codes) {
                log_error("Loaded DH parameters look bad!");
                goto err;
        }

        SSL_CTX_set_tmp_dh(ctx, dh);
        DH_free(dh);
        BIO_free(f);
        free(path);
        return 0;
err:
        if (f)
                BIO_free(f);
        if (path)
                free(path);
        return -1;
}

/**
 * Callback for openssl diffie hellman parameter generation.  Prints little characters to amuse the
 * user while their CPU searches for a safe prime.
 */
static void
dh_verbose_cb(int p, int n, void *arg)
{
        switch (p) {
        case 0:
                fputs(".", stderr);
                break;
        case 1:
                fputs("+", stderr);
                break;
        case 2:
                fputs("*", stderr);
                break;
        case 3:
                fputs("\n", stderr);
                break;
        }
}

/**
 * Generate a new set of Diffie-Hellman parameters of length 'bits', write them to the appropriate
 * file in workdir, and set them in the SSL context.
 *
 * We _do_ want to generate our own parameters rather than using, say, any of the well-known IPSEC
 * primes here: using nearly any well-known prime in TLS can make a protocol more blockable than it
 * would otherwise be, if nobody else is using it... and basically nobody is using the RFC2409
 * primes _in TLS_.
 */
int
generate_dh(const char *workdir, SSL_CTX *ctx, int bits)
{
        log_note("Generating DH parameters. (This could take a while.)");
        DH *dh = DH_generate_parameters(bits, 2, dh_verbose_cb, NULL);

        if (!dh) {
                log_error("Couldn't make DH parameters.");
                return -1;
        }
        char *path = printf_dup("%s/keys/dh_params", workdir);
        BIO *bio = BIO_new_file(path, "w");
        free(path);
        if (!bio) {
                log_error("Couldn't open dh_params for writing");
                DH_free(dh);
                return -1;
        }
        if (!PEM_write_bio_DHparams(bio, dh)) {
                DH_free(dh);
                BIO_free(bio);
                return -1;
        }
        BIO_free(bio);

        SSL_CTX_set_tmp_dh(ctx, dh);
        DH_free(dh);
        return 0;
}

/**
 * OpenSSL callback to ask for a password for reading your private key; see documenation for
 * OpenSSL's SSL_CTX_set_default_passwd_cb for more information on the interface.
 */
static int
pem_passwd_cb(char *buf, int size, int rwflag, void *userdata)
{
        assert(rwflag == 0); /* Only reading is supported */
        return my_getpass("Password for private key: ", buf, size);
}

/**
 * Read our TLS certificate and private key from the appropriate files in the workdir.
 *
 * Return 0 on success, -1 on failure.
 */
static int
load_cert_and_key(const char *workdir, SSL_CTX *ctx)
{
        char *certpath, *keypath;
        certpath = printf_dup("%s/keys/tls_cert", workdir);
        keypath = printf_dup("%s/keys/tls_secret_key", workdir);
        if (!certpath || !keypath)
                /*XXX cleanup*/
                return -1;

        if (!SSL_CTX_use_certificate_chain_file(ctx, certpath)) {
                log_error("SSL_CTX_use_certificate_chain_file");
                return -1; /*XXXX cleanup*/
        }

        /*XXXX check return */
        SSL_CTX_set_default_passwd_cb(ctx, pem_passwd_cb);
        SSL_CTX_set_default_passwd_cb_userdata(ctx, NULL);

        if (!SSL_CTX_use_PrivateKey_file(ctx, keypath, SSL_FILETYPE_PEM)) {
                log_error("SSL_CTX_use_privatekey_file");
                return -1; /*XXXX cleanup*/
        }
        if (!SSL_CTX_check_private_key(ctx)) {
                log_error("SSL_CTX_check_private_key");
                return -1; /*XXXX cleanup*/
        }

        free(certpath);
        free(keypath);

        /* Now, let's log our public key and cretificate hashes. */
        /* XXXX There MUST be a better way to do this. */
        SSL *ssl_tmp = SSL_new(ctx);
        EVP_PKEY *key = SSL_get_privatekey(ssl_tmp);
        uint8_t keydigest[HASH_LEN];
        if (hash_pubkey(keydigest, key) < 0) {
                log_error("Couldn't compute digest of public key");
        } else {
                char *hex = hexdup(keydigest, HASH_LEN);
                log_note("Public key digest: %s", hex);
                free(hex);
        }

        X509 *cert = SSL_get_certificate(ssl_tmp);
        if (hash_cert(keydigest, cert) < 0) {
                log_error("Couldn't compute digest of certificate");
        } else {
                char *hex = hexdup(keydigest, HASH_LEN);
                log_note("Certificate digest: %s", hex);
                free(hex);
        }

        /* XXX do I need to free 'key' ? Do I need to free 'cert'? */
        SSL_free(ssl_tmp);


        return 0;
}

/**
 * Libevent callback: invoked when we get a SIGINT.  Initiates a clean-ish shutdown.
 */
static void
handle_sigint_cb(evutil_socket_t signum, short what, void *arg)
{
        assert(signum == SIGINT);
        struct event_base *base = arg;
        /* XXXX Actually, we should give pending requests a while to finish, if we want to shut down
         * gracefully. */
        event_base_loopexit(base, NULL);
}

/**
 * Libevent callback: invoked when we get a SIGHUP.  Reloads the disrtributions.
 */
static void
handle_sighup_cb(evutil_socket_t signum, short what, void *arg)
{
        assert(signum == SIGHUP);
        const char *workdir = arg;
        load_distributed_files(workdir);
}

/**
 * Libevent callback: invoked when we get a new connection.
 */
static void
listener_cb(struct evconnlistener *listener,
            evutil_socket_t fd,
            struct sockaddr *sa,
            int socklen,
            void *arg)
{
        SSL_CTX *ctx = arg;
        struct event_base *base = evconnlistener_get_base(listener);

        new_connection(base, ctx, fd, sa, socklen);
}

/**
 * Load files for all the distributions in the appropriate directory in our workdir, and launch
 * or stop workers as appropriate.  (We start a worker for each file not previously distributed,
 * and stop all workers that were distributing files we don't have any more.)
 *
 * Return the number of currently configured distributions.
 */
int
load_distributed_files(const char *workdir)
{
        char *directory = printf_dup("%s/dist", workdir);
        if (!directory)
                return -1;
        DIR *d = opendir(directory);
        log_note("Reading files in %s...", directory);
        free(directory);

        /* We use a mark-and-sweep approach to kill obsolete workers.  We start by marking
           everybody.  If we find a distribution file that you're serving, then we remove your
           mark.  At the end of the look, every worker that still has a mark is obsolete. */
        mark_all_workers();

        struct dirent *de;
        int n_ok = 0;
        while ((de = readdir(d))) { /*XXXX not a threadsafe API*/
                if (de->d_name[0] == '.')
                        continue;  /* Skip hidden files */
                char *path = printf_dup("%s/dist/%s", workdir, de->d_name);
                log_note("Reading %s... ", de->d_name);

                struct stat st;
                if (stat(path, &st)) {
                        log_error("couldn't stat");
                        free(path);
                        continue;
                }

                int should_replace=0;
                struct worker *old_worker = worker_get_by_filename(path, &st, &should_replace);
                if (old_worker && !should_replace) {
                        free(path);
                        unmark_worker(old_worker);
                        ++n_ok;
                        continue;
                }

                struct distribution *dist = load_distribution(path);
                free(path);
                if (!dist) {
                        log_error("couldn't load");
                        continue;
                }

                char *hex = hexdup(distribution_get_identity(dist), 32);
                log_note("Distribution identity is %s", hex);
                free(hex);

                struct worker *w = new_worker(dist);
                if (!w) {
                        log_error("couldn't make worker");
                        free_distribution(dist);
                        continue;
                }
                if (start_worker(w) < 0) {
                        log_error("Couldn't start worker");
                        free_worker(w);
                        continue;
                }
                add_worker(w);
                puts("looks okay.");
                ++n_ok;
        }
        closedir(d);

        sweep_marked_workers();

        return n_ok;
}

/**
 * Libevent callback. Invoked periodically to call pthread_join on every worker that has stopped,
 * and do final cleanup on it.
 */
static void
join_workers_cb(evutil_socket_t s, short what, void *arg)
{
        join_all_stopped_workers();
}

/**
 * Explain how to invoke the program.
 */
static void
syntax(void)
{
        puts("Syntax:");
        puts("  inverarity <work_dir> [address] [port]");
        puts("Address defaults to localhost; port defaults to 49494");
}

int
main(int argc, char **argv)
{
        const char *workdir;
        const char *conf_address = "localhost";
        const char *conf_port = "49494";

        /* parse the command line */
        if (argc < 2) {
                log_error("Too few arguments!");
                syntax();
                return 1;
        }
        if (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")) {
                syntax();
                return 1;
        }
        workdir = argv[1];
        if (argc >= 3)
                conf_address = argv[2];
        if (argc >= 4)
                conf_address = argv[3];
        if (argc >= 5) {
                syntax();
                return 1;
        }

        /* Make sure that the main directory and its subdirectories exist, and have reasonable
         * permissions. */
        if (checkdir(workdir, NULL, 0))
                return 1;
        if (checkdir(workdir, "keys", 1))
                return 1;
        if (checkdir(workdir, "dist", 1))
                return 1;

        /* Initialize openssl. */
        SSL_library_init();
        ERR_load_crypto_strings();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        /* XXXX enable engines */

        /* Initialize libevent */
        evthread_use_pthreads();
        struct event_base *evbase = event_base_new();

        /* Set up a response queue so the workers can inform us about completed requests. */
        if (init_response_queue(evbase) < 0) {
                log_error("Can't initialize response queue");
                return 1; /* XXX cleanup */
        }

        /* Initialize an SSL_CTX */
        SSL_CTX *the_ctx = SSL_CTX_new(TLSv1_server_method());
        /* Use only high-strength suites with ephemeral key agreement */
        SSL_CTX_set_cipher_list(the_ctx, "kEDH+HIGH:!3DES");
        SSL_CTX_set_options(the_ctx, SSL_OP_SINGLE_DH_USE);

        /* Initialize the openssl prng nice and early. */
        RAND_poll();

        /* Load the Diffie Hellman parameters, or generate them */
        if (load_dh(workdir, the_ctx) < 0) {
                if (generate_dh(workdir, the_ctx, 1536) < 0) {
                        log_error("Couldn't generate DH parameters");
                        return 1; /*XXXX clean up */
                }
        }
        /* Load our key and certificate */
        if (load_cert_and_key(workdir, the_ctx) < 0) {
                log_error("Couldn't load cert and key");
                return 1;
        }
        /* Throw away sessions; they don't make sense for our use case. */
        SSL_CTX_set_session_cache_mode(the_ctx, SSL_SESS_CACHE_OFF);
        /* XXXX disable compression too; we don't expect to be doing anything compressible. */

        /* Set up signal handlers */
        struct event *sigint_event = evsignal_new(evbase, SIGINT, handle_sigint_cb, evbase);
        struct event *sighup_event = evsignal_new(evbase, SIGHUP, handle_sighup_cb, (void*)workdir);
        event_add(sigint_event, NULL);
        event_add(sighup_event, NULL);

        /* Set up a periodic timer to reap dead workers. */
        struct event *joinworkers_event = event_new(evbase, -1, EV_PERSIST, join_workers_cb, NULL);
        struct timeval joinworkers_timer = { 120, 0 };
        event_add(joinworkers_event, &joinworkers_timer);

        /* Load the files */
        if (load_distributed_files(workdir) == 0) {
                log_error("nothing to distribute");
                return 1; /*XXXX clean up */
        }

        /* Set up the listeners. */
        struct evutil_addrinfo *result, hints, *ai;
        memset(&hints, 0, sizeof(hints));
        hints.ai_flags = EVUTIL_AI_PASSIVE;
        int r = evutil_getaddrinfo(conf_address, conf_port, &hints, &result);
        if (r) {
                log_note("ERR: Couldn't resolve hostname %s port %s: %s",
                         conf_address, conf_port,
                         evutil_gai_strerror(r));
                return 1; /*XXXX clean up */
        }
        for (ai = result; ai; ai=ai->ai_next) {
                struct evconnlistener *lstn;
                lstn = evconnlistener_new_bind(evbase,
                                               listener_cb,
                                               the_ctx,
                                               LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_FREE,
                                               -1,
                                               ai->ai_addr,
                                               ai->ai_addrlen);
                /* XXX save these someplace so we clean them up nicely. */
                (void) lstn;
        }
        evutil_freeaddrinfo(result);

        /* Run the main loop */
        log_note("STARTING!");
        event_base_dispatch(evbase);

        log_note("Clean shutdown.");
        stop_all_workers();
        join_all_stopped_workers();

        return 0;
}

/*
         "Information.  What's wrong with dope and women?  Is it any
     wonder the world's gone insane, with information come to be
     the only real medium of exchange?"

         "I thought it was cigarettes."

         "You dream."

         -- Gravity's Rainbow, p.258
 */

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
