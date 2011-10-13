/* Inverarity is Copyright 2011 by Nick Mathewson.                    ____/|/|
   This is free software; see LICENSE at end of file for more info.     O \|\|
*/
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <fcntl.h>
#include <termios.h>
#include <netinet/in.h>

#include "util.h"
#include "logging.h"

int
checkdir(const char *dir, const char *subdir, int create)
{
        char *path;
        int res = 0;

        if (subdir)
                path = printf_dup("%s/%s", dir, subdir);

        else
                path = strdup(dir);

        if (!path)
                return -1;

        struct stat st;
        int do_create = 0;
        if (stat(path, &st)) {
                if (create && errno == ENOENT) {
                        do_create = 1;
                } else {
                        log_perror("stat");
                        goto err;
                }
        }
        if (!S_ISDIR(st.st_mode)) {
                log_error("expected a dir but got a file");
                goto err;
        }
        if (do_create) {
                if (mkdir(path, 0700)) {
                        log_perror("mkdir");
                        goto err;
                }
                if (stat(path, &st)) {
                        log_perror("stat (2)");
                        goto err;
                }
        }
        if (st.st_mode & 0077 || st.st_uid != geteuid()) {
                log_error("bad permissions");
                goto err;
        }

        goto ok;
err:
        res = -1;
ok:
        free(path);
        return res;
}

char *
vprintf_dup(const char *format, va_list lst)
{
        size_t sz;
        va_list lst_copy;
        char b[1];
        char *result;

        /* This is inefficient, but in practice it should be nowhere near critical path. */

        va_copy(lst_copy, lst);
        sz = vsnprintf(b, 1, format, lst_copy);
        va_end(lst_copy);

        result = malloc(sz + 1);
        vsnprintf(result, sz+1, format, lst);
        return result;
}

char *
printf_dup(const char *format, ...)
{
        va_list lst;
        va_start(lst, format);
        char *result = vprintf_dup(format, lst);
        va_end(lst);
        return result;
}

char *
hexdup(const uint8_t *input, size_t n)
{
        char *result = malloc(n*2+1), *cp;
        if (!result)
                return NULL;
        size_t i;
        cp=result;
        for (i=0; i < n; ++i) {
                *cp++ = "0123456789ABCDEF"[input[i] >> 4];
                *cp++ = "0123456789ABCDEF"[input[i] & 15];
        }
        *cp = '\0';
        return result;
}

int
my_getpass(const char *prompt, char *buf, int size)
{
        FILE *in = NULL;

        /* This approach is a big cargo-culty, and honestly I'd rather not even have to do this.
         *
         * XXXX find some good code with a friendly license to drop in here instead.
         */

        int is_tty = isatty(0);
        if (is_tty) {
                int fd = open("/dev/tty", O_RDONLY);
                if (fd >= 0)
                        in = fdopen(fd, "r");
        } else {
                in = stdin;
        }

        struct termios termios;
        tcflag_t saved_flags = 0;
        int restore=1;

        if (is_tty) {
                /* XXX do we need to block sigint? */
                printf("%s", prompt);
                if (tcgetattr(0, &termios)) {
                        restore = 0;
                } else {
                        saved_flags = termios.c_lflag;
                        termios.c_lflag &= ~ECHO;
                        tcsetattr(0, TCSAFLUSH, &termios);
                }
        }

        char *result = fgets(buf, size, in);
        int len = 0;
        if (result) {
                len = strlen(buf);
                if (len && buf[len-1] == '\n')
                        --len;
        }

        if (is_tty && restore) {
                termios.c_lflag = saved_flags;
                puts("");
                tcsetattr(0, TCSAFLUSH, &termios);
        }

        return len;
}

int
strcmpend(const char *str, const char *suffix)
{
        const size_t str_len = strlen(str);
        const size_t suf_len = strlen(suffix);

        if (str_len < suf_len)
                return -1;
        return strcmp(str + str_len - suf_len, suffix);
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
