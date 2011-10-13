/* Inverarity is Copyright 2011 by Nick Mathewson.                    ____/|/|
   This is free software; see LICENSE at end of file for more info.     O \|\|
*/

#ifndef INVERARITY_UTIL_H
#define INVERARITY_UTIL_H

#include <stdarg.h>

#ifndef __GNUC__
#define __attribute__(x)
#endif

/**
 * Check whether the directory dir/subdir exists with appropriate permissions -- here defined as
 * mode 700, owned by us.  If subdr is empty, checks dir.  If create is true, creates the directory
 * if it doesn't exist.
 */
int checkdir(const char *dir, const char *subdir, int create);

/**
 * As vsprintf, but returns a newly allocated string contaning the formatted output.
 *
 * (We define this because asprintf isn't portable, sprintf isn't safe, and snprintf can be a
 * pain.)
 */
char *vprintf_dup(const char *format, va_list lst);
/**
 * As sprintf, but returns a newly allocated string contaning the formatted output.
 *
 * (We define this because asprintf isn't portable, sprintf isn't safe, and snprintf can be a
 * pain.)
 */
char *printf_dup(const char *format, ...)
  __attribute__((format(printf, 1, 2)))
;

/**
 * Return a newly allocated string containing the len-byte stream in input, encoded in hexadecimal.
 *
 * Case is not guaranteed.
 */
char *hexdup(const uint8_t *input, size_t len);

/**
 * Try to read a password without echoing it to the terminal.  Begin by displaying 'prompt', then
 * write the result into the 'size'-byte buffer at 'buf'.  Returns the number of characers in the
 * password.
 */
int my_getpass(const char *prompt, char *buf, int size);

/**
 * As strcmp, but compares that last strlen(suffix) characters of 'str' to 'suffix'
 **/
int strcmpend(const char *str, const char *suffix);

#endif
/*
  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to
  deal in the Software without restricti on, including without limitation the
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
