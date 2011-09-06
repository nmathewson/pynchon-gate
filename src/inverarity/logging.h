/* Inverarity is Copyright 2011 by Nick Mathewson.                    ____/|/|
   This is free software; see LICENSE at end of file for more info.     O \|\|
*/
#ifndef INVERARITY_LOGGING_H
#define INVERARITY_LOGGING_H

/* General-purpose logging code.
 *
 * Right now, it just sends everything to stdout.  But eventually, there should probably be a
 * logfile facility that this can use.  Let's not get overcomplicated, though.
 */

#ifndef __GNUC__
#define __attribute__(x)
#endif

/** Log an error message.  The formatting is as for printf. */
void log_error(const char *fmt, ...)
  __attribute__((format(printf, 1, 2)))
;
/** Log an error message.  The formatting is as for perror. */
void log_perror(const char *str);
/** Log an non-error message.  The formatting is as for printf. */
void log_note(const char *fmt, ...)
  __attribute__((format(printf, 1, 2)))
;

#endif
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
