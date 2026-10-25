// SPDX-License-Identifier: LGPL-2.1-or-later

#include "config.h"

#include <time.h>
#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>
#include <unistd.h>
#include <systemd/sd-journal.h>

#include "log_msg.h"

static int log_level = LOG_WARNING;

void
set_max_log_level (int level)
{
  log_level = level;
}

void
log_msg(int priority, const char *fmt, ...)
{
  static int is_tty = -1;
  va_list ap;

  if (priority > log_level)
    return;

  if (is_tty == -1)
    is_tty = isatty (STDOUT_FILENO);

  va_start(ap, fmt);

  if (is_tty)
    {
      if (priority == LOG_ERR)
	{
	  vfprintf(stderr, fmt, ap);
	  fputc('\n', stderr);
	}
      else
	{
	  vprintf(fmt, ap);
	  putchar('\n');
	}
    }
  else
    sd_journal_printv(priority, fmt, ap);

  va_end(ap);
}
