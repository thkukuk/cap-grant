//SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

/* logging */
#include <syslog.h>
extern void set_max_log_level (int level);
extern void log_msg(int priority, const char *fmt, ...);
