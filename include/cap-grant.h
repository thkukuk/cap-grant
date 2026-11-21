//SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int cap_grant_nice(int inc, char **error);
extern int cap_grant_setpriority(int which, id_t who, int priority, char **error);
extern int cap_grant_socket(int domain, int type, int protocol, char **error);


#ifdef __cplusplus
}
#endif
