//SPDX-License-Identifier: LGPL-2.1-or-later

/* Integration test client for libcap-grant. Exercises the three
   exported library functions against a running cap-grantd instance.
   Meant to be run against an isolated, test-only cap-grantd (see
   run-integration-tests.sh), never against a production instance,
   since it changes this process' own nice value. */

#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#include "cap-grant.h"

static int failures = 0;

#define CHECK(cond, fmt, ...)						\
  do									\
    {									\
      if (cond)								\
	printf("PASS: " fmt "\n", ##__VA_ARGS__);			\
      else								\
	{								\
	  printf("FAIL: " fmt "\n", ##__VA_ARGS__);			\
	  failures++;							\
	}								\
    }									\
  while (0)

static void
free_error(char **error)
{
  if (*error)
    {
      printf("      error: %s\n", *error);
      free(*error);
      *error = NULL;
    }
}

static void
test_nice(void)
{
  char *error = NULL;
  int before, after, r;

  errno = 0;
  before = getpriority(PRIO_PROCESS, 0);
  CHECK(errno == 0, "getpriority() baseline succeeds");

  r = cap_grant_nice(2, &error);
  CHECK(r == 0, "cap_grant_nice(+2) succeeds");
  free_error(&error);

  errno = 0;
  after = getpriority(PRIO_PROCESS, 0);
  CHECK(after == before + 2, "nice value increased by 2 (before=%d, after=%d)", before, after);

  before = after;
  r = cap_grant_nice(-1, &error);
  CHECK(r == 0, "cap_grant_nice(-1) succeeds (requires CAP_SYS_NICE in daemon)");
  free_error(&error);

  after = getpriority(PRIO_PROCESS, 0);
  CHECK(after == before - 1, "nice value decreased by 1 (before=%d, after=%d)", before, after);
}

static void
test_setpriority(void)
{
  char *error = NULL;
  int r;

  r = cap_grant_setpriority(PRIO_PROCESS, 0, 0, &error);
  CHECK(r == 0, "cap_grant_setpriority(PRIO_PROCESS, 0, 0) succeeds");
  free_error(&error);

  errno = 0;
  int cur = getpriority(PRIO_PROCESS, 0);
  CHECK(errno == 0 && cur == 0, "nice value is 0 after cap_grant_setpriority (cur=%d)", cur);

  r = cap_grant_setpriority(PRIO_USER, 0, 0, &error);
  CHECK(r == -EINVAL, "cap_grant_setpriority() rejects which != PRIO_PROCESS (r=%d)", r);
  free_error(&error);

  r = cap_grant_setpriority(PRIO_PROCESS, (id_t) getpid() + 1, 0, &error);
  CHECK(r == -EINVAL, "cap_grant_setpriority() rejects who != self (r=%d)", r);
  free_error(&error);
}

static void
test_socket(void)
{
  char *error = NULL;
  int fd;

  fd = cap_grant_socket(AF_INET, SOCK_RAW, IPPROTO_ICMP, &error);
  CHECK(fd >= 0, "cap_grant_socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) succeeds (fd=%d)", fd);
  free_error(&error);
  if (fd >= 0)
    close(fd);

  fd = cap_grant_socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6, &error);
  CHECK(fd >= 0, "cap_grant_socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6) succeeds (fd=%d)", fd);
  free_error(&error);
  if (fd >= 0)
    close(fd);

  fd = cap_grant_socket(AF_INET, SOCK_STREAM, 0, &error);
  CHECK(fd < 0, "cap_grant_socket(AF_INET, SOCK_STREAM, 0) is refused (fd=%d)", fd);
  free_error(&error);
}

int
main(void)
{
  test_nice();
  test_setpriority();
  test_socket();

  if (failures > 0)
    {
      printf("%d check(s) FAILED\n", failures);
      return 1;
    }

  printf("All checks passed\n");
  return 0;
}
