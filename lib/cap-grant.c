//SPDX-License-Identifier: LGPL-2.1-or-later

#include "config.h"

#include <errno.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/wait.h>

#include <systemd/sd-varlink.h>

#include "basics.h"
#include "varlink-socket.h"
#include "cap-grant.h"

static int
connect_to_cap_grantd(sd_varlink **ret, const char *socket, char **error)
{
  _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
  int r;

  r = sd_varlink_connect_address(&link, socket);
  if (r < 0)
    {
      if (error)
	if (asprintf (error, "Failed to connect to %s: %s",
		      socket, strerror(-r)) < 0)
	  *error = strdup ("Out of memory");
      return r;
    }

  *ret = TAKE_PTR(link);
  return 0;
}

struct status {
  bool success;
  char *error;
};

static void
status_free (struct status *var)
{
  var->error = mfree(var->error);
}

static void
stop_pkttyagent(pid_t pid)
{
  if (pid <= 0)
    return;

  kill(pid, SIGTERM);
  waitpid(pid, NULL, 0);
}

static void
stop_pkttyagentp(pid_t *pid)
{
  stop_pkttyagent(*pid);
}

/* Best-effort: register a short-lived polkit text authentication agent
   for our own process, so that if cap-grantd's polkit check needs
   interactive authentication, polkit has an agent to call instead of
   just telling cap-grantd "no agent available" (which cap-grantd then
   reports back as "interactive authentication required"). Desktop
   sessions normally already have an agent running, hence --fallback:
   don't replace it, pkttyagent then simply won't register itself.

   If we are already root, cap-grantd's own polkit check bypasses
   polkit entirely, so there is nothing to authenticate and no agent is
   needed. If pkttyagent isn't installed or fails to register, we
   simply proceed without one, exactly as if this function didn't
   exist. */
static int
start_pkttyagent(pid_t *ret_pid)
{
  int pipefd[2];
  pid_t pid;

  *ret_pid = 0;

  if (getuid() == 0)
    return 0;

  if (pipe(pipefd) < 0)
    return -errno;

  pid = fork();
  if (pid < 0)
    {
      int saved_errno = errno;
      close(pipefd[0]);
      close(pipefd[1]);
      return -saved_errno;
    }

  if (pid == 0)
    {
      char process_arg[32];
      char notify_arg[32];

      close(pipefd[0]);

      snprintf(process_arg, sizeof process_arg, "--process=%ld", (long) getppid());
      snprintf(notify_arg, sizeof notify_arg, "--notify-fd=%d", pipefd[1]);

      execlp("pkttyagent", "pkttyagent", process_arg, "--fallback", notify_arg, NULL);
      _exit(127);
    }

  close(pipefd[1]);

  /* pkttyagent closes the notify fd once it has registered (or if it
     gives up/exits early), so this blocks exactly until it's safe to
     issue the privileged call. */
  char buf[1];
  while (read(pipefd[0], buf, sizeof buf) > 0)
    ;
  close(pipefd[0]);

  *ret_pid = pid;
  return 0;
}

int
cap_grant_nice(int inc, char **error)
{
  _cleanup_(status_free) struct status p = {
    .success = false,
    .error = NULL,
  };
  static const sd_json_dispatch_field dispatch_table[] = {
    { "Success", SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, offsetof(struct status, success), 0 },
    { "ErrorMsg", SD_JSON_VARIANT_STRING, sd_json_dispatch_string,  offsetof(struct status, error), 0 },
    {}
  };
  _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
  _cleanup_(sd_json_variant_unrefp) sd_json_variant *params = NULL;
  _cleanup_(stop_pkttyagentp) pid_t pkttyagent_pid = 0;
  sd_json_variant *result;
  int r;

  r = connect_to_cap_grantd(&link, _VARLINK_CAP_GRANT_SOCKET, error);
  if (r < 0)
    return r;

  (void) start_pkttyagent(&pkttyagent_pid);

  errno = 0;
  int current = getpriority(PRIO_PROCESS, 0);
  if (current == -1 && errno != 0)
    {
      r = -errno;
      if (error)
        if (asprintf (error, "Failed to get current priority: %s",
                      strerror(errno)) < 0)
          *error = strdup ("Out of memory");
      return r;
    }

  int priority = current + inc;
  if (priority < PRIO_MIN)
    priority = PRIO_MIN;
  else if (priority >= PRIO_MAX)
    priority = PRIO_MAX - 1;

  r = sd_json_buildo(&params,
                     SD_JSON_BUILD_PAIR("Priority", SD_JSON_BUILD_INTEGER(priority)));
  if (r < 0)
    {
      if (error)
        if (asprintf (error, "Failed to build JSON data: %s",
                      strerror(-r)) < 0)
          *error = strdup ("Out of memory");
      return r;
    }

  const char *error_id;
  r = sd_varlink_call(link, "org.openSUSE.CapGrant.SetPriority", params, &result, &error_id);
  if (r < 0)
    {
      if (error)
        if (asprintf (error, "Failed to call Nice method: %s",
                      strerror(-r)) < 0)
          *error = strdup ("Out of memory");
      return r;
    }

  /* dispatch before checking error_id, we may need the result for the error
     message */
  r = sd_json_dispatch(result, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &p);
  if (r < 0)
    {
      if (error)
        if (asprintf (error, "Failed to parse JSON answer: %s",
                      strerror(-r)) < 0)
          *error = strdup("Out of memory");
      return r;
    }

  if (error_id && strlen(error_id) > 0)
    {
      if (error)
        {
          if (p.error)
            *error = strdup(p.error);
          else
            *error = strdup(error_id);
        }
      return -EIO;
    }

  return 0;
}

int
cap_grant_socket(int domain, int type, int protocol, char **error)
{
  _cleanup_(status_free) struct status p = {
    .success = false,
    .error = NULL,
  };
  static const sd_json_dispatch_field dispatch_table[] = {
    { "Success", SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, offsetof(struct status, success), 0 },
    { "ErrorMsg", SD_JSON_VARIANT_STRING, sd_json_dispatch_string,  offsetof(struct status, error), 0 },
    {}
  };
  _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
  _cleanup_(sd_json_variant_unrefp) sd_json_variant *params = NULL;
  _cleanup_(stop_pkttyagentp) pid_t pkttyagent_pid = 0;
  sd_json_variant *result;
  int r;

  r = connect_to_cap_grantd(&link, _VARLINK_CAP_GRANT_SOCKET, error);
  if (r < 0)
    return r;

  (void) start_pkttyagent(&pkttyagent_pid);

  r = sd_varlink_set_allow_fd_passing_input(link, 1);
  if (r < 0)
    {
      if (error)
        if (asprintf (error, "Failed to enable fd passing: %s",
                      strerror(-r)) < 0)
          *error = strdup ("Out of memory");
      return r;
    }

  r = sd_json_buildo(&params,
                     SD_JSON_BUILD_PAIR("Domain", SD_JSON_BUILD_INTEGER(domain)),
                     SD_JSON_BUILD_PAIR("Type", SD_JSON_BUILD_INTEGER(type)),
                     SD_JSON_BUILD_PAIR("Protocol", SD_JSON_BUILD_INTEGER(protocol)));
  if (r < 0)
    {
      if (error)
        if (asprintf (error, "Failed to build JSON data: %s",
                      strerror(-r)) < 0)
          *error = strdup ("Out of memory");
      return r;
    }

  const char *error_id;
  r = sd_varlink_call(link, "org.openSUSE.CapGrant.Socket", params, &result, &error_id);
  if (r < 0)
    {
      if (error)
        if (asprintf (error, "Failed to call Socket method: %s",
                      strerror(-r)) < 0)
          *error = strdup ("Out of memory");
      return r;
    }

  /* dispatch before checking error_id, we may need the result for the error
     message */
  r = sd_json_dispatch(result, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &p);
  if (r < 0)
    {
      if (error)
        if (asprintf (error, "Failed to parse JSON answer: %s",
                      strerror(-r)) < 0)
          *error = strdup("Out of memory");
      return r;
    }

  if (error_id && strlen(error_id) > 0)
    {
      if (error)
        {
          if (p.error)
            *error = strdup(p.error);
          else
            *error = strdup(error_id);
        }
      return -EIO;
    }

  r = sd_varlink_take_fd(link, 0);
  if (r < 0)
    {
      if (error)
        if (asprintf (error, "Failed to receive socket fd: %s",
                      strerror(-r)) < 0)
          *error = strdup("Out of memory");
      return r;
    }

  return r;
}

