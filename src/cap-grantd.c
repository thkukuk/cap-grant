//SPDX-License-Identifier: GPL-2.0-or-later

#include "config.h"

#include <limits.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdbool.h>
#include <libintl.h>
#include <syslog.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-varlink.h>
#include <systemd/sd-journal.h>

#include "basics.h"
#include "cap-grant.h"
#include "mkdir_p.h"
#include "log_msg.h"

#include "varlink-socket.h"
#include "varlink-org.openSUSE.cap-grant.h"
#include "cap-grantd.h"
#include "cap-grantd-polkit.h"

static int socket_activation = false;

static int
vl_method_ping(sd_varlink *link, sd_json_variant *parameters,
	       sd_varlink_method_flags_t _unused_(flags),
	       void _unused_(*userdata))
{
  int r;

  log_msg(LOG_INFO, "Varlink method \"Ping\" called...");

  r = sd_varlink_dispatch(link, parameters, NULL, NULL);
  if (r != 0)
    return r;

  return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_BOOLEAN("Alive", true));
}

static int
vl_method_set_log_level(sd_varlink *link, sd_json_variant *parameters,
			sd_varlink_method_flags_t _unused_(flags),
			void *userdata)
{
  static const sd_json_dispatch_field dispatch_table[] = {
    { "Level", SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int, 0, SD_JSON_MANDATORY },
    {}
  };
  CG_CTX *ctx = userdata;
  int r, level;

  log_msg(LOG_INFO, "Varlink method \"SetLogLevel\" called...");

  r = sd_varlink_dispatch(link, parameters, dispatch_table, &level);
  if (r != 0)
    return r;

  log_msg(LOG_DEBUG, "Log level %i requested", level);

  r = cg_polkit_check_async(link, ctx, "org.openSUSE.CapGrant.set-log-level", CG_POLKIT_ABSENT_DENY);
  if (r <= 0)
    return r;

  set_max_log_level(level);

  log_msg(LOG_INFO, "New log setting: level=%i", level);

  return sd_varlink_reply(link, NULL);
}

static int
vl_method_quit(sd_varlink *link, sd_json_variant *parameters,
	       sd_varlink_method_flags_t _unused_(flags),
	       void *userdata)
{
  struct p {
    int code;
  } p = {
    .code = 0
  };
  static const sd_json_dispatch_field dispatch_table[] = {
    { "ExitCode", SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int, offsetof(struct p, code), 0 },
    {}
  };
  CG_CTX *ctx = userdata;
  int r;

  log_msg(LOG_INFO, "Varlink method \"Quit\" called...");

  r = sd_varlink_dispatch(link, parameters, dispatch_table, /* userdata= */ NULL);
  if (r != 0)
    {
      log_msg(LOG_ERR, "Quit request: varlink dispatch failed: %s", strerror(-r));
      return r;
    }

  r = cg_polkit_check_async(link, ctx, "org.openSUSE.CapGrant.quit", CG_POLKIT_ABSENT_DENY);
  if (r <= 0)
    return r;

  r = sd_event_exit(ctx->loop, p.code);
  if (r != 0)
    {
      log_msg(LOG_ERR, "Quit request: disabling event loop failed: %s",
	      strerror(-r));
      return sd_varlink_errorbo(link, "org.openSUSE.CapGrant.InternalError",
                                SD_JSON_BUILD_PAIR_BOOLEAN("Success", false));
    }

  return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_BOOLEAN("Success", true));
}

static int
vl_method_setpriority(sd_varlink *link, sd_json_variant *parameters,
		      sd_varlink_method_flags_t _unused_(flags),
		      void *userdata)
{
  static const sd_json_dispatch_field dispatch_table[] = {
    { "Priority", SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int64, 0, SD_JSON_MANDATORY },
    {}
  };
  _cleanup_(freep) char *error = NULL;
  CG_CTX *ctx = userdata;
  int64_t prio;
  pid_t process_id;
  int r;

  log_msg(LOG_INFO, "Varlink method \"SetPriority\" called...");

  r = sd_varlink_dispatch(link, parameters, dispatch_table, &prio);
  if (r != 0)
    {
      log_msg(LOG_ERR, "SetPriority request: varlink dispatch failed: %s", strerror(-r));
      return r;
    }

  r = sd_varlink_get_peer_pid(link, &process_id);
  if (r < 0)
    {
      log_msg(LOG_ERR, "Failed to get peer PID: %s", strerror(-r));
      return r;
    }

  log_msg(LOG_DEBUG, "Setpriority with Priority '%li' for process '%i' requested", prio, process_id);

  r = cg_polkit_check_async(link, ctx, "org.openSUSE.CapGrant.setpriority", CG_POLKIT_ABSENT_DENY);
  if (r <= 0)
    return r;

  r = setpriority(PRIO_PROCESS, process_id, prio);
  if (r < 0)
    {
      int save_errno = errno;
      log_msg(LOG_ERR, "Setpriority failed: %s", strerror(save_errno));
      return sd_varlink_errorbo(link, "org.openSUSE.CapGrant.InternalError",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
                                SD_JSON_BUILD_PAIR_STRING("ErrorMsg", strerror(save_errno)));
    }

  return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_BOOLEAN("Success", true));
}

/* Only grant raw ICMP sockets, used e.g. for ping-style tools which
   would otherwise need to be setuid/have CAP_NET_RAW themselves. */
static bool
allowed_socket_params(int domain, int type, int protocol)
{
  int base_type = type & ~(SOCK_CLOEXEC | SOCK_NONBLOCK);

  if (base_type != SOCK_RAW && base_type != SOCK_DGRAM)
    return false;

  if (domain == AF_INET && protocol == IPPROTO_ICMP)
    return true;

  if (domain == AF_INET6 && protocol == IPPROTO_ICMPV6)
    return true;

  return false;
}

static int
vl_method_socket(sd_varlink *link, sd_json_variant *parameters,
		  sd_varlink_method_flags_t _unused_(flags),
		  void *userdata)
{
  struct p {
    int domain;
    int type;
    int protocol;
  } p = { 0 };
  static const sd_json_dispatch_field dispatch_table[] = {
    { "Domain",   SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int, offsetof(struct p, domain),   SD_JSON_MANDATORY },
    { "Type",     SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int, offsetof(struct p, type),     SD_JSON_MANDATORY },
    { "Protocol", SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int, offsetof(struct p, protocol), SD_JSON_MANDATORY },
    {}
  };
  CG_CTX *ctx = userdata;
  int r;

  log_msg(LOG_INFO, "Varlink method \"Socket\" called...");

  r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
  if (r != 0)
    {
      log_msg(LOG_ERR, "Socket request: varlink dispatch failed: %s", strerror(-r));
      return r;
    }

  r = cg_polkit_check_async(link, ctx, "org.openSUSE.CapGrant.socket", CG_POLKIT_ABSENT_DENY);
  if (r <= 0)
    return r;

  if (!allowed_socket_params(p.domain, p.type, p.protocol))
    {
      log_msg(LOG_WARNING, "Socket: refused request for domain=%i type=%i protocol=%i",
	      p.domain, p.type, p.protocol);
      return sd_varlink_errorbo(link, "org.openSUSE.CapGrant.InternalError",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
                                SD_JSON_BUILD_PAIR_STRING("ErrorMsg", "Requested socket parameters not allowed"));
    }

  int fd = socket(p.domain, p.type, p.protocol);
  if (fd < 0)
    {
      int save_errno = errno;
      log_msg(LOG_ERR, "socket() failed: %s", strerror(save_errno));
      return sd_varlink_errorbo(link, "org.openSUSE.CapGrant.InternalError",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
                                SD_JSON_BUILD_PAIR_STRING("ErrorMsg", strerror(save_errno)));
    }

  r = sd_varlink_push_fd(link, fd);
  if (r < 0)
    {
      log_msg(LOG_ERR, "Failed to push fd to client: %s", strerror(-r));
      close(fd);
      return r;
    }

  return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_BOOLEAN("Success", true));
}

/* Send a messages to systemd daemon, that inicialization of daemon
   is finished and daemon is ready to accept connections. */
static void
announce_ready(void)
{
  int r = sd_notify(0, "READY=1\n"
		    "STATUS=Processing requests...");
  if (r < 0)
    log_msg(LOG_ERR, "sd_notify(READY) failed: %s", strerror(-r));
}

static void
announce_stopping(void)
{
  int r = sd_notify(0, "STOPPING=1\n"
		    "STATUS=Shutting down...");
  if (r < 0)
    log_msg(LOG_ERR, "sd_notify(STOPPING) failed: %s", strerror(-r));
}

/* event loop which quits after 30 seconds idle time */
#define USEC_PER_SEC  ((uint64_t) 1000000ULL)
#define DEFAULT_EXIT_USEC (30*USEC_PER_SEC)

static int
varlink_event_loop_with_idle(sd_event *e, sd_varlink_server *s)
{
  int r, code;

  for (;;)
    {
      r = sd_event_get_state(e);
      if (r < 0)
	return r;
      if (r == SD_EVENT_FINISHED)
	break;

      r = sd_event_run(e, DEFAULT_EXIT_USEC);
      if (r < 0)
	return r;

      if (r == 0 && (sd_varlink_server_current_connections(s) == 0))
	sd_event_exit(e, 0);
    }

  r = sd_event_get_exit_code(e, &code);
  if (r < 0)
    return r;

  return code;
}

static int
run_varlink(void)
{
  int r;
  _cleanup_(sd_event_unrefp) sd_event *event = NULL;
  _cleanup_(cg_polkit_context_done) CG_CTX ctx = {};
  _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *varlink_server = NULL;

  r = mkdir_p(_VARLINK_CAP_GRANT_SOCKET_DIR, 0755);
  if (r < 0)
    {
      log_msg(LOG_ERR, "Failed to create directory '"_VARLINK_CAP_GRANT_SOCKET_DIR"' for Varlink socket: %s",
	      strerror(-r));
      return r;
    }

  r = sd_event_new(&event);
  if (r < 0)
    {
      log_msg(LOG_ERR, "Failed to create new event: %s",
	      strerror(-r));
      return r;
    }
  ctx.loop = event;

  r = sd_varlink_server_new(&varlink_server, SD_VARLINK_SERVER_ACCOUNT_UID|SD_VARLINK_SERVER_INHERIT_USERDATA|SD_VARLINK_SERVER_ALLOW_FD_PASSING_OUTPUT);
  if (r < 0)
    {
      log_msg(LOG_ERR, "Failed to allocate varlink server: %s",
	      strerror(-r));
      return r;
    }

  r = sd_varlink_server_set_description(varlink_server, "cap-grantd");
  if (r < 0)
    {
      log_msg(LOG_ERR, "Failed to set varlink server description: %s",
	      strerror(-r));
      return r;
    }

  r = sd_varlink_server_set_info(varlink_server, NULL, PACKAGE" (cap-grantd)",
				 VERSION, "https://github.com/thkukuk/cap-grant");
  if (r < 0)
    return r;

  r = sd_varlink_server_add_interface(varlink_server, &vl_interface_org_openSUSE_CapGrant);
  if (r < 0)
    {
      log_msg(LOG_ERR, "Failed to add interface: %s", strerror(-r));
      return r;
    }

  r = sd_varlink_server_bind_method_many(varlink_server,
					 "org.openSUSE.CapGrant.SetPriority",  vl_method_setpriority,
					 "org.openSUSE.CapGrant.Socket",       vl_method_socket,
					 "org.openSUSE.CapGrant.Ping",         vl_method_ping,
					 "org.openSUSE.CapGrant.Quit",         vl_method_quit,
					 "org.openSUSE.CapGrant.SetLogLevel",  vl_method_set_log_level);
  if (r < 0)
    {
      log_msg(LOG_ERR, "Failed to bind Varlink methods: %s",
	      strerror(-r));
      return r;
    }

  sd_varlink_server_set_userdata(varlink_server, &ctx);

  r = sd_varlink_server_bind_disconnect(varlink_server, cg_polkit_on_disconnect);
  if (r < 0)
    {
      log_msg(LOG_ERR, "Failed to bind disconnect callback: %s", strerror(-r));
      return r;
    }

  r = sd_varlink_server_attach_event(varlink_server, event, SD_EVENT_PRIORITY_NORMAL);
  if (r < 0)
    {
      log_msg(LOG_ERR, "Failed to attach to event: %s", strerror(-r));
      return r;
    }

  r = sd_varlink_server_listen_auto(varlink_server);
  if (r < 0)
    {
      log_msg(LOG_ERR, "Failed to listens: %s", strerror(-r));
      return r;
    }


  if (!socket_activation)
    {
      r = sd_varlink_server_listen_address(varlink_server, _VARLINK_CAP_GRANT_SOCKET, 0666);
      if (r < 0)
	{
	  log_msg(LOG_ERR, "Failed to bind to Varlink socket: %s", strerror(-r));
	  return r;
	}
    }

  announce_ready();
  if (socket_activation)
    r = varlink_event_loop_with_idle(event, varlink_server);
  else
    r = sd_event_loop(event);
  announce_stopping();

  return r;
}

static void
print_help(void)
{
  printf("cap-grantd - Assign capabilities to other processes\n");

  printf("  -s, --socket   Activation through socket\n");
  printf("  -d, --debug    Debug mode\n");
  printf("  -v, --verbose  Verbose logging\n");
  printf("  -?, --help     Give this help list\n");
  printf("      --version  Print program version\n");
}

int
main(int argc, char **argv)
{
  while (1)
    {
      int c;
      int option_index = 0;
      static struct option long_options[] =
        {
	  {"socket", no_argument, NULL, 's'},
          {"debug", no_argument, NULL, 'd'},
          {"verbose", no_argument, NULL, 'v'},
          {"version", no_argument, NULL, '\255'},
          {"usage", no_argument, NULL, '?'},
          {"help", no_argument, NULL, 'h'},
          {NULL, 0, NULL, '\0'}
        };


      c = getopt_long(argc, argv, "sdvh?", long_options, &option_index);
      if (c == (-1))
        break;
      switch (c)
        {
	case 's':
	  socket_activation = true;
	  break;
        case 'd':
	  set_max_log_level(LOG_DEBUG);
          break;
        case '?':
        case 'h':
          print_help();
          return 0;
        case 'v':
	  set_max_log_level(LOG_INFO);
          break;
        case '\255':
          fprintf(stdout, "cap-grantd (%s) %s\n", PACKAGE, VERSION);
          return 0;
        default:
          print_help();
          return 1;
        }
    }

  argc -= optind;
  argv += optind;

  if (argc > 1)
    {
      fprintf(stderr, "Try `cap-grantd --help' for more information.\n");
      return 1;
    }

  log_msg(LOG_INFO, "Starting cap-grantd (%s) %s...", PACKAGE, VERSION);

  int r = run_varlink();
  if (r < 0)
    {
      log_msg(LOG_ERR, "ERROR: varlink loop failed: %s", strerror(-r));
      return -r;
    }

  log_msg(LOG_INFO, "cap-grantd stopped.");

  return 0;
}
