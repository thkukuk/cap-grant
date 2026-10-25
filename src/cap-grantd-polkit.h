//SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <systemd/sd-varlink.h>

#include "cap-grantd.h"

/* What to do if polkit itself cannot be reached (polkitd not running,
   no system bus, out of memory, ...). */
typedef enum CGPolkitAbsentPolicy {
  CG_POLKIT_ABSENT_DENY,   /* privileged actions: fail closed */
  CG_POLKIT_ABSENT_ALLOW,  /* legacy-open actions: fail open, preserves old behaviour */
} CGPolkitAbsentPolicy;

/*
 * Checks whether the peer of "link" is authorized for "action_id".
 *
 * Peer UID 0 (root) is always authorized immediately, without talking to
 * polkit at all, so root keeps working even if polkitd isn't installed or
 * running.
 *
 * For every other caller, the full path of the calling program (resolved
 * via /proc/<pid>/exe) is looked up and passed to polkit as the "program"
 * detail of the CheckAuthorization call, together with the action id. This
 * lets administrators write polkit rules (/etc/polkit-1/rules.d/)
 * that grant specific programs (e.g. /usr/bin/clockdiff or /usr/bin/ping)
 * access without a password, by inspecting action.lookup("program").
 *
 * If no such rule matches, the action's own <defaults> in the .policy file
 * apply. For actions configured as auth_admin_keep, the user is prompted
 * for admin authentication once (via whatever polkit agent is registered
 * for their session) and polkit caches that authorization for subsequent
 * calls for a while, so repeated calls (e.g. re-running clockdiff) do not
 * require the password every time.
 *
 * Return value:
 *   1   -> authorized. The caller should proceed with the privileged
 *          operation as normal.
 *   0   -> an asynchronous check was just started, or is already
 *          outstanding. The caller must `return 0;` immediately without
 *          calling sd_varlink_reply()/sd_varlink_error(); the Varlink
 *          call will be re-dispatched (the whole method handler run
 *          again) once the check completes, via sd_varlink_dispatch_again().
 *   <0  -> the check is finished and failed (denied, or an internal
 *          error); a Varlink error reply has already been sent. The
 *          caller must `return r;` immediately.
 */
int cg_polkit_check_async(sd_varlink *link, CG_CTX *ctx, const char *action_id,
                           CGPolkitAbsentPolicy absent_policy);

/* Must be bound as the Varlink server's disconnect callback (directly via
   sd_varlink_server_bind_disconnect()). Cancels and frees any polkit check
   outstanding for the departing connection. */
void cg_polkit_on_disconnect(sd_varlink_server *server, sd_varlink *link, void *userdata);

/* Called once when shutting down, to release ctx->polkit_bus and any
   (normally none) leftover pending query nodes. */
void cg_polkit_context_done(CG_CTX *ctx);
