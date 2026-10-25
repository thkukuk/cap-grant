# cap-grant

cap-grant lets unprivileged programs obtain the specific Linux
capabilities they need (raw sockets, renice), even on systems
that run with `NoNewPrivs` set globally, where file capabilities
(`cap_net_raw`, `cap_sys_nice`, ...) no longer work.

## The problem

File capabilities (set with `setcap` on a binary) only take effect if
the process is allowed to gain privileges on `execve()`. If a process
has `PR_SET_NO_NEW_PRIVS` set the kernel ignores any file capabilities
on the binaries it executes. See <https://www.thkukuk.de/blog/no_new_privs/>
for the background.

## The solution

cap-grant moves the privileged operation out of the unprivileged
process and into a small, socket activated daemon, `cap-grantd`, which:

* Is reachable over a Varlink socket (`/run/cap-grant/org.openSUSE.CapGrant`)
* Authorizes every request through PolicyKit (`polkit`) before acting
* Performs the privileged operation itself (e.g.
 [socket(2)](https://manpages.opensuse.org/socket.2) or
 [setpriority(2)](https://manpages.opensuse.org/setpriority.2)

Because the client never needs to gain privileges itself, this works
whether or not `NoNewPrivs` is set on the client process.

`libcap-grant` is the small client library applications link against
to talk to `cap-grantd`. `clockdiff` (bundled under `examples/`) is a
real-world example of a tool ported to use it in place of file
capabilities.

## Components

| Component | Description |
|---|---|
| `cap-grantd` | System daemon, started via systemd socket activation. |
| `libcap-grant` | Client library (public header: `cap-grant.h`) that applications link against to talk to `cap-grantd` over Varlink. |
| `examples/clockdiff` | `clockdiff` ported to request its raw socket and nice priority from `cap-grantd` instead of relying on file capabilities. |
| polkit policy/rules | `polkit/org.openSUSE.CapGrant.policy` defines the actions; `polkit/*.rules.example` shows how to pre-authorize specific programs. |
| systemd units | `systemd/cap-grantd.{service,socket}` for socket-activated startup. |

## Using it from your own code

Link against `libcap-grant` (a pkg-config file `libcap-grant.pc` is
installed) and include `<cap-grant.h>`:

```c
#include <cap-grant.h>

char *error = NULL;

/* Ask cap-grantd to open a raw ICMP socket for us. */
int fd = cap_grant_socket(AF_INET, SOCK_RAW, IPPROTO_ICMP, &error);
if (fd < 0) {
        fprintf(stderr, "cap_grant_socket: %s\n", error ? error : strerror(-fd));
        free(error);
        exit(1);
}
free(error);

/* Ask cap-grantd to raise our scheduling priority. */
int r = cap_grant_nice(-16, &error);
if (r < 0) {
        fprintf(stderr, "cap_grant_nice: %s\n", error ? error : strerror(-r));
        free(error);
        exit(1);
}
free(error);
```

Both functions return `0`/a non-negative fd on success or a negative
`-errno` on failure. Optionally they provide a human-readable message.

`cap_grant_nice()` takes a relative increment (like
[nice(2)](https://manpages.opensuse.org/nice.2) as argument) and asks the
daemon to adjust the caller's current priority by that amount.
`cap_grant_socket()` takes the same arguments as `socket(2)` and returns
a ready-to-use file descriptor passed back over the Varlink connection.

## Building

```sh
meson setup build
meson compile -C build
sudo meson install -C build
```

Requires `libsystemd` >= 257 (for `sd-varlink`), and optionally
`polkit-gobject-1` (used only to discover where to install the
polkit actions file; cap-grantd talks to polkitd over D-Bus
directly at runtime regardless).

## Admin configuration

### 1. Install and enable the daemon

`meson install` places:

- `cap-grantd` in `$libexecdir`,
- `cap-grantd.{service,socket}` under the systemd system unit directory,
- `org.openSUSE.CapGrant.policy` under the polkit actions directory.

Enable socket activation:

```sh
systemctl enable --now cap-grantd.socket
```

`cap-grantd` itself keeps `CAP_NET_RAW` and `CAP_SYS_NICE` in its
capability bounding set (see `CapabilityBoundingSet=` in
`systemd/cap-grantd.service`) and otherwise runs fully unprivileged
with `NoNewPrivileges=yes` — it never needs file capabilities or
setuid itself, it only ever hands out what's already in its own
bounding set.

### 2. Decide who is authorized

By default every action in `org.openSUSE.CapGrant.policy` requires
`auth_admin_keep`, i.e. any caller who isn't root is prompted for the
admin password via the usual polkit authentication agent. That's
appropriate for an interactive desktop session, but not for a
non-interactive tool like `clockdiff` invoked from a script or by a
regular user.

To let specific trusted binaries use specific actions without a
password prompt, install a polkit JavaScript rule. An example is
provided in `polkit/10-org.openSUSE.CapGrant-clockdiff.rules.example`,
which allows any local user to run `/usr/bin/clockdiff` with the
`setpriority` and `socket` actions:

```sh
cp polkit/10-org.openSUSE.CapGrant-clockdiff.rules.example \
   /etc/polkit-1/rules.d/10-org.openSUSE.CapGrant-clockdiff.rules
systemctl restart polkit
```

The rule matches on the `program` detail that `cap-grantd` attaches to
every `CheckAuthorization` call (the resolved `/proc/<pid>/exe` of the
caller, see `cg_polkit_check_async()` in
`src/cap-grantd-polkit.c`), so it only ever grants the action to the
exact binary path listed — not to anything else that happens to
request the same action. Add more entries to `allowedPrograms` /
`allowedActions` in the rule to trust additional tools, or write
narrower rules (e.g. restricted to a specific group) for tighter
control.

If polkit itself is not installed or not reachable, cap-grantd denies
all non-root requests by default (`CG_POLKIT_ABSENT_DENY`) rather than
silently granting them.

### 3. Point applications at the socket

Nothing else is required on the client side: `libcap-grant` always
connects to the socket created by`cap-grantd.socket`. Any local user
able to reach that socket and satisfying the polkit rules above can use it.
