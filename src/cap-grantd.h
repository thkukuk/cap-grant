//SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <systemd/sd-bus.h>
#include <systemd/sd-event.h>

typedef struct CGPolkitQuery CGPolkitQuery;

typedef struct {
  sd_event *loop;
  sd_bus *polkit_bus;             /* lazily opened system bus connection, used only for polkit checks */
  CGPolkitQuery *polkit_queries;  /* pending polkit checks, keyed by sd_varlink* peer link */
} CG_CTX;
