/*
 * lxc: linux Container library
 *
 * Copyright © 2014-2015 Canonical Ltd.
 *
 * Authors:
 * Tycho Andersen <tycho.andersen@canonical.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
#ifndef __LXC_CRIU_H
#define __LXC_CRIU_H

#include <stdbool.h>

#include <lxc/lxccontainer.h>

bool __criu_pre_dump(struct lxc_container *c, struct migrate_opts *opts);
bool __criu_dump(struct lxc_container *c, struct migrate_opts *opts);
bool __criu_restore(struct lxc_container *c, struct migrate_opts *opts);

#endif
