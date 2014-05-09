/*
 * lxc: linux Container library
 *
 * (C) Copyright Canonical, Inc. 2012
 *
 * Authors:
 * Serge Hallyn <serge.hallyn@canonical.com>
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

#ifndef __LXC_LXCSECCOMP_H
#define __LXC_LXCSECCOMP_H

#include "conf.h"

#ifdef HAVE_SECCOMP
int lxc_seccomp_load(struct lxc_conf *conf);
int lxc_read_seccomp_config(struct lxc_conf *conf);
void lxc_seccomp_free(struct lxc_conf *conf);
#else
static inline int lxc_seccomp_load(struct lxc_conf *conf) {
	return 0;
}

static inline int lxc_read_seccomp_config(struct lxc_conf *conf) {
	return 0;
}

static inline void lxc_seccomp_free(struct lxc_conf *conf) {
	if (conf->seccomp) {
		free(conf->seccomp);
		conf->seccomp = NULL;
	}
}
#endif

#endif
