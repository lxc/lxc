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

// We require either the criu major/minor version, or the criu GITID if criu
// was built from git.
#define CRIU_VERSION 		"1.6"

#define CRIU_GITID_VERSION	"1.5"
#define CRIU_GITID_PATCHLEVEL	133

struct criu_opts {
	/* The type of criu invocation, one of "dump" or "restore" */
	char *action;

	/* The directory to pass to criu */
	char *directory;

	/* The container to dump */
	struct lxc_container *c;

	/* Enable criu verbose mode? */
	bool verbose;

	/* dump: stop the container or not after dumping? */
	bool stop;

	/* restore: the file to write the init process' pid into */
	char *pidfile;
	const char *cgroup_path;
};

void exec_criu(struct criu_opts *opts);

/* Check and make sure the container has a configuration that we know CRIU can
 * dump. */
bool criu_ok(struct lxc_container *c);

// do_restore never returns, the calling process is used as the
// monitor process. do_restore calls exit() if it fails.
void do_restore(struct lxc_container *c, int pipe, char *directory, bool verbose);

#endif
