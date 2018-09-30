/*
 * lxc: linux Container library
 *
 * Copyright © 2017 Canonical Ltd.
 *
 * Authors:
 * Christian Brauner <christian.brauner@ubuntu.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#define _GNU_SOURCE
#define __STDC_FORMAT_MACROS
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "lxctest.h"
#include "namespace.h"
#include "raw_syscalls.h"
#include "utils.h"

int main(int argc, char *argv[])
{
	int status;
	pid_t pid;
	int flags = 0;

	pid = lxc_raw_clone(CLONE_PARENT_SETTID);
	if (pid >= 0 || pid != -EINVAL) {
		lxc_error("%s\n", "Calling lxc_raw_clone(CLONE_PARENT_SETTID) "
				  "should not be possible");
		exit(EXIT_FAILURE);
	}

	pid = lxc_raw_clone(CLONE_CHILD_SETTID);
	if (pid >= 0 || pid != -EINVAL) {
		lxc_error("%s\n", "Calling lxc_raw_clone(CLONE_CHILD_SETTID) "
				  "should not be possible");
		exit(EXIT_FAILURE);
	}

	pid = lxc_raw_clone(CLONE_CHILD_CLEARTID);
	if (pid >= 0 || pid != -EINVAL) {
		lxc_error("%s\n", "Calling lxc_raw_clone(CLONE_CHILD_CLEARTID) "
				  "should not be possible");
		exit(EXIT_FAILURE);
	}

	pid = lxc_raw_clone(CLONE_SETTLS);
	if (pid >= 0 || pid != -EINVAL) {
		lxc_error("%s\n", "Calling lxc_raw_clone(CLONE_SETTLS) should "
				  "not be possible");
		exit(EXIT_FAILURE);
	}

	pid = lxc_raw_clone(CLONE_VM);
	if (pid >= 0 || pid != -EINVAL) {
		lxc_error("%s\n", "Calling lxc_raw_clone(CLONE_VM) should "
			  "not be possible");
		exit(EXIT_FAILURE);
	}

	pid = lxc_raw_clone(0);
	if (pid < 0) {
		lxc_error("%s\n", "Failed to call lxc_raw_clone(0)");
		exit(EXIT_FAILURE);
	}

	if (pid == 0) {
		lxc_error("%s\n", "Child will exit(EXIT_SUCCESS)");
		exit(EXIT_SUCCESS);
	}

	status = wait_for_pid(pid);
	if (status != 0) {
		lxc_error("%s\n", "Failed to retrieve correct exit status");
		exit(EXIT_FAILURE);
	}

	pid = lxc_raw_clone(0);
	if (pid < 0) {
		lxc_error("%s\n", "Failed to call lxc_raw_clone(0)");
		exit(EXIT_FAILURE);
	}

	if (pid == 0) {
		lxc_error("%s\n", "Child will exit(EXIT_FAILURE)");
		exit(EXIT_FAILURE);
	}

	status = wait_for_pid(pid);
	if (status == 0) {
		lxc_error("%s\n", "Failed to retrieve correct exit status");
		exit(EXIT_FAILURE);
	}

	flags |= CLONE_NEWUSER;
	if (cgns_supported())
		flags |= CLONE_NEWCGROUP;
	flags |= CLONE_NEWNS;
	flags |= CLONE_NEWIPC;
	flags |= CLONE_NEWNET;
	flags |= CLONE_NEWIPC;
	flags |= CLONE_NEWPID;
	flags |= CLONE_NEWUTS;

	pid = lxc_raw_clone(flags);
	if (pid < 0) {
		lxc_error("%s\n", "Failed to call lxc_raw_clone(CLONE_NEWUSER "
				  "| CLONE_NEWCGROUP | CLONE_NEWNS | "
				  "CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWIPC "
				  "| CLONE_NEWPID | CLONE_NEWUTS);");
		exit(EXIT_FAILURE);
	}

	if (pid == 0) {
		lxc_error("%s\n", "Child will exit(EXIT_SUCCESS)");
		exit(EXIT_SUCCESS);
	}

	status = wait_for_pid(pid);
	if (status != 0) {
		lxc_error("%s\n", "Failed to retrieve correct exit status");
		exit(EXIT_FAILURE);
	}

	pid = lxc_raw_clone(flags);
	if (pid < 0) {
		lxc_error("%s\n", "Failed to call lxc_raw_clone(CLONE_NEWUSER "
				  "| CLONE_NEWCGROUP | CLONE_NEWNS | "
				  "CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWIPC "
				  "| CLONE_NEWPID | CLONE_NEWUTS);");
		exit(EXIT_FAILURE);
	}


	if (pid == 0) {
		lxc_error("%s\n", "Child will exit(EXIT_FAILURE)");
		exit(EXIT_FAILURE);
	}

	status = wait_for_pid(pid);
	if (status == 0) {
		lxc_error("%s\n", "Failed to retrieve correct exit status");
		exit(EXIT_FAILURE);
	}

	pid = lxc_raw_clone(CLONE_VFORK);
	if (pid < 0) {
		lxc_error("%s\n", "Failed to call lxc_raw_clone(CLONE_VFORK);");
		exit(EXIT_FAILURE);
	}

	if (pid == 0) {
		lxc_error("%s\n", "Child will exit(EXIT_SUCCESS)");
		exit(EXIT_SUCCESS);
	}

	status = wait_for_pid(pid);
	if (status != 0) {
		lxc_error("%s\n", "Failed to retrieve correct exit status");
		exit(EXIT_FAILURE);
	}

	pid = lxc_raw_clone(CLONE_VFORK);
	if (pid < 0) {
		lxc_error("%s\n", "Failed to call lxc_raw_clone(CLONE_VFORK);");
		exit(EXIT_FAILURE);
	}

	if (pid == 0) {
		lxc_error("%s\n", "Child will exit(EXIT_FAILURE)");
		exit(EXIT_FAILURE);
	}

	status = wait_for_pid(pid);
	if (status == 0) {
		lxc_error("%s\n", "Failed to retrieve correct exit status");
		exit(EXIT_FAILURE);
	}

	pid = lxc_raw_clone(CLONE_FILES);
	if (pid < 0) {
		lxc_error("%s\n", "Failed to call lxc_raw_clone(CLONE_FILES);");
		exit(EXIT_FAILURE);
	}

	if (pid == 0) {
		lxc_error("%s\n", "Child will exit(EXIT_SUCCESS)");
		exit(EXIT_SUCCESS);
	}

	status = wait_for_pid(pid);
	if (status != 0) {
		lxc_error("%s\n", "Failed to retrieve correct exit status");
		exit(EXIT_FAILURE);
	}

	pid = lxc_raw_clone(CLONE_FILES);
	if (pid < 0) {
		lxc_error("%s\n", "Failed to call lxc_raw_clone(CLONE_FILES);");
		exit(EXIT_FAILURE);
	}

	if (pid == 0) {
		lxc_error("%s\n", "Child will exit(EXIT_FAILURE)");
		exit(EXIT_FAILURE);
	}

	status = wait_for_pid(pid);
	if (status == 0) {
		lxc_error("%s\n", "Failed to retrieve correct exit status");
		exit(EXIT_FAILURE);
	}

	lxc_debug("%s\n", "All lxc_raw_clone() tests successful");
	exit(EXIT_SUCCESS);
}
