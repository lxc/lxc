/*
 * lxc: linux Container library
 *
 * SPDX-License-Identifier: LGPL-2.1+
 *
 */

#include "config.h"

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

#include "cgroups/cgroup_utils.h"
#include "lxctest.h"
#include "namespace.h"
#include "process_utils.h"
#include "utils.h"

int main(int argc, char *argv[])
{
	int status;
	pid_t pid;
	int flags = 0;

	pid = lxc_raw_clone(CLONE_PARENT_SETTID, NULL);
	if (pid >= 0 || pid != -EINVAL) {
		lxc_error("%s\n", "Calling lxc_raw_clone(CLONE_PARENT_SETTID) "
				  "should not be possible");
		exit(EXIT_FAILURE);
	}

	pid = lxc_raw_clone(CLONE_CHILD_SETTID, NULL);
	if (pid >= 0 || pid != -EINVAL) {
		lxc_error("%s\n", "Calling lxc_raw_clone(CLONE_CHILD_SETTID) "
				  "should not be possible");
		exit(EXIT_FAILURE);
	}

	pid = lxc_raw_clone(CLONE_CHILD_CLEARTID, NULL);
	if (pid >= 0 || pid != -EINVAL) {
		lxc_error("%s\n", "Calling lxc_raw_clone(CLONE_CHILD_CLEARTID) "
				  "should not be possible");
		exit(EXIT_FAILURE);
	}

	pid = lxc_raw_clone(CLONE_SETTLS, NULL);
	if (pid >= 0 || pid != -EINVAL) {
		lxc_error("%s\n", "Calling lxc_raw_clone(CLONE_SETTLS) should "
				  "not be possible");
		exit(EXIT_FAILURE);
	}

	pid = lxc_raw_clone(CLONE_VM, NULL);
	if (pid >= 0 || pid != -EINVAL) {
		lxc_error("%s\n", "Calling lxc_raw_clone(CLONE_VM) should "
			  "not be possible");
		exit(EXIT_FAILURE);
	}

	pid = lxc_raw_clone(0, NULL);
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

	pid = lxc_raw_clone(0, NULL);
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

	pid = lxc_raw_clone(flags, NULL);
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

	pid = lxc_raw_clone(flags, NULL);
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

	pid = lxc_raw_clone(CLONE_VFORK, NULL);
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

	pid = lxc_raw_clone(CLONE_VFORK, NULL);
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

	pid = lxc_raw_clone(CLONE_FILES, NULL);
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

	pid = lxc_raw_clone(CLONE_FILES, NULL);
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
