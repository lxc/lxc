/*
 * Copyright © 2012 Serge Hallyn <serge.hallyn@ubuntu.com>.
 * Copyright © 2012 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
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
#include <alloca.h>
#include <stdio.h>
#include <sched.h>
#include <unistd.h>
#include <signal.h>
#include <sys/reboot.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "lxc/namespace.h"

#include <sched.h>
#include <linux/sched.h>
#include <linux/reboot.h>

int clone(int (*fn)(void *), void *child_stack, int flags, void *arg, ...);

static int do_reboot(void *arg)
{
	int *cmd = arg;

	if (reboot(*cmd))
		printf("failed to reboot(%d): %m\n", *cmd);
	return 0;
}

static int test_reboot(int cmd, int sig)
{
	long stack_size = 4096;
	void *stack = alloca(stack_size) + stack_size;
	int status;
	pid_t ret;

	ret = clone(do_reboot, stack, CLONE_NEWPID | SIGCHLD, &cmd);
	if (ret < 0) {
		printf("failed to clone: %m\n");
		return -1;
	}

	if (wait(&status) < 0) {
		printf("unexpected wait error: %m\n");
		return -1;
	}

	if (!WIFSIGNALED(status)) {
		if (sig != -1)
			printf("child process exited but was not signaled\n");
		return -1;
	}

	if (WTERMSIG(status) != sig) {
		printf("signal termination is not the one expected\n");
		return -1;
	}

	return 0;
}

static int have_reboot_patch(void)
{
	FILE *f = fopen("/proc/sys/kernel/ctrl-alt-del", "r");
	int ret;
	int v;

	if (!f)
		return 0;

	ret = fscanf(f, "%d", &v);
	fclose(f);
	if (ret != 1)
		return 0;
	ret = reboot(v ? LINUX_REBOOT_CMD_CAD_ON : LINUX_REBOOT_CMD_CAD_OFF);
	if (ret != -1)
		return 0;
	return 1;
}

int main(int argc, char *argv[])
{
	int status;

	if (getuid() != 0) {
		printf("Must run as root.\n");
		return 1;
	}

	status = have_reboot_patch();
	if (status != 0) {
		printf("Your kernel does not have the container reboot patch\n");
		return 1;
	}

	status = test_reboot(LINUX_REBOOT_CMD_CAD_ON, -1);
	if (status >= 0) {
		printf("reboot(LINUX_REBOOT_CMD_CAD_ON) should have failed\n");
		return 1;
	}
	printf("reboot(LINUX_REBOOT_CMD_CAD_ON) has failed as expected\n");

	status = test_reboot(LINUX_REBOOT_CMD_RESTART, SIGHUP);
	if (status < 0)
		return 1;
	printf("reboot(LINUX_REBOOT_CMD_RESTART) succeed\n");

	status = test_reboot(LINUX_REBOOT_CMD_RESTART2, SIGHUP);
	if (status < 0)
		return 1;
	printf("reboot(LINUX_REBOOT_CMD_RESTART2) succeed\n");

	status = test_reboot(LINUX_REBOOT_CMD_HALT, SIGINT);
	if (status < 0)
		return 1;
	printf("reboot(LINUX_REBOOT_CMD_HALT) succeed\n");

	status = test_reboot(LINUX_REBOOT_CMD_POWER_OFF, SIGINT);
	if (status < 0)
		return 1;
	printf("reboot(LINUX_REBOOT_CMD_POWERR_OFF) succeed\n");

	printf("All tests passed\n");
	return 0;
}
