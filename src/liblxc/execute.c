/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Daniel Lezcano <dlezcano at fr.ibm.com>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
#define _GNU_SOURCE
#include <stdio.h>
#undef _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <netinet/in.h>
#include <net/if.h>

#include <list.h>
#include <conf.h>
#include <log.h>
#include <lxc.h>
#include <lock.h>
#include <state.h>
#include <cgroup.h>
#include <namespace.h>
#include <utils.h>

LXC_TTY_HANDLER(SIGINT);
LXC_TTY_HANDLER(SIGQUIT);

int lxc_execute(const char *name, int argc, char *argv[], 
		lxc_callback_t preexec, void *data)
{
	char *init = NULL, *val = NULL, *vinit = "[vinit]";
	int fd, lock, sv[2], sync = 0, err = -1;
	pid_t pid;
	int clone_flags;

	lock = lxc_get_lock(name);
	if (!lock) {
		lxc_log_error("'%s' is busy", name);
		return -1;
	}

	if (lock < 0) {
		lxc_log_error("failed to acquire lock on '%s':%s",
			      name, strerror(-lock));
		return -1;
	}

	fcntl(lock, F_SETFD, FD_CLOEXEC);

	if (lxc_setstate(name, STARTING)) {
		lxc_log_error("failed to set state %s", state2str(STARTING));
		goto out;
	}

	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, sv)) {
		lxc_log_syserror("failed to create communication socketpair");
		goto err;
	}

	LXC_TTY_ADD_HANDLER(SIGINT);
	LXC_TTY_ADD_HANDLER(SIGQUIT);

	clone_flags = CLONE_NEWPID|CLONE_NEWIPC|CLONE_NEWNS;
	if (conf_has_utsname(name))
		clone_flags |= CLONE_NEWUTS;
	if (conf_has_network(name))
		clone_flags |= CLONE_NEWNET;

	pid = fork_ns(clone_flags);
	if (pid < 0) {
		lxc_log_syserror("failed to fork into a new namespace");
		goto err_fork_ns;
	}

	if (!pid) {

		pid = fork();
		if (pid < 0) {
			lxc_log_syserror("failed to fork");
			return 1;
		}

		if (!pid) {
			close(sv[1]);
			fcntl(sv[0], F_SETFD, FD_CLOEXEC);

			if (write(sv[0], &sync, sizeof(sync)) < 0) {
				lxc_log_syserror("failed to write socket");
				return 1;
			}

			if (read(sv[0], &sync, sizeof(sync)) < 0) {
				lxc_log_syserror("failed to read socket");
				return 1;
			}

			if (lxc_setup(name)) {
				lxc_log_error("failed to setup the container");
				goto error;
			}
			if (mount("proc", "/proc", "proc", 0, NULL)) {
				lxc_log_error("failed to mount '/proc'");
				goto error;
			}
			if (mount("sysfs", "/sys", "sysfs", 0, NULL)) {
				lxc_log_syserror("failed to mount '/sys'");
				/* continue: non fatal error until sysfs not per
				 namespace */
			}

			if (preexec)
				if (preexec(name, argc, argv, data)) {
					lxc_log_error("preexec callback has failed");
					return -1;
				}

			execvp(argv[0], argv);
		error:
			lxc_log_syserror("failed to exec %s", argv[0]);
			if (write(sv[0], &sync, sizeof(sync)) < 0)
				lxc_log_syserror("failed to write the socket");
			
			return 1;
		}

		setsid();
		close(0);
		close(1);
		close(2);

		if (prctl(PR_SET_NAME, vinit, 0, 0, 0))
			lxc_log_syserror("failed to set process name");

		close(sv[0]);
		close(sv[1]);

		for (;;) {
			int status;
			if (wait(&status) < 0) {
				if (errno == ECHILD)
					return 0;
				if (errno == EINTR)
					continue;
				lxc_log_syserror("failed to wait child");
				return 1;
			}
		}
	}

	close(sv[0]);
	
	if (read(sv[1], &sync, sizeof(sync)) < 0) {
		lxc_log_syserror("failed to read the socket");
		goto err_pipe_read;
	}

	if (clone_flags & CLONE_NEWNET && conf_create_network(name, pid)) {
		lxc_log_error("failed to create the configured network");
		goto err_create_network;
	}

	if (write(sv[1], &sync, sizeof(sync)) < 0) {
		lxc_log_syserror("failed to write the socket");
		goto err_pipe_write;
	}

	err = read(sv[1], &sync, sizeof(sync));
	if (err < 0) {
		lxc_log_error("failed to read the socket");
		goto err_pipe_read2;
	}

	if (err > 0) {
		lxc_log_error("something went wrong with %d", pid);
		/* TODO : check status etc ... */
		waitpid(pid, NULL, 0);
		goto err_child_failed;
	}

	asprintf(&init, LXCPATH "/%s/init", name);
	fd = open(init, O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR);
	if (fd < 0) {
		lxc_log_syserror("failed to open %s", init);
		goto err_open;
	}

	asprintf(&val, "%d", pid);
	if (write(fd, val, strlen(val)) < 0) {
		lxc_log_syserror("failed to write init pid");
		goto err_write;
	}

	if (lxc_link_nsgroup(name, pid))
		lxc_log_warning("cgroupfs not found: cgroup disabled");

	if (lxc_setstate(name, RUNNING)) {
		lxc_log_error("failed to set state to %s", state2str(RUNNING));
		goto err_state_failed;
	}

wait_again:
	if (waitpid(pid, NULL, 0) < 0) {
		if (errno == EINTR) 
			goto wait_again;
		lxc_log_syserror("failed to wait the pid %d", pid);
		goto err_waitpid_failed;
	}

	if (lxc_setstate(name, STOPPING))
		lxc_log_error("failed to set state %s", state2str(STOPPING));

	if (clone_flags & CLONE_NEWNET && conf_destroy_network(name))
		lxc_log_error("failed to destroy the network");

	err = 0;
out:
	if (lxc_setstate(name, STOPPED))
		lxc_log_error("failed to set state %s", state2str(STOPPED));

	lxc_unlink_nsgroup(name);
	unlink(init);
	free(init);
	free(val);
	lxc_put_lock(lock);

	return err;

err_write:
	close(fd);

err_state_failed:
err_child_failed:
err_pipe_read2:
err_pipe_write:
	conf_destroy_network(name);
err_create_network:
err_pipe_read:
err_open:
err_waitpid_failed:
	if (lxc_setstate(name, ABORTING))
		lxc_log_error("failed to set state %s", state2str(STOPPED));

	kill(pid, SIGKILL);
err_fork_ns:
	LXC_TTY_DEL_HANDLER(SIGQUIT);
	LXC_TTY_DEL_HANDLER(SIGINT);
	close(sv[0]);
	close(sv[1]);
err:
	goto out;
}
