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
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <mntent.h>
#include <sys/param.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <net/if.h>

#include <lxc.h>
#include <namespace.h>
#include <network.h>
#include <state.h>
#include <cgroup.h>
#include <utils.h>
#include <list.h>
#include <conf.h>
#include <log.h>
#include <lock.h>

LXC_TTY_HANDLER(SIGINT);
LXC_TTY_HANDLER(SIGQUIT);

int lxc_start(const char *name, int argc, char *argv[], 
	      lxc_callback_t prestart, void *data)
{
	char *init = NULL, *val = NULL;
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

	/* Begin the set the state to STARTING*/
	if (lxc_setstate(name, STARTING)) {
		lxc_log_error("failed to set state %s", state2str(STARTING));
		goto out;
	}

	/* Synchro socketpair */
	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, sv)) {
		lxc_log_syserror("failed to create communication socketpair");
		goto err;
	}

	/* Avoid signals from terminal */
	LXC_TTY_ADD_HANDLER(SIGINT);
	LXC_TTY_ADD_HANDLER(SIGQUIT);

	clone_flags = CLONE_NEWPID|CLONE_NEWIPC;
	if (conf_has_fstab(name))
		clone_flags |= CLONE_NEWNS;
	if (conf_has_utsname(name))
		clone_flags |= CLONE_NEWUTS;
	if (conf_has_network(name))
		clone_flags |= CLONE_NEWNET;

	/* Create a process in a new set of namespaces */
	pid = fork_ns(clone_flags);
	if (pid < 0) {
		lxc_log_syserror("failed to fork into a new namespace");
		goto err_fork_ns;
	}

	if (!pid) {

		close(sv[1]);

		/* Be sure we don't inherit this after the exec */
		fcntl(sv[0], F_SETFD, FD_CLOEXEC);
		
		/* Tell our father he can begin to configure the container */
		if (write(sv[0], &sync, sizeof(sync)) < 0) {
			lxc_log_syserror("failed to write socket");
			return 1;
		}

		/* Wait for the father to finish the configuration */
		if (read(sv[0], &sync, sizeof(sync)) < 0) {
			lxc_log_syserror("failed to read socket");
			return 1;
		}

		/* Setup the container, ip, names, utsname, ... */
		if (lxc_setup(name)) {
			lxc_log_error("failed to setup the container");
			if (write(sv[0], &sync, sizeof(sync)) < 0)
				lxc_log_syserror("failed to write the socket");
			return -1;
		}

		/* If a callback has been passed, call it before doing exec */
		if (prestart)
			if (prestart(name, argc, argv, data)) {
				lxc_log_error("prestart callback has failed");
				return -1;
			}

		execvp(argv[0], argv);
		lxc_log_syserror("failed to exec %s", argv[0]);

		/* If the exec fails, tell that to our father */
		if (write(sv[0], &sync, sizeof(sync)) < 0)
			lxc_log_syserror("failed to write the socket");
		
		return 1;
	}

	close(sv[0]);
	
	/* Wait for the child to be ready */
	if (read(sv[1], &sync, sizeof(sync)) < 0) {
		lxc_log_syserror("failed to read the socket");
		goto err_pipe_read;
	}

	/* Create the network configuration */
	if (clone_flags & CLONE_NEWNET && conf_create_network(name, pid)) {
		lxc_log_error("failed to create the configured network");
		goto err_create_network;
	}

	/* Tell the child to continue its initialization */
	if (write(sv[1], &sync, sizeof(sync)) < 0) {
		lxc_log_syserror("failed to write the socket");
		goto err_pipe_write;
	}

	/* Wait for the child to exec or returning an error */
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

	asprintf(&val, "%d\n", pid);
	asprintf(&init, LXCPATH "/%s/init", name);
	fd = open(init, O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR);
	if (fd < 0) {
		lxc_log_syserror("failed to open '%s'", init);
		goto err_write;
	}
	
	if (write(fd, val, strlen(val)) < 0) {
		lxc_log_syserror("failed to write the init pid");
		goto err_write;
	}

	close(fd);

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
	if (clone_flags & CLONE_NEWNET)
		conf_destroy_network(name);
err_create_network:
err_pipe_read:
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
