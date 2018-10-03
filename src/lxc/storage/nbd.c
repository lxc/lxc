/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Daniel Lezcano <daniel.lezcano at free.fr>
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/wait.h>

#include "config.h"
#include "log.h"
#include "nbd.h"
#include "storage.h"
#include "storage_utils.h"
#include "syscall_wrappers.h"
#include "utils.h"

#ifndef HAVE_STRLCPY
#include "include/strlcpy.h"
#endif

lxc_log_define(nbd, lxc);

struct nbd_attach_data {
	const char *nbd;
	const char *path;
};

static int do_attach_nbd(void *d);
static bool clone_attach_nbd(const char *nbd, const char *path);
static bool nbd_busy(int idx);
static void nbd_detach(const char *path);
static int nbd_get_partition(const char *src);
static bool wait_for_partition(const char *path);

bool attach_nbd(char *src, struct lxc_conf *conf)
{
	char *orig, *p, path[50];
	int i = 0;
	size_t len;

	len = strlen(src);
	orig = alloca(len + 1);
	(void)strlcpy(orig, src, len + 1);

	/* if path is followed by a partition, drop that for now */
	p = strchr(orig, ':');
	if (p)
		*p = '\0';

	while (1) {
		sprintf(path, "/dev/nbd%d", i);

		if (!file_exists(path))
			return false;

		if (nbd_busy(i)) {
			i++;
			continue;
		}

		if (!clone_attach_nbd(path, orig))
			return false;

		conf->nbd_idx = i;
		return true;
	}
}

void detach_nbd_idx(int idx)
{
	int ret;
	char path[50];

	ret = snprintf(path, 50, "/dev/nbd%d", idx);
	if (ret < 0 || ret >= 50)
		return;

	nbd_detach(path);
}

int nbd_clonepaths(struct lxc_storage *orig, struct lxc_storage *new,
		   const char *oldname, const char *cname, const char *oldpath,
		   const char *lxcpath, int snap, uint64_t newsize,
		   struct lxc_conf *conf)
{
	return -ENOSYS;
}

int nbd_create(struct lxc_storage *bdev, const char *dest, const char *n,
	       struct bdev_specs *specs)
{
	return -ENOSYS;
}

int nbd_destroy(struct lxc_storage *orig)
{
	return -ENOSYS;
}

bool nbd_detect(const char *path)
{
	if (!strncmp(path, "nbd:", 4))
		return true;

	return false;
}

int nbd_mount(struct lxc_storage *bdev)
{
	int ret = -1, partition;
	const char *src;
	char path[50];

	if (strcmp(bdev->type, "nbd"))
		return -22;

	if (!bdev->src || !bdev->dest)
		return -22;

	/* nbd_idx should have been copied by bdev_init from the lxc_conf */
	if (bdev->nbd_idx < 0)
		return -22;

	src = lxc_storage_get_path(bdev->src, bdev->type);
	partition = nbd_get_partition(src);
	if (partition)
		ret = snprintf(path, 50, "/dev/nbd%dp%d", bdev->nbd_idx,
				partition);
	else
		ret = snprintf(path, 50, "/dev/nbd%d", bdev->nbd_idx);
	if (ret < 0 || ret >= 50) {
		ERROR("Error setting up nbd device path");
		return ret;
	}

	/* It might take awhile for the partition files to show up */
	if (partition)
		if (!wait_for_partition(path))
			return -2;

	ret = mount_unknown_fs(path, bdev->dest, bdev->mntopts);
	if (ret < 0)
		ERROR("Error mounting %s", bdev->src);

	return ret;
}

int nbd_umount(struct lxc_storage *bdev)
{
	if (strcmp(bdev->type, "nbd"))
		return -22;

	if (!bdev->src || !bdev->dest)
		return -22;

	return umount(bdev->dest);
}

bool requires_nbd(const char *path)
{
	if (strncmp(path, "nbd:", 4) == 0)
		return true;

	return false;
}

static int do_attach_nbd(void *d)
{
	struct nbd_attach_data *data = d;
	const char *nbd, *path;
	pid_t pid;
	sigset_t mask;
	int sfd;
	ssize_t s;
	struct signalfd_siginfo fdsi;

	sigemptyset(&mask);
	sigaddset(&mask, SIGHUP);
	sigaddset(&mask, SIGCHLD);

	nbd = data->nbd;
	path = data->path;

	if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
		SYSERROR("Error blocking signals for nbd watcher");
		exit(1);
	}

	sfd = signalfd(-1, &mask, 0);
	if (sfd == -1) {
		SYSERROR("Error opening signalfd for nbd task");
		exit(1);
	}

	if (prctl(PR_SET_PDEATHSIG, prctl_arg(SIGHUP), prctl_arg(0),
		  prctl_arg(0), prctl_arg(0)) < 0)
		SYSERROR("Error setting parent death signal for nbd watcher");

	pid = fork();
	if (pid) {
		for (;;) {
			s = read(sfd, &fdsi, sizeof(struct signalfd_siginfo));
			if (s != sizeof(struct signalfd_siginfo))
				SYSERROR("Error reading from signalfd");

			if (fdsi.ssi_signo == SIGHUP) {
				/* container has exited */
				nbd_detach(nbd);
				exit(0);
			} else if (fdsi.ssi_signo == SIGCHLD) {
				int status;

				/* If qemu-nbd fails, or is killed by a signal,
				 * then exit */
				while (waitpid(-1, &status, WNOHANG) > 0) {
					if ((WIFEXITED(status) && WEXITSTATUS(status) != 0) ||
							WIFSIGNALED(status)) {
						nbd_detach(nbd);
						exit(1);
					}
				}
			}
		}
	}

	close(sfd);

	if (sigprocmask(SIG_UNBLOCK, &mask, NULL) == -1)
		WARN("Warning: unblocking signals for nbd watcher");

	execlp("qemu-nbd", "qemu-nbd", "-c", nbd, path, (char *)NULL);
	SYSERROR("Error executing qemu-nbd");
	_exit(1);
}

static bool clone_attach_nbd(const char *nbd, const char *path)
{
	pid_t pid;
	struct nbd_attach_data data;

	data.nbd = nbd;
	data.path = path;

	pid = lxc_clone(do_attach_nbd, &data, CLONE_NEWPID);
	if (pid < 0)
		return false;

	return true;
}

static bool nbd_busy(int idx)
{
	char path[100];
	int ret;

	ret = snprintf(path, 100, "/sys/block/nbd%d/pid", idx);
	if (ret < 0 || ret >= 100)
		return true;

	return file_exists(path);
}

static void nbd_detach(const char *path)
{
	int ret;
	pid_t pid = fork();

	if (pid < 0) {
		SYSERROR("Error forking to detach nbd");
		return;
	}

	if (pid) {
		ret = wait_for_pid(pid);
		if (ret < 0)
			ERROR("nbd disconnect returned an error");
		return;
	}

	execlp("qemu-nbd", "qemu-nbd", "-d", path, (char *)NULL);
	SYSERROR("Error executing qemu-nbd");
	_exit(1);
}

/*
 * Pick the partition # off the end of a nbd:file:p
 * description.  Return 1-9 for the partition id, or 0
 * for no partition.
 */
static int nbd_get_partition(const char *src)
{
	char *p = strchr(src, ':');
	if (!p)
		return 0;

	p = strchr(p+1, ':');
	if (!p)
		return 0;

	p++;

	if (*p < '1' || *p > '9')
		return 0;

	return *p - '0';
}

static bool wait_for_partition(const char *path)
{
	int count = 0;

	while (count < 5) {
		if (file_exists(path))
			return true;

		sleep(1);
		count++;
	}

	ERROR("Device %s did not show up after 5 seconds", path);
	return false;
}
