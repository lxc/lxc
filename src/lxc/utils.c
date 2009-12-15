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
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <dirent.h>
#include <fcntl.h>

#include "list.h"
#include "log.h"

lxc_log_define(lxc_utils, lxc);

int lxc_copy_file(const char *srcfile, const char *dstfile)
{
	void *srcaddr = NULL, *dstaddr;
	struct stat stat;
	int srcfd, dstfd, ret = -1;
	char c = '\0';

	dstfd = open(dstfile, O_CREAT | O_EXCL | O_RDWR, 0600);
	if (dstfd < 0) {
		SYSERROR("failed to creat '%s'", dstfile);
		goto out;
	}

	srcfd = open(srcfile, O_RDONLY);
	if (srcfd < 0) {
		SYSERROR("failed to open '%s'", srcfile);
		goto err;
	}

	if (fstat(srcfd, &stat)) {
		SYSERROR("failed to stat '%s'", srcfile);
		goto err;
	}

	if (!stat.st_size) {
		INFO("copy '%s' which is an empty file", srcfile);
		ret = 0;
		goto out_close;
	}

	if (lseek(dstfd, stat.st_size - 1, SEEK_SET) < 0) {
		SYSERROR("failed to seek dest file '%s'", dstfile);
		goto err;
	}

	/* fixup length */
	if (write(dstfd, &c, 1) < 0) {
		SYSERROR("failed to write to '%s'", dstfile);
		goto err;
	}

	srcaddr = mmap(NULL, stat.st_size, PROT_READ, MAP_SHARED, srcfd, 0L);
	if (srcaddr == MAP_FAILED) {
		SYSERROR("failed to mmap '%s'", srcfile);
		goto err;
	}

	dstaddr = mmap(NULL, stat.st_size, PROT_WRITE, MAP_SHARED, dstfd, 0L);
	if (dstaddr == MAP_FAILED) {
		SYSERROR("failed to mmap '%s'", dstfile);
		goto err;
	}

	ret = 0;

	memcpy(dstaddr, srcaddr, stat.st_size);

	munmap(dstaddr, stat.st_size);
out_mmap:
	if (srcaddr)
		munmap(srcaddr, stat.st_size);
out_close:
	close(dstfd);
	close(srcfd);
out:
	return ret;
err:
	unlink(dstfile);
	goto out_mmap;
}

struct lxc_fd_entry {
	int fd;
	struct lxc_list list;
};

struct lxc_list lxc_fd_list;

static int fd_list_add(int fd)
{
	struct lxc_fd_entry *entry;

	entry = malloc(sizeof(struct lxc_fd_entry));
	if (!entry) {
		SYSERROR("malloc");
		return -1;
	}

	entry->fd = fd;
	entry->list.elem = entry;
	lxc_list_add(&lxc_fd_list, &entry->list);

	return 0;
}

static void fd_list_del(struct lxc_fd_entry *entry)
{
	lxc_list_del(&entry->list);
	free(entry);
}

static void __attribute__((constructor)) __lxc_fd_collect_inherited(void)
{
	struct dirent dirent, *direntp;
	int fd, fddir;
	DIR *dir;

	lxc_list_init(&lxc_fd_list);

	dir = opendir("/proc/self/fd");
	if (!dir) {
		WARN("failed to open directory: %s", strerror(errno));
		return;
	}

	fddir = dirfd(dir);

	while (!readdir_r(dir, &dirent, &direntp)) {

		if (!direntp)
			break;

		if (!strcmp(direntp->d_name, "."))
			continue;

		if (!strcmp(direntp->d_name, ".."))
			continue;

		fd = atoi(direntp->d_name);

		if (fd == fddir)
			continue;

		if (fd_list_add(fd))
			WARN("failed to add fd '%d' to the list", fd);
	}

	if (closedir(dir))
		WARN("failed to close directory");
}

int lxc_close_inherited_fd(int fd)
{
	struct lxc_fd_entry *entry;
	struct lxc_list *iterator;

	lxc_list_for_each(iterator, &lxc_fd_list) {

		entry = iterator->elem;

		if (entry->fd != fd)
			continue;

		fd_list_del(entry);

		break;
	}

	DEBUG("closing fd '%d'", fd);

	return close(fd);
}

int lxc_close_all_inherited_fd(void)
{
	struct lxc_fd_entry *entry;
	struct lxc_list *iterator;

again:
	lxc_list_for_each(iterator, &lxc_fd_list) {

		entry = iterator->elem;

		/* do not close the stderr fd to keep open default
		 * error reporting path.
		 */
		if (entry->fd == 2 && isatty(entry->fd)) {
			fd_list_del(entry);
			continue;
		}

		DEBUG("closing fd '%d'", entry->fd);

		if (close(entry->fd))
			WARN("failed to close fd '%d': %s", entry->fd,
			     strerror(errno));

		fd_list_del(entry);
		goto again;
	}

	DEBUG("closed all inherited file descriptors");

	return 0;
}

static int mount_fs(const char *source, const char *target, const char *type)
{
	/* the umount may fail */
	if (umount(target))
		WARN("failed to unmount %s : %s", target, strerror(errno));

	if (mount(source, target, type, 0, NULL)) {
		ERROR("failed to mount %s : %s", target, strerror(errno));
		return -1;
	}

	DEBUG("'%s' mounted on '%s'", source, target);

	return 0;
}

extern int lxc_setup_fs(void)
{
	if (mount_fs("proc", "/proc", "proc"))
		return -1;

	if (mount_fs("shmfs", "/dev/shm", "tmpfs"))
		return -1;

	/* If we were able to mount /dev/shm, then /dev exists */
	if (access("/dev/mqueue", F_OK) && mkdir("/dev/mqueue", 0666)) {
		SYSERROR("failed to create '/dev/mqueue'");
		return -1;
	}

	if (mount_fs("mqueue", "/dev/mqueue", "mqueue"))
		return -1;

	return 0;
}

/* borrowed from iproute2 */
extern int get_u16(ushort *val, const char *arg, int base)
{
	unsigned long res;
	char *ptr;

	if (!arg || !*arg)
		return -1;

	res = strtoul(arg, &ptr, base);
	if (!ptr || ptr == arg || *ptr || res > 0xFFFF)
		return -1;

	*val = res;

	return 0;
}

