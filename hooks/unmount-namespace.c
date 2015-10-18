/*
 * Copyright © 2015 Wolfgang Bumiller <w.bumiller@proxmox.com>.
 * Copyright © 2015 Proxmox Server Solutions GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * --
 *
 * This stop-hook unmounts everything in the container's namespace, and thereby
 * waits for all calls commands to finish. This is useful when one needs to be
 * sure that network filesystems are finished unmounting in the namespace
 * before continuing with other tasks. Without this hook the cleanup of mounts
 * is done by the kernel in the background after all the references to the
 * namespaces are gone.
 */

#define _GNU_SOURCE    /* setns */
#include <stdio.h>     /* fdopen, getmntent, endmntent */
#include <stdlib.h>    /* malloc, qsort */
#include <unistd.h>    /* close */
#include <string.h>    /* strcmp, strncmp, strdup, strerror */
#include <sched.h>     /* setns */
#include <sys/mount.h> /* umount2 */
#include <sys/types.h> /* openat, open */
#include <sys/stat.h>  /* openat, open */
#include <fcntl.h>     /* openat, open */
#include <errno.h>     /* errno */

#include <../src/config.h>

#if IS_BIONIC
#include <../src/include/lxcmntent.h>
#else
#include <mntent.h>
#endif

#ifndef O_PATH
#define O_PATH      010000000
#endif

/* Define setns() if missing from the C library */
#ifndef HAVE_SETNS
static inline int setns(int fd, int nstype)
{
#ifdef __NR_setns
	return syscall(__NR_setns, fd, nstype);
#elif defined(__NR_set_ns)
	return syscall(__NR_set_ns, fd, nstype);
#else
	errno = ENOSYS;
	return -1;
#endif
}
#endif

struct mount {
	char *src; /* currently not used */
	char *dst;
	char *fs; /* currently not used */
};

static void mount_free(struct mount *mnt) {
	free(mnt->src);
	free(mnt->dst);
	free(mnt->fs);
}

static int mount_cmp_dst(const void *a_, const void *b_) {
	struct mount *a = (struct mount*)a_;
	struct mount *b = (struct mount*)b_;
	return strcmp(b->dst, a->dst); /* swapped order */
}

/* Unmounting /dev/pts fails, and  so /dev also fails, but /dev is not what
 * we're interested in. (There might also still be /dev/cgroup mounts).
 */
static int mount_should_error(const struct mount *mnt) {
	const char *dst = mnt->dst;
	return !(strncmp(dst, "/dev", 4) == 0 && (dst[4] == 0 || dst[4] == '/'));
}

/* Read mounts from 'self/mounts' relative to a directory filedescriptor.
 * Before entering the container we open a handle to /proc on the host as we
 * need to access /proc/self/mounts and the container's /proc doesn't contain
 * our /self. We then use openat(2) to avoid having to mount a temporary /proc.
 */
static int read_mounts(int procfd, struct mount **mp, size_t *countp) {
	int fd;
	struct mntent *ent;
	FILE *mf;
	size_t capacity = 32;
	size_t count = 0;
	struct mount *mounts = (struct mount*)malloc(capacity * sizeof(*mounts));

	if (!mounts) {
		errno = ENOMEM;
		return 0;
	}

	*mp = NULL;
	*countp = 0;

	fd = openat(procfd, "self/mounts", O_RDONLY);
	if (fd < 0) {
		free(mounts);
		return 0;
	}

	mf = fdopen(fd, "r");
	if (!mf) {
		int error = errno;
		close(fd);
		errno = error;
		free(mounts);
		return 0;
	}
	while ((ent = getmntent(mf))) {
		struct mount *new;
		if (count == capacity) {
			capacity *= 2;
			new = (struct mount*)realloc(mounts, capacity * sizeof(*mounts));
			if (!new)
				goto out_alloc_entry;
			mounts = new;
		}
		new = &mounts[count++];
		new->src = strdup(ent->mnt_fsname);
		new->dst = strdup(ent->mnt_dir);
		new->fs  = strdup(ent->mnt_type);
		if (!new->src || !new->dst || !new->fs)
			goto out_alloc_entry;
	}
	endmntent(mf);

	*mp = mounts;
	*countp = count;

	return 1;

out_alloc_entry:
	endmntent(mf);
	while (count--) {
		free(mounts[count].src);
		free(mounts[count].dst);
		free(mounts[count].fs);
	}
	free(mounts);
	errno = ENOMEM;
	return 0;
}

int main(int argc, char **argv) {
	int i, procfd, ctmntfd;
	struct mount *mounts;
	size_t zi, count = 0;
	const char *mntns = NULL;

	if (argc < 4 || strcmp(argv[2], "lxc") != 0) {
		fprintf(stderr, "%s: usage error, expected LXC hook arguments\n", argv[0]);
		return 2;
	}

	if (strcmp(argv[3], "stop") != 0)
		return 0;

	for (i = 4; i != argc; ++i) {
		if (!strncmp(argv[i], "mnt:", 4)) {
			mntns = argv[i] + 4;
			break;
		}
	}

	if (!mntns) {
		fprintf(stderr, "%s: no mount namespace provided\n", argv[0]);
		return 3;
	}

	/* Open a handle to /proc on the host as we need to access /proc/self/mounts
	 * and the container's /proc doesn't contain our /self. See read_mounts().
	 */
	procfd = open("/proc", O_RDONLY | O_DIRECTORY | O_PATH);
	if (procfd < 0) {
		fprintf(stderr, "%s: failed to open /proc: %s\n", argv[0], strerror(errno));
		return 4;
	}

	/* Open the mount namespace and enter it. */
	ctmntfd = open(mntns, O_RDONLY);
	if (ctmntfd < 0) {
		fprintf(stderr, "%s: failed to open mount namespace: %s\n",
			argv[0], strerror(errno));
		close(procfd);
		return 5;
	}

	if (setns(ctmntfd, CLONE_NEWNS) != 0) {
		fprintf(stderr, "%s: failed to attach to namespace: %s\n",
			argv[0], strerror(errno));
		close(ctmntfd);
		close(procfd);
		return 6;
	}
	close(ctmntfd);

	/* Now read [[procfd]]/self/mounts */
	if (!read_mounts(procfd, &mounts, &count)) {
		fprintf(stderr, "%s: failed to read mountpoints: %s\n",
			argv[0], strerror(errno));
		close(procfd);
		return 7;
	}
	close(procfd);

	/* Just sort to get a sane unmount-order... */
	qsort(mounts, count, sizeof(*mounts), &mount_cmp_dst);

	for (zi = 0; zi != count; ++zi) {
		/* fprintf(stderr, "Unmount: %s\n", mounts[zi].dst); */
		if (umount2(mounts[zi].dst, 0) != 0) {
			int error = errno;
			if (mount_should_error(&mounts[zi])) {
				fprintf(stderr, "%s: failed to unmount %s: %s\n",
					argv[0], mounts[zi].dst, strerror(error));
			}
		}
		mount_free(&mounts[zi]);
	}
	free(mounts);

	return 0;
}
