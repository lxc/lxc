/*
 * lxc: linux Container library
 *
 * Copyright © 2016 Canonical Ltd.
 *
 * Authors:
 * Christian Brauner <christian.brauner@mailbox.org>
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
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "lxctest.h"
#include "utils.h"

void test_lxc_deslashify(void)
{
	char *s = "/A///B//C/D/E/";
	char *t;

	t = lxc_deslashify(s);
	if (!t)
		exit(EXIT_FAILURE);
	lxc_test_assert_abort(strcmp(t, "/A/B/C/D/E") == 0);
	free(t);

	s = "/A";

	t = lxc_deslashify(s);
	if (!t)
		exit(EXIT_FAILURE);
	lxc_test_assert_abort(strcmp(t, "/A") == 0);
	free(t);

	s = "";
	t = lxc_deslashify(s);
	if (!t)
		exit(EXIT_FAILURE);
	lxc_test_assert_abort(strcmp(t, "") == 0);
	free(t);

	s = "//";

	t = lxc_deslashify(s);
	if (!t)
		exit(EXIT_FAILURE);
	lxc_test_assert_abort(strcmp(t, "/") == 0);
	free(t);
}

/* /proc/int_as_str/ns/mnt\0 = (5 + 21 + 7 + 1) */
#define __MNTNS_LEN (5 + (LXC_NUMSTRLEN64) + 7 + 1)
void test_detect_ramfs_rootfs(void)
{
	size_t i;
	int ret;
	int fret = EXIT_FAILURE;
	char path[__MNTNS_LEN];
	int init_ns = -1;
	char tmpf1[] = "lxc-test-utils-XXXXXX";
	char tmpf2[] = "lxc-test-utils-XXXXXX";
	int fd1 = -1, fd2 = -1;
	FILE *fp1 = NULL, *fp2 = NULL;
	char *mountinfo[] = {
		"18 24 0:17 / /sys rw,nosuid,nodev,noexec,relatime shared:7 - sysfs sysfs rw",
		"19 24 0:4 / /proc rw,nosuid,nodev,noexec,relatime shared:13 - proc proc rw",
		"20 24 0:6 / /dev rw,nosuid,relatime shared:2 - devtmpfs udev rw,size=4019884k,nr_inodes=1004971,mode=755",
		"21 20 0:14 / /dev/pts rw,nosuid,noexec,relatime shared:3 - devpts devpts rw,gid=5,mode=620,ptmxmode=000",
		"22 24 0:18 / /run rw,nosuid,noexec,relatime shared:5 - tmpfs tmpfs rw,size=807912k,mode=755",

		/* This is what we care about. */
		"24 0 8:2 / / rw - rootfs rootfs rw,size=1004396k,nr_inodes=251099",

		"25 18 0:12 / /sys/kernel/security rw,nosuid,nodev,noexec,relatime shared:8 - securityfs securityfs rw",
		"26 20 0:20 / /dev/shm rw,nosuid,nodev shared:4 - tmpfs tmpfs rw",
		"27 22 0:21 / /run/lock rw,nosuid,nodev,noexec,relatime shared:6 - tmpfs tmpfs rw,size=5120k",
		"28 18 0:22 / /sys/fs/cgroup ro,nosuid,nodev,noexec shared:9 - tmpfs tmpfs ro,mode=755",
		"29 28 0:23 / /sys/fs/cgroup/systemd rw,nosuid,nodev,noexec,relatime shared:10 - cgroup cgroup rw,xattr,release_agent=/lib/systemd/systemd-cgroups-agent,name=systemd",
		"30 18 0:24 / /sys/fs/pstore rw,nosuid,nodev,noexec,relatime shared:11 - pstore pstore rw",
		"31 18 0:25 / /sys/firmware/efi/efivars rw,nosuid,nodev,noexec,relatime shared:12 - efivarfs efivarfs rw",
		"32 28 0:26 / /sys/fs/cgroup/cpu,cpuacct rw,nosuid,nodev,noexec,relatime shared:14 - cgroup cgroup rw,cpu,cpuacct",
		"33 28 0:27 / /sys/fs/cgroup/net_cls,net_prio rw,nosuid,nodev,noexec,relatime shared:15 - cgroup cgroup rw,net_cls,net_prio",
		"34 28 0:28 / /sys/fs/cgroup/blkio rw,nosuid,nodev,noexec,relatime shared:16 - cgroup cgroup rw,blkio",
		"35 28 0:29 / /sys/fs/cgroup/freezer rw,nosuid,nodev,noexec,relatime shared:17 - cgroup cgroup rw,freezer",
		"36 28 0:30 / /sys/fs/cgroup/memory rw,nosuid,nodev,noexec,relatime shared:18 - cgroup cgroup rw,memory",
		"37 28 0:31 / /sys/fs/cgroup/hugetlb rw,nosuid,nodev,noexec,relatime shared:19 - cgroup cgroup rw,hugetlb",
		"38 28 0:32 / /sys/fs/cgroup/cpuset rw,nosuid,nodev,noexec,relatime shared:20 - cgroup cgroup rw,cpuset",
		"39 28 0:33 / /sys/fs/cgroup/devices rw,nosuid,nodev,noexec,relatime shared:21 - cgroup cgroup rw,devices",
		"40 28 0:34 / /sys/fs/cgroup/pids rw,nosuid,nodev,noexec,relatime shared:22 - cgroup cgroup rw,pids",
		"41 28 0:35 / /sys/fs/cgroup/perf_event rw,nosuid,nodev,noexec,relatime shared:23 - cgroup cgroup rw,perf_event",
		"42 19 0:36 / /proc/sys/fs/binfmt_misc rw,relatime shared:24 - autofs systemd-1 rw,fd=32,pgrp=1,timeout=0,minproto=5,maxproto=5,direct",
		"43 18 0:7 / /sys/kernel/debug rw,relatime shared:25 - debugfs debugfs rw",
		"44 20 0:37 / /dev/hugepages rw,relatime shared:26 - hugetlbfs hugetlbfs rw",
		"45 20 0:16 / /dev/mqueue rw,relatime shared:27 - mqueue mqueue rw",
		"46 43 0:9 / /sys/kernel/debug/tracing rw,relatime shared:28 - tracefs tracefs rw",
		"76 18 0:38 / /sys/fs/fuse/connections rw,relatime shared:29 - fusectl fusectl rw",
		"78 24 8:1 / /boot/efi rw,relatime shared:30 - vfat /dev/sda1 rw,fmask=0077,dmask=0077,codepage=437,iocharset=iso8859-1,shortname=mixed,errors=remount-ro",
	};

	ret = snprintf(path, __MNTNS_LEN, "/proc/self/ns/mnt");
	if (ret < 0 || (size_t)ret >= __MNTNS_LEN) {
		lxc_error("%s\n", "Failed to create path with snprintf().");
		goto non_test_error;
	}

	init_ns = open(path, O_RDONLY | O_CLOEXEC);
	if (init_ns < 0) {
		lxc_error("%s\n", "Failed to open initial mount namespace.");
		goto non_test_error;
	}

	if (unshare(CLONE_NEWNS) < 0) {
		lxc_error("%s\n", "Could not unshare mount namespace.");
		close(init_ns);
		init_ns = -1;
		goto non_test_error;
	}

	if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, 0) < 0) {
		lxc_error("Failed to remount / private: %s.\n", strerror(errno));
		goto non_test_error;
	}

	fd1 = mkstemp(tmpf1);
	if (fd1 < 0) {
		lxc_error("%s\n", "Could not create temporary file.");
		goto non_test_error;
	}

	fd2 = mkstemp(tmpf2);
	if (fd2 < 0) {
		lxc_error("%s\n", "Could not create temporary file.");
		goto non_test_error;
	}

	fp1 = fdopen(fd1, "r+");
	if (!fp1) {
		lxc_error("%s\n", "Could not fdopen() temporary file.");
		goto non_test_error;
	}

	fp2 = fdopen(fd2, "r+");
	if (!fp2) {
		lxc_error("%s\n", "Could not fdopen() temporary file.");
		goto non_test_error;
	}

	/* Test if it correctly detects - rootfs rootfs */
	for (i = 0; i < sizeof(mountinfo) / sizeof(mountinfo[0]); i++) {
		if (fprintf(fp1, "%s\n", mountinfo[i]) < 0) {
			lxc_error("Could not write \"%s\" to temporary file.", mountinfo[i]);
			goto non_test_error;
		}
	}
	fclose(fp1);
	fp1 = NULL;
	fd1 = -1;

	/* Test if it correctly fails to detect when no - rootfs rootfs */
	for (i = 0; i < sizeof(mountinfo) / sizeof(mountinfo[0]); i++) {
		if (strcmp(mountinfo[i], "24 0 8:2 / / rw - rootfs rootfs rw,size=1004396k,nr_inodes=251099") == 0)
			continue;
		if (fprintf(fp2, "%s\n", mountinfo[i]) < 0) {
			lxc_error("Could not write \"%s\" to temporary file.", mountinfo[i]);
			goto non_test_error;
		}
	}
	fclose(fp2);
	fp2 = NULL;
	fd2 = -1;

	if (mount(tmpf1, "/proc/self/mountinfo", NULL, MS_BIND, 0) < 0) {
		lxc_error("%s\n", "Could not overmount \"/proc/self/mountinfo\".");
		goto non_test_error;
	}

	lxc_test_assert_abort(detect_ramfs_rootfs());

	if (mount(tmpf2, "/proc/self/mountinfo", NULL, MS_BIND, 0) < 0) {
		lxc_error("%s\n", "Could not overmount \"/proc/self/mountinfo\".");
		goto non_test_error;
	}

	lxc_test_assert_abort(!detect_ramfs_rootfs());
	fret = EXIT_SUCCESS;

non_test_error:
	if (fp1)
		fclose(fp1);
	else if (fd1 > 0)
		close(fd1);
	if (fp2)
		fclose(fp2);
	else if (fd2 > 0)
		close(fd2);

	if (init_ns > 0) {
		if (setns(init_ns, 0) < 0) {
			lxc_error("Failed to switch back to initial mount namespace: %s.\n", strerror(errno));
			fret = EXIT_FAILURE;
		}
		close(init_ns);
	}
	if (fret == EXIT_SUCCESS)
		return;
	exit(fret);
}

void test_lxc_safe_uint(void)
{
	int ret;
	unsigned int n;
	char numstr[LXC_NUMSTRLEN64];

	lxc_test_assert_abort((-EINVAL == lxc_safe_uint("    -123", &n)));
	lxc_test_assert_abort((-EINVAL == lxc_safe_uint("-123", &n)));

	ret = snprintf(numstr, LXC_NUMSTRLEN64, "%" PRIu64, (uint64_t)UINT_MAX);
	if (ret < 0 || ret >= LXC_NUMSTRLEN64)
		exit(EXIT_FAILURE);
	lxc_test_assert_abort((0 == lxc_safe_uint(numstr, &n)) && n == UINT_MAX);

	ret = snprintf(numstr, LXC_NUMSTRLEN64, "%" PRIu64, (uint64_t)UINT_MAX + 1);
	if (ret < 0 || ret >= LXC_NUMSTRLEN64)
		exit(EXIT_FAILURE);
	lxc_test_assert_abort((-ERANGE == lxc_safe_uint(numstr, &n)));

	lxc_test_assert_abort((0 == lxc_safe_uint("1234345", &n)) && n == 1234345);
	lxc_test_assert_abort((0 == lxc_safe_uint("   345", &n)) && n == 345);
	lxc_test_assert_abort((-EINVAL == lxc_safe_uint("   g345", &n)));
	lxc_test_assert_abort((-EINVAL == lxc_safe_uint("   3g45", &n)));
	lxc_test_assert_abort((-EINVAL == lxc_safe_uint("   345g", &n)));
	lxc_test_assert_abort((-EINVAL == lxc_safe_uint("g345", &n)));
	lxc_test_assert_abort((-EINVAL == lxc_safe_uint("3g45", &n)));
	lxc_test_assert_abort((-EINVAL == lxc_safe_uint("345g", &n)));
	lxc_test_assert_abort((-EINVAL == lxc_safe_uint("g345   ", &n)));
	lxc_test_assert_abort((-EINVAL == lxc_safe_uint("3g45   ", &n)));
	lxc_test_assert_abort((-EINVAL == lxc_safe_uint("345g   ", &n)));
	lxc_test_assert_abort((-EINVAL == lxc_safe_uint("g", &n)));
	lxc_test_assert_abort((-EINVAL == lxc_safe_uint("   g345", &n)));
}

void test_lxc_safe_int(void)
{
	int ret;
	signed int n;
	char numstr[LXC_NUMSTRLEN64];

	ret = snprintf(numstr, LXC_NUMSTRLEN64, "%" PRIu64, (uint64_t)INT_MAX);
	if (ret < 0 || ret >= LXC_NUMSTRLEN64)
		exit(EXIT_FAILURE);
	lxc_test_assert_abort((0 == lxc_safe_int(numstr, &n)) && n == INT_MAX);

	ret = snprintf(numstr, LXC_NUMSTRLEN64, "%" PRIu64, (uint64_t)INT_MAX + 1);
	if (ret < 0 || ret >= LXC_NUMSTRLEN64)
		exit(EXIT_FAILURE);
	lxc_test_assert_abort((-ERANGE == lxc_safe_int(numstr, &n)));

	ret = snprintf(numstr, LXC_NUMSTRLEN64, "%" PRId64, (int64_t)INT_MIN);
	if (ret < 0 || ret >= LXC_NUMSTRLEN64)
		exit(EXIT_FAILURE);
	lxc_test_assert_abort((0 == lxc_safe_int(numstr, &n)) && n == INT_MIN);

	ret = snprintf(numstr, LXC_NUMSTRLEN64, "%" PRId64, (int64_t)INT_MIN - 1);
	if (ret < 0 || ret >= LXC_NUMSTRLEN64)
		exit(EXIT_FAILURE);
	lxc_test_assert_abort((-ERANGE == lxc_safe_int(numstr, &n)));

	lxc_test_assert_abort((0 == lxc_safe_int("1234345", &n)) && n == 1234345);
	lxc_test_assert_abort((0 == lxc_safe_int("   345", &n)) && n == 345);
	lxc_test_assert_abort((0 == lxc_safe_int("-1234345", &n)) && n == -1234345);
	lxc_test_assert_abort((0 == lxc_safe_int("   -345", &n)) && n == -345);
	lxc_test_assert_abort((-EINVAL == lxc_safe_int("   g345", &n)));
	lxc_test_assert_abort((-EINVAL == lxc_safe_int("   3g45", &n)));
	lxc_test_assert_abort((-EINVAL == lxc_safe_int("   345g", &n)));
	lxc_test_assert_abort((-EINVAL == lxc_safe_int("g345", &n)));
	lxc_test_assert_abort((-EINVAL == lxc_safe_int("3g45", &n)));
	lxc_test_assert_abort((-EINVAL == lxc_safe_int("345g", &n)));
	lxc_test_assert_abort((-EINVAL == lxc_safe_int("g345   ", &n)));
	lxc_test_assert_abort((-EINVAL == lxc_safe_int("3g45   ", &n)));
	lxc_test_assert_abort((-EINVAL == lxc_safe_int("345g   ", &n)));
	lxc_test_assert_abort((-EINVAL == lxc_safe_int("g", &n)));
	lxc_test_assert_abort((-EINVAL == lxc_safe_int("   g345", &n)));
}

void test_lxc_safe_long(void)
{
	signed long int n;

	lxc_test_assert_abort((0 == lxc_safe_long("1234345", &n)) && n == 1234345);
	lxc_test_assert_abort((0 == lxc_safe_long("   345", &n)) && n == 345);
	lxc_test_assert_abort((0 == lxc_safe_long("-1234345", &n)) && n == -1234345);
	lxc_test_assert_abort((0 == lxc_safe_long("   -345", &n)) && n == -345);
	lxc_test_assert_abort((-EINVAL == lxc_safe_long("   g345", &n)));
	lxc_test_assert_abort((-EINVAL == lxc_safe_long("   3g45", &n)));
	lxc_test_assert_abort((-EINVAL == lxc_safe_long("   345g", &n)));
	lxc_test_assert_abort((-EINVAL == lxc_safe_long("g345", &n)));
	lxc_test_assert_abort((-EINVAL == lxc_safe_long("3g45", &n)));
	lxc_test_assert_abort((-EINVAL == lxc_safe_long("345g", &n)));
	lxc_test_assert_abort((-EINVAL == lxc_safe_long("g345   ", &n)));
	lxc_test_assert_abort((-EINVAL == lxc_safe_long("3g45   ", &n)));
	lxc_test_assert_abort((-EINVAL == lxc_safe_long("345g   ", &n)));
	lxc_test_assert_abort((-EINVAL == lxc_safe_long("g", &n)));
	lxc_test_assert_abort((-EINVAL == lxc_safe_long("   g345", &n)));
}

void test_lxc_string_replace(void)
{
	char *s;

	s = lxc_string_replace("A", "A", "A");
	lxc_test_assert_abort(strcmp(s, "A") == 0);
	free(s);

	s = lxc_string_replace("A", "AA", "A");
	lxc_test_assert_abort(strcmp(s, "AA") == 0);
	free(s);

	s = lxc_string_replace("A", "AA", "BA");
	lxc_test_assert_abort(strcmp(s, "BAA") == 0);
	free(s);

	s = lxc_string_replace("A", "AA", "BAB");
	lxc_test_assert_abort(strcmp(s, "BAAB") == 0);
	free(s);

	s = lxc_string_replace("AA", "A", "AA");
	lxc_test_assert_abort(strcmp(s, "A") == 0);
	free(s);

	s = lxc_string_replace("AA", "A", "BAA");
	lxc_test_assert_abort(strcmp(s, "BA") == 0);
	free(s);

	s = lxc_string_replace("AA", "A", "BAAB");
	lxc_test_assert_abort(strcmp(s, "BAB") == 0);
	free(s);

	s = lxc_string_replace("\"A\"A", "\"A\"", "B\"A\"AB");
	lxc_test_assert_abort(strcmp(s, "B\"A\"B") == 0);
	free(s);
}

void test_lxc_string_in_array(void)
{
	lxc_test_assert_abort(lxc_string_in_array("", (const char *[]){"", NULL}));
	lxc_test_assert_abort(!lxc_string_in_array("A", (const char *[]){"", NULL}));
	lxc_test_assert_abort(!lxc_string_in_array("AAA", (const char *[]){"", "3472", "jshH", NULL}));

	lxc_test_assert_abort(lxc_string_in_array("A", (const char *[]){"A", NULL}));
	lxc_test_assert_abort(lxc_string_in_array("A", (const char *[]){"A", "B", "C", NULL}));
	lxc_test_assert_abort(lxc_string_in_array("A", (const char *[]){"B", "A", "C", NULL}));

	lxc_test_assert_abort(lxc_string_in_array("ABC", (const char *[]){"ASD", "ATR", "ABC", NULL}));
	lxc_test_assert_abort(lxc_string_in_array("GHJ", (const char *[]){"AZIU", "WRT567B", "879C", "GHJ", "IUZ89", NULL}));
	lxc_test_assert_abort(lxc_string_in_array("XYZ", (const char *[]){"BERTA", "ARQWE(9", "C8Zhkd", "7U", "XYZ", "UOIZ9", "=)()", NULL}));
}

void test_parse_byte_size_string(void)
{
	int ret;
	int64_t n;

	ret = parse_byte_size_string("0", &n);
	if (ret < 0) {
		lxc_error("%s\n", "Failed to parse \"0\"");
		exit(EXIT_FAILURE);
	}
	if (n != 0) {
		lxc_error("%s\n", "Failed to parse \"0\"");
		exit(EXIT_FAILURE);
	}

	ret = parse_byte_size_string("1", &n);
	if (ret < 0) {
		lxc_error("%s\n", "Failed to parse \"1\"");
		exit(EXIT_FAILURE);
	}
	if (n != 1) {
		lxc_error("%s\n", "Failed to parse \"1\"");
		exit(EXIT_FAILURE);
	}

	ret = parse_byte_size_string("1 ", &n);
	if (ret == 0) {
		lxc_error("%s\n", "Failed to parse \"1 \"");
		exit(EXIT_FAILURE);
	}

	ret = parse_byte_size_string("1B", &n);
	if (ret < 0) {
		lxc_error("%s\n", "Failed to parse \"1B\"");
		exit(EXIT_FAILURE);
	}
	if (n != 1) {
		lxc_error("%s\n", "Failed to parse \"1B\"");
		exit(EXIT_FAILURE);
	}

	ret = parse_byte_size_string("1kB", &n);
	if (ret < 0) {
		lxc_error("%s\n", "Failed to parse \"1kB\"");
		exit(EXIT_FAILURE);
	}
	if (n != 1024) {
		lxc_error("%s\n", "Failed to parse \"1kB\"");
		exit(EXIT_FAILURE);
	}

	ret = parse_byte_size_string("1MB", &n);
	if (ret < 0) {
		lxc_error("%s\n", "Failed to parse \"1MB\"");
		exit(EXIT_FAILURE);
	}
	if (n != 1048576) {
		lxc_error("%s\n", "Failed to parse \"1MB\"");
		exit(EXIT_FAILURE);
	}

	ret = parse_byte_size_string("1TB", &n);
	if (ret == 0) {
		lxc_error("%s\n", "Failed to parse \"1TB\"");
		exit(EXIT_FAILURE);
	}

	ret = parse_byte_size_string("1 B", &n);
	if (ret < 0) {
		lxc_error("%s\n", "Failed to parse \"1 B\"");
		exit(EXIT_FAILURE);
	}
	if (n != 1) {
		lxc_error("%s\n", "Failed to parse \"1 B\"");
		exit(EXIT_FAILURE);
	}

	ret = parse_byte_size_string("1 kB", &n);
	if (ret < 0) {
		lxc_error("%s\n", "Failed to parse \"1 kB\"");
		exit(EXIT_FAILURE);
	}
	if (n != 1024) {
		lxc_error("%s\n", "Failed to parse \"1 kB\"");
		exit(EXIT_FAILURE);
	}

	ret = parse_byte_size_string("1 MB", &n);
	if (ret < 0) {
		lxc_error("%s\n", "Failed to parse \"1 MB\"");
		exit(EXIT_FAILURE);
	}
	if (n != 1048576) {
		lxc_error("%s\n", "Failed to parse \"1 MB\"");
		exit(EXIT_FAILURE);
	}

	ret = parse_byte_size_string("1 TB", &n);
	if (ret == 0) {
		lxc_error("%s\n", "Failed to parse \"1 TB\"");
		exit(EXIT_FAILURE);
	}

	ret = parse_byte_size_string("asdf", &n);
	if (ret == 0) {
		lxc_error("%s\n", "Failed to parse \"asdf\"");
		exit(EXIT_FAILURE);
	}
}

void test_lxc_config_net_hwaddr(void)
{
	bool lxc_config_net_hwaddr(const char *line);

	if (!lxc_config_net_hwaddr("lxc.net.0.hwaddr = 00:16:3e:04:65:b8\n"))
		exit(EXIT_FAILURE);

	if (lxc_config_net_hwaddr("lxc.net"))
		exit(EXIT_FAILURE);
	if (lxc_config_net_hwaddr("lxc.net."))
		exit(EXIT_FAILURE);
	if (lxc_config_net_hwaddr("lxc.net.0."))
		exit(EXIT_FAILURE);
}

void test_task_blocks_signal(void)
{
	int ret;
	pid_t pid;

	pid = fork();
	if (pid < 0)
		_exit(EXIT_FAILURE);

	if (pid == 0) {
		int i;
		sigset_t mask;
		int signals[] = {SIGBUS,   SIGILL,       SIGSEGV,
				 SIGWINCH, SIGQUIT,      SIGUSR1,
				 SIGUSR2,  SIGRTMIN + 3, SIGRTMIN + 4};

		sigemptyset(&mask);

		for (i = 0; i < (sizeof(signals) / sizeof(signals[0])); i++) {
			ret = sigaddset(&mask, signals[i]);
			if (ret < 0)
				_exit(EXIT_FAILURE);
		}

		ret = pthread_sigmask(SIG_BLOCK, &mask, NULL);
		if (ret < 0) {
			lxc_error("%s\n", "Failed to block signals");
			_exit(EXIT_FAILURE);
		}

		for (i = 0; i < (sizeof(signals) / sizeof(signals[0])); i++) {
			if (!task_blocks_signal(getpid(), signals[i])) {
				lxc_error("Failed to detect blocked signal "
					  "(idx = %d, signal number = %d)\n",
					  i, signals[i]);
				_exit(EXIT_FAILURE);
			}
		}

		if (task_blocks_signal(getpid(), SIGKILL)) {
			lxc_error("%s\n",
				  "Falsely detected SIGKILL as blocked signal");
			_exit(EXIT_FAILURE);
		}

		if (task_blocks_signal(getpid(), SIGSTOP)) {
			lxc_error("%s\n",
				  "Falsely detected SIGSTOP as blocked signal");
			_exit(EXIT_FAILURE);
		}

		_exit(EXIT_SUCCESS);
	}

	ret = wait_for_pid(pid);
	if (ret < 0)
		_exit(EXIT_FAILURE);

	return;
}

int main(int argc, char *argv[])
{
	test_lxc_string_replace();
	test_lxc_string_in_array();
	test_lxc_deslashify();
	test_detect_ramfs_rootfs();
	test_lxc_safe_uint();
	test_lxc_safe_int();
	test_lxc_safe_long();
	test_parse_byte_size_string();
	test_lxc_config_net_hwaddr();
	test_task_blocks_signal();

	exit(EXIT_SUCCESS);
}
