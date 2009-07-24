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
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <mntent.h>
#include <unistd.h>
#include <pty.h>

#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mount.h>
#include <sys/mman.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <libgen.h>

#include "network.h"
#include "error.h"
#include "parse.h"

#include <lxc/lxc.h>
#include <lxc/log.h>

lxc_log_define(lxc_conf, lxc);

#define MAXHWLEN    18
#define MAXINDEXLEN 20
#define MAXMTULEN   16
#define MAXLINELEN  128

#ifndef MS_REC
#define MS_REC 16384
#endif

typedef int (*instanciate_cb)(const char *directory,
			      const char *file, pid_t pid);

struct netdev_conf {
	const char *type;
	instanciate_cb cb;
	int count;
};

struct mount_opt {
	char *name;
	int clear;
	int flag;
};

static int instanciate_veth(const char *, const char *, pid_t);
static int instanciate_macvlan(const char *, const char *, pid_t);
static int instanciate_phys(const char *, const char *, pid_t);
static int instanciate_empty(const char *, const char *, pid_t);
static int unconfigure_cgroup(const char *name);

static struct netdev_conf netdev_conf[MAXCONFTYPE + 1] = {
	[VETH]    = { "veth",    instanciate_veth,    0  },
	[MACVLAN] = { "macvlan", instanciate_macvlan, 0, },
	[PHYS]    = { "phys",    instanciate_phys,    0, },
	[EMPTY]   = { "empty",   instanciate_empty,   0, },
};

static struct mount_opt mount_opt[] = {
	{ "defaults",   0, 0              },
	{ "ro",         0, MS_RDONLY      },
	{ "rw",         1, MS_RDONLY      },
	{ "suid",       1, MS_NOSUID      },
	{ "nosuid",     0, MS_NOSUID      },
	{ "dev",        1, MS_NODEV       },
	{ "nodev",      0, MS_NODEV       },
	{ "exec",       1, MS_NOEXEC      },
	{ "noexec",     0, MS_NOEXEC      },
	{ "sync",       0, MS_SYNCHRONOUS },
	{ "async",      1, MS_SYNCHRONOUS },
	{ "remount",    0, MS_REMOUNT     },
	{ "mand",       0, MS_MANDLOCK    },
	{ "nomand",     1, MS_MANDLOCK    },
	{ "atime",      1, MS_NOATIME     },
	{ "noatime",    0, MS_NOATIME     },
	{ "diratime",   1, MS_NODIRATIME  },
	{ "nodiratime", 0, MS_NODIRATIME  },
	{ "bind",       0, MS_BIND        },
	{ "rbind",      0, MS_BIND|MS_REC },
	{ NULL,         0, 0              },
};

static int write_info(const char *path, const char *file, const char *info)
{
	int fd, err = -1;
	char f[MAXPATHLEN];

	snprintf(f, MAXPATHLEN, "%s/%s", path, file);
	fd = creat(f, 0755);
	if (fd < 0)
		goto out;

	if (write(fd, info, strlen(info)) < 0 ||
	    write(fd, "\n", strlen("\n") + 1) < 0)
		goto out_write;
	err = 0;
out:
	close(fd);
	return err;

out_write:
	unlink(f);
	goto out;
}

static int read_info(const char *path, const char *file, char *info, size_t len)
{
	int fd, ret = -1;
	char f[MAXPATHLEN], *token;

	snprintf(f, MAXPATHLEN, "%s/%s", path, file);
	fd = open(f, O_RDONLY);
	if (fd < 0) {
		if (errno == ENOENT)
			ret = 1;
		goto out;
	}

	ret = read(fd, info, len);
	if (ret < 0)
		goto out;

	token = strstr(info, "\n");
	if (token)
		*token = '\0';
	ret = 0;
out:
	close(fd);
	return ret;
}

static int delete_info(const char *path, const char *file)
{
	char info[MAXPATHLEN];
	int ret;

	snprintf(info, MAXPATHLEN, "%s/%s", path, file);
	ret = unlink(info);

	return ret;
}

static int configure_ip4addr(int fd, struct lxc_inetdev *in)
{
	char addr[INET6_ADDRSTRLEN];
	char bcast[INET_ADDRSTRLEN];
	char line[MAXLINELEN];
	int err = -1;

	if (!inet_ntop(AF_INET, &in->addr, addr, sizeof(addr))) {
		SYSERROR("failed to convert ipv4 address");
		goto err;
	}

	if (!inet_ntop(AF_INET, &in->bcast, bcast, sizeof(bcast))) {
		SYSERROR("failed to convert ipv4 broadcast");
		goto err;
	}

	if (in->prefix)
		snprintf(line, MAXLINELEN, "%s/%d %s\n", addr, in->prefix, bcast);
	else
		snprintf(line, MAXLINELEN, "%s %s\n", addr, bcast);

	if (write(fd, line, strlen(line)) < 0) {
		SYSERROR("failed to write address info");
		goto err;
	}

	err = 0;
err:
	return err;
}

static int configure_ip6addr(int fd, struct lxc_inet6dev *in6)
{
	char addr[INET6_ADDRSTRLEN];
	char line[MAXLINELEN];
	int err = -1;

	if (!inet_ntop(AF_INET6, &in6->addr, addr, sizeof(addr))) {
		SYSERROR("failed to convert ipv4 address");
		goto err;
	}

	snprintf(line, MAXLINELEN, "%s/%d\n", addr, in6->prefix?in6->prefix:64);

	if (write(fd, line, strlen(line)) < 0) {
		SYSERROR("failed to write address info");
		goto err;
	}

	err = 0;
err:
	return err;
}

static int configure_ip_address(const char *path, struct lxc_list *ip, int family)
{
	char file[MAXPATHLEN];
	struct lxc_list *iterator;
	int fd, err = -1;

	if (mkdir(path, 0755)) {
		SYSERROR("failed to create directory %s", path);
		return -1;
	}

	snprintf(file, MAXPATHLEN, "%s/addresses", path);
	fd = creat(file, 0755);
	if (fd < 0) {
		SYSERROR("failed to create %s file", file);
		goto err;
	}

	lxc_list_for_each(iterator, ip) {
		err = family == AF_INET?
			configure_ip4addr(fd, iterator->elem):
			configure_ip6addr(fd, iterator->elem);
		if (err)
			goto err;
	}
out:
	close(fd);
	return err;
err:
	unlink(file);
	rmdir(path);
	goto out;
}

static int configure_netdev(const char *path, struct lxc_netdev *netdev)
{
	int err = -1;
	char dir[MAXPATHLEN];

	if (mkdir(path, 0755)) {
		SYSERROR("failed to create %s directory", path);
		return -1;
	}

	if (netdev->ifname) {
		if (write_info(path, "link", netdev->ifname))
			goto out_link;
	}

	if (netdev->newname) {
		if (write_info(path, "name", netdev->newname))
			goto out_newname;
	}

	if (netdev->hwaddr) {
		if (write_info(path, "hwaddr", netdev->hwaddr))
			goto out_hwaddr;
	}

	if (netdev->mtu) {
		if (write_info(path, "mtu", netdev->mtu))
			goto out_mtu;
	}

	if (netdev->flags & IFF_UP) {
		if (write_info(path, "up", ""))
			goto out_up;
	}

	if (!lxc_list_empty(&netdev->ipv4)) {
		snprintf(dir, MAXPATHLEN, "%s/ipv4", path);
		if (configure_ip_address(dir, &netdev->ipv4, AF_INET))
			goto out_ipv4;
	}

	if (!lxc_list_empty(&netdev->ipv6)) {
		snprintf(dir, MAXPATHLEN, "%s/ipv6", path);
		if (configure_ip_address(dir, &netdev->ipv6, AF_INET6))
			goto out_ipv6;
	}
	err = 0;
out:
	return err;
out_ipv6:
	delete_info(path, "ipv4");
out_ipv4:
	delete_info(path, "up");
out_up:
	delete_info(path, "mtu");
out_mtu:
	delete_info(path, "hwaddr");
out_hwaddr:
	delete_info(path, "name");
out_newname:
	delete_info(path, "link");
out_link:
	rmdir(path);
	goto out;
}

static int configure_utsname(const char *name, struct utsname *utsname)
{
	char path[MAXPATHLEN];

	snprintf(path, MAXPATHLEN, LXCPATH "/%s", name);

	if (write_info(path, "utsname", utsname->nodename)) {
		ERROR("failed to write the utsname info");
		return -1;
	}

	return 0;
}

static int configure_network(const char *name, struct lxc_list *network)
{
	struct lxc_list *iterator;
	struct lxc_network *n;
	char networkpath[MAXPATHLEN];
	char path[MAXPATHLEN];
	int err = -1;

	if (lxc_list_empty(network))
		return 0;

	snprintf(networkpath, MAXPATHLEN, LXCPATH "/%s/network", name);
	if (mkdir(networkpath, 0755)) {
		SYSERROR("failed to create %s directory", networkpath);
		goto out;
	}

 	lxc_list_for_each(iterator, network) {

		n = iterator->elem;

		if (n->type < 0 || n->type > MAXCONFTYPE) {
			ERROR("invalid network configuration type '%d'",
				      n->type);
			goto out;
		}

		snprintf(path, MAXPATHLEN, "%s/%s%d", networkpath,
			 netdev_conf[n->type].type,
			 netdev_conf[n->type].count++);

		if (configure_netdev(path, lxc_list_first_elem(&n->netdev))) {
			ERROR("failed to configure network type %s",
				      netdev_conf[n->type].type);
			goto out;
		}
	}

	err = 0;
out:
	return err;
}

static int configure_cgroup(const char *name, struct lxc_list *cgroup)
{
	char path[MAXPATHLEN];
	struct lxc_list *iterator;
	struct lxc_cgroup *cg;
	FILE *file;

	if (lxc_list_empty(cgroup))
		return 0;

	snprintf(path, MAXPATHLEN, LXCPATH "/%s/cgroup", name);

	file = fopen(path, "w+");
	if (!file) {
		SYSERROR("failed to open '%s'", path);
		return -1;
	}

	lxc_list_for_each(iterator, cgroup) {
		cg = iterator->elem;
		fprintf(file, "%s=%s\n", cg->subsystem, cg->value);
	}

	fclose(file);

	return 0;
}

static int configure_tty(const char *name, int tty)
{
	char path[MAXPATHLEN];
	char *nbtty;
	int ret;

	if (asprintf(&nbtty, "%d", tty) < 0) {
		ERROR("failed to convert tty number");
		return -1;
	}

	snprintf(path, MAXPATHLEN, LXCPATH "/%s", name);

	ret = write_info(path, "tty", nbtty);
	if (ret)
		ERROR("failed to write the tty info");

	free(nbtty);

	return ret;
}

static int configure_find_fstype_cb(void* buffer, void *data)
{
	struct cbarg {
		const char *rootfs;
		const char *testdir;
		char *fstype;
		int mntopt;
	} *cbarg = data;

	char *fstype;

	/* we don't try 'nodev' entries */
	if (strstr(buffer, "nodev"))
		return 0;

	fstype = buffer;
	fstype += lxc_char_left_gc(fstype, strlen(fstype));
	fstype[lxc_char_right_gc(fstype, strlen(fstype))] = '\0';

	if (mount(cbarg->rootfs, cbarg->testdir, fstype, cbarg->mntopt, NULL))
		return 0;

	/* found ! */
	umount(cbarg->testdir);
	strcpy(cbarg->fstype, fstype);

	return 1;
}

/* find the filesystem type with brute force */
static int configure_find_fstype(const char *rootfs, char *fstype, int mntopt)
{
	int i, found;
	char buffer[MAXPATHLEN];

	struct cbarg {
		const char *rootfs;
		const char *testdir;
		char *fstype;
		int mntopt;
	} cbarg = {
		.rootfs = rootfs,
		.fstype = fstype,
		.mntopt = mntopt,
	};

	/* first we check with /etc/filesystems, in case the modules
	 * are auto-loaded and fall back to the supported kernel fs
	 */
	char *fsfile[] = {
		"/etc/filesystems",
		"/proc/filesystems",
	};

	cbarg.testdir = tempnam("/tmp", "lxc-");
	if (!cbarg.testdir) {
		SYSERROR("failed to build a temp name");
		return -1;
	}

	if (mkdir(cbarg.testdir, 0755)) {
		SYSERROR("failed to create temporary directory");
		return -1;
	}

	for (i = 0; i < sizeof(fsfile)/sizeof(fsfile[0]); i++) {

		found = lxc_file_for_each_line(fsfile[i],
					       configure_find_fstype_cb,
					       buffer, sizeof(buffer), &cbarg);

		if (found < 0) {
			SYSERROR("failed to read '%s'", fsfile[i]);
			goto out;
		}

		if (found)
			break;
	}

	if (!found) {
		ERROR("failed to determine fs type for '%s'", rootfs);
		goto out;
	}

out:
	rmdir(cbarg.testdir);
	return found - 1;
}

static int configure_rootfs_dir_cb(const char *rootfs, const char *absrootfs,
				   FILE *f)
{
	return fprintf(f, "%s %s none rbind 0 0\n", absrootfs, rootfs);
}

static int configure_rootfs_blk_cb(const char *rootfs, const char *absrootfs,
				   FILE *f)
{
	char fstype[MAXPATHLEN];

	if (configure_find_fstype(absrootfs, fstype, 0)) {
		ERROR("failed to configure mount for block device '%s'",
			      absrootfs);
		return -1;
	}

	return fprintf(f, "%s %s %s defaults 0 0\n", absrootfs, rootfs, fstype);
}

static int configure_rootfs(const char *name, const char *rootfs)
{
	char path[MAXPATHLEN];
	char absrootfs[MAXPATHLEN];
	char fstab[MAXPATHLEN];
	struct stat s;
	FILE *f;
	int i, ret;

	typedef int (*rootfs_cb)(const char *, const char *, FILE *);

	struct rootfs_type {
		int type;
		rootfs_cb cb;
	} rtfs_type[] = {
		{ __S_IFDIR, configure_rootfs_dir_cb },
		{ __S_IFBLK, configure_rootfs_blk_cb },
	};

	if (!realpath(rootfs, absrootfs)) {
		SYSERROR("failed to get real path for '%s'", rootfs);
		return -1;
	}

	snprintf(path, MAXPATHLEN, LXCPATH "/%s/rootfs", name);

	if (mkdir(path, 0755)) {
		SYSERROR("failed to create the '%s' directory", path);
		return -1;
	}

	if (access(absrootfs, F_OK)) {
		SYSERROR("'%s' is not accessible", absrootfs);
		return -1;
	}

	if (stat(absrootfs, &s)) {
		SYSERROR("failed to stat '%s'", absrootfs);
		return -1;
	}

	for (i = 0; i < sizeof(rtfs_type)/sizeof(rtfs_type[0]); i++) {

		if (!__S_ISTYPE(s.st_mode, rtfs_type[i].type))
			continue;

		snprintf(fstab, MAXPATHLEN, LXCPATH "/%s/fstab", name);

		f = fopen(fstab, "a+");
		if (!f) {
			SYSERROR("failed to open fstab file");
			return -1;
		}

		ret = rtfs_type[i].cb(path, absrootfs, f);

		fclose(f);

		if (ret < 0) {
			ERROR("failed to add rootfs mount in fstab");
			return -1;
		}

		snprintf(path, MAXPATHLEN, LXCPATH "/%s/rootfs/rootfs", name);

		return symlink(absrootfs, path);
	}

	ERROR("unsupported rootfs type for '%s'", absrootfs);
	return -1;
}

static int configure_pts(const char *name, int pts)
{
	char path[MAXPATHLEN];
	char *maxpts;
	int ret;

	if (asprintf(&maxpts, "%d", pts) < 0) {
		ERROR("failed to convert max pts number");
		return -1;
	}

	snprintf(path, MAXPATHLEN, LXCPATH "/%s", name);

	ret = write_info(path, "pts", maxpts);
	if (ret)
		ERROR("failed to write the pts info");

	free(maxpts);

	return ret;
}

static int configure_mount(const char *name, const char *fstab)
{
	char path[MAXPATHLEN];

	snprintf(path, MAXPATHLEN, LXCPATH "/%s/fstab", name);

	if (lxc_copy_file(fstab, path)) {
		ERROR("failed to copy the fstab file");
		return -1;
	}

	return 0;
}

static int unconfigure_ip_addresses(const char *directory)
{
	char path[MAXPATHLEN];

	snprintf(path, MAXPATHLEN, "%s/ipv4", directory);
	delete_info(path, "addresses");
	rmdir(path);

	snprintf(path, MAXPATHLEN, "%s/ipv6", directory);
	delete_info(path, "addresses");
	rmdir(path);

	return 0;
}

static int unconfigure_network_cb(const char *name, const char *directory,
				  const char *file, void *data)
{
	char path[MAXPATHLEN];

	snprintf(path, MAXPATHLEN, "%s/%s", directory, file);
	delete_info(path, "ifindex");
	delete_info(path, "name");
	delete_info(path, "addr");
	delete_info(path, "link");
	delete_info(path, "hwaddr");
	delete_info(path, "mtu");
	delete_info(path, "up");
	unconfigure_ip_addresses(path);
	rmdir(path);

	return 0;
}

static int unconfigure_network(const char *name)
{
	char directory[MAXPATHLEN];

	snprintf(directory, MAXPATHLEN, LXCPATH "/%s/network", name);
	lxc_dir_for_each(name, directory, unconfigure_network_cb, NULL);
	rmdir(directory);

	return 0;
}

static int unconfigure_cgroup_cb(const char *name, const char *directory,
				  const char *file, void *data)
{
	return delete_info(directory, file);
}

static int unconfigure_cgroup(const char *name)
{
	char filename[MAXPATHLEN];
	struct stat s;

	snprintf(filename, MAXPATHLEN, LXCPATH "/%s/cgroup", name);

	if (stat(filename, &s)) {
		SYSERROR("failed to stat '%s'", filename);
		return -1;
	}

	if (S_ISDIR(s.st_mode)) {
		/* old cgroup configuration */
		lxc_dir_for_each(name, filename, unconfigure_cgroup_cb, NULL);
		rmdir(filename);
	} else {
		unlink(filename);
	}

	return 0;
}

static int unconfigure_rootfs(const char *name)
{
	char path[MAXPATHLEN];

	snprintf(path, MAXPATHLEN, LXCPATH "/%s/rootfs", name);

#warning deprecated code to be removed in the next version

	/* ugly but for backward compatibily, */
	delete_info(path, "rootfs");
	rmdir(path);
	unlink(path);

	return 0;
}

static int unconfigure_pts(const char *name)
{
	char path[MAXPATHLEN];

	snprintf(path, MAXPATHLEN, LXCPATH "/%s", name);
	delete_info(path, "pts");

	return 0;
}

static int unconfigure_tty(const char *name)
{
	char path[MAXPATHLEN];

	snprintf(path, MAXPATHLEN, LXCPATH "/%s", name);
	delete_info(path, "tty");

	return 0;
}

static int unconfigure_mount(const char *name)
{
	char path[MAXPATHLEN];

	snprintf(path, MAXPATHLEN, LXCPATH "/%s", name);
	delete_info(path, "fstab");

	return 0;
}

static int unconfigure_utsname(const char *name)
{
	char path[MAXPATHLEN];

	snprintf(path, MAXPATHLEN, LXCPATH "/%s", name);
	delete_info(path, "utsname");

	return 0;
}

static int setup_utsname(const char *name)
{
	int ret;
	char path[MAXPATHLEN];
	struct utsname utsname;

	snprintf(path, MAXPATHLEN, LXCPATH "/%s", name);

	ret = read_info(path, "utsname", utsname.nodename,
			sizeof(utsname.nodename));
	if (ret < 0) {
		SYSERROR("failed to read utsname info");
		return -1;
	}

	if (!ret && sethostname(utsname.nodename, strlen(utsname.nodename))) {
		SYSERROR("failed to set the hostname to '%s'",
				 utsname.nodename);
		return -1;
	}

	INFO("'%s' hostname has been setup", utsname.nodename);

	return 0;
}

static int setup_tty(const char *name, const struct lxc_tty_info *tty_info)
{
	char path[MAXPATHLEN];
	int i;

	for (i = 0; i < tty_info->nbtty; i++) {

		struct lxc_pty_info *pty_info = &tty_info->pty_info[i];

		if (conf_has_rootfs(name))
			snprintf(path, MAXPATHLEN,
				 LXCPATH "/%s/rootfs/dev/tty%d", name, i + 1);
		else
			snprintf(path, MAXPATHLEN, "/dev/tty%d", i + 1);

		/* At this point I can not use the "access" function
		 * to check the file is present or not because it fails
		 * with EACCES errno and I don't know why :( */

		if (mount(pty_info->name, path, "none", MS_BIND, 0)) {
			WARN("failed to mount '%s'->'%s'",
					pty_info->name, path);
			continue;
		}
	}

	INFO("%d tty(s) has been setup", tty_info->nbtty);

	return 0;
}

static int setup_rootfs(const char *name)
{
	char path[MAXPATHLEN];

	snprintf(path, MAXPATHLEN, LXCPATH "/%s/rootfs", name);

	if (chroot(path)) {
		SYSERROR("failed to set chroot %s", path);
		return -1;
	}

	if (chdir(getenv("HOME")) && chdir("/")) {
		SYSERROR("failed to change to home directory");
		return -1;
	}

	INFO("chrooted to '%s'", path);

	return 0;
}

static int setup_pts(const char *name)
{
	char mountname[MAXPATHLEN];

	if (!access("/dev/pts/ptmx", F_OK) && umount("/dev/pts")) {
		SYSERROR("failed to umount 'dev/pts'");
		return -1;
	}

	snprintf(mountname, MAXPATHLEN, "%spts", name);

	if (mount(mountname, "/dev/pts", "devpts", MS_MGC_VAL, "newinstance")) {
		SYSERROR("failed to mount a new instance of '/dev/pts'");
		return -1;
	}

	if (chmod("/dev/pts/ptmx", 0666)) {
		SYSERROR("failed to set permission for '/dev/pts/ptmx'");
		return -1;
	}

	if (access("/dev/ptmx", F_OK)) {
		if (!symlink("/dev/pts/ptmx", "/dev/ptmx"))
			goto out;
		SYSERROR("failed to symlink '/dev/pts/ptmx'->'/dev/ptmx'");
		return -1;
	}

	/* fallback here, /dev/pts/ptmx exists just mount bind */
	if (mount("/dev/pts/ptmx", "/dev/ptmx", "none", MS_BIND, 0)) {
		SYSERROR("mount failed '/dev/pts/ptmx'->'/dev/ptmx'");
		return -1;
	}

	INFO("created new pts instance");
out:
	return 0;
}

static int setup_console(const char *name, const char *tty)
{
	char console[MAXPATHLEN];

	snprintf(console, MAXPATHLEN, LXCPATH "/%s/rootfs/dev/console", name);

	if (access(console, R_OK|W_OK))
		return 0;

	if (mount(tty, console, "none", MS_BIND, 0)) {
		ERROR("failed to mount the console");
		return -1;
	}

	INFO("console '%s' mounted to '%s'", tty, console);

	return 0;
}

static int setup_cgroup_cb(void* buffer, void *data)
{
	char *key = buffer, *value;
	char *name = data;
	int ret;

	value = strchr(key, '=');
	if (!value)
		return -1;

	*value = '\0';
	value += 1;

	/* remove spurious '\n'*/
	if (value[strlen(value) - 1] == '\n')
		value[strlen(value) - 1] = '\0';

	ret = lxc_cgroup_set(name, key, value);
	if (ret)
		ERROR("failed to set cgroup '%s' = '%s' for '%s'",
		      key, value, name);
	else
		DEBUG("cgroup '%s' set to '%s'", key, value);

	return ret;
}

static int setup_convert_cgroup_cb(const char *name, const char *directory,
				   const char *file, void *data)
{
	FILE *f = data;
	char line[MAXPATHLEN];

	if (read_info(directory, file, line, MAXPATHLEN)) {
		ERROR("failed to read %s", file);
		return -1;
	}

	fprintf(f, "%s=%s\n", file, line);

	return 0;
}

static int setup_convert_cgroup(const char *name, char *directory)
{
	char filename[MAXPATHLEN];
	FILE *file;
	int ret;

	snprintf(filename, MAXPATHLEN, LXCPATH "/%s/cgroup.new", name);

	file = fopen(filename, "w+");
	if (!file)
		return -1;

	ret = lxc_dir_for_each(name, directory, setup_convert_cgroup_cb, file);
	if (ret)
		goto out_error;

	ret = unconfigure_cgroup(name);
	if (ret)
		goto out_error;

	ret = rename(filename, directory);
	if (ret)
		goto out_error;
out:
	fclose(file);
	return ret;

out_error:
	unlink(filename);
	goto out;
}

static int setup_cgroup(const char *name)
{
	char filename[MAXPATHLEN];
	char line[MAXPATHLEN];
	struct stat s;
	int ret;

	snprintf(filename, MAXPATHLEN, LXCPATH "/%s/cgroup", name);

	if (stat(filename, &s)) {
		SYSERROR("failed to stat '%s'", filename);
		return -1;
	}

	if (S_ISDIR(s.st_mode)) {
		if (setup_convert_cgroup(name, filename)) {
			ERROR("failed to convert old cgroup configuration");
			return -1;
		}
	}

	ret = lxc_file_for_each_line(filename, setup_cgroup_cb,
				     line, MAXPATHLEN, (void *)name);
	if (ret)
		return ret;

	INFO("cgroup has been setup");

	return 0;
}

static void parse_mntopt(char *opt, unsigned long *flags, char **data)
{
	struct mount_opt *mo;

	/* If opt is found in mount_opt, set or clear flags.
	 * Otherwise append it to data. */

	for (mo = &mount_opt[0]; mo->name != NULL; mo++) {
		if (!strncmp(opt, mo->name, strlen(mo->name))) {
			if (mo->clear)
				*flags &= ~mo->flag;
			else
				*flags |= mo->flag;
			return;
		}
	}

	if (strlen(*data))
		strcat(*data, ",");
	strcat(*data, opt);
}

static int parse_mntopts(struct mntent *mntent, unsigned long *mntflags,
			 char **mntdata)
{
	char *s, *data;
	char *p, *saveptr = NULL;

	if (!mntent->mnt_opts)
		return 0;

	s = strdup(mntent->mnt_opts);
	if (!s) {
		SYSERROR("failed to allocate memory");
		return -1;
	}

	data = malloc(strlen(s) + 1);
	if (!data) {
		SYSERROR("failed to allocate memory");
		free(s);
		return -1;
	}
	*data = 0;

	for (p = strtok_r(s, ",", &saveptr); p != NULL;
	     p = strtok_r(NULL, ",", &saveptr))
		parse_mntopt(p, mntflags, &data);

	if (*data)
		*mntdata = data;
	else
		free(data);
	free(s);

	return 0;
}

static int setup_mount(const char *name)
{
	char path[MAXPATHLEN];
	struct mntent *mntent;
	FILE *file;
	int ret = -1;
	unsigned long mntflags;
	char *mntdata;

	snprintf(path, MAXPATHLEN, LXCPATH "/%s/fstab", name);

	file = setmntent(path, "r");
	if (!file) {
		if (errno == ENOENT)
			return 0;
		SYSERROR("failed to open '%s'", path);
		goto out;
	}

	while ((mntent = getmntent(file))) {
		mntflags = 0;
		mntdata = NULL;
		if (parse_mntopts(mntent, &mntflags, &mntdata) < 0) {
			ERROR("failed to parse mount option '%s'",
				      mntent->mnt_opts);
			goto out;
		}

		if (mount(mntent->mnt_fsname, mntent->mnt_dir,
			  mntent->mnt_type, mntflags, mntdata)) {
			SYSERROR("failed to mount '%s' on '%s'",
					 mntent->mnt_fsname, mntent->mnt_dir);
			goto out;
		}

		DEBUG("mounted %s on %s, type %s", mntent->mnt_fsname,
		      mntent->mnt_dir, mntent->mnt_type);

		free(mntdata);
	}

	ret = 0;

	INFO("mount points have been setup");
out:
	endmntent(file);
	return ret;
}

static int setup_ipv4_addr_cb(void *buffer, void *data)
{
	char *ifname = data;
	char *cursor, *slash, *addr, *bcast = NULL, *prefix = NULL;
	int p = 24;

	addr = buffer;
	cursor = strstr(addr, " ");
	if (cursor) {
		*cursor = '\0';
		bcast = cursor + 1;
		cursor = strstr(bcast, "\n");
		if (cursor)
			*cursor = '\0';
	}

	slash = strstr(addr, "/");
	if (slash) {
		*slash = '\0';
		prefix = slash + 1;
	}

	if (prefix)
		p = atoi(prefix);

	if (lxc_ip_addr_add(ifname, addr, p, bcast)) {
		ERROR("failed to set %s to addr %s/%d %s", ifname,
			      addr, p, bcast?bcast:"");
		return -1;
	}

	DEBUG("address '%s/%s' on '%s' has been setup", addr, prefix, ifname);

	return 0;
}

static int setup_ipv6_addr_cb(void *buffer, void *data)
{
	char *ifname = data;
	char *cursor, *slash, *addr, *bcast = NULL, *prefix = NULL;
	int p = 24;

	addr = buffer;
	cursor = strstr(addr, " ");
	if (cursor) {
		*cursor = '\0';
		bcast = cursor + 1;
		cursor = strstr(bcast, "\n");
		if (cursor)
			*cursor = '\0';
	}

	slash = strstr(addr, "/");
	if (slash) {
		*slash = '\0';
		prefix = slash + 1;
	}

	if (prefix)
		p = atoi(prefix);

	if (lxc_ip6_addr_add(ifname, addr, p, bcast)) {
		ERROR("failed to set %s to addr %s/%d %s", ifname,
			      addr, p, bcast?bcast:"");
		return -1;
	}

	INFO("address '%s/%s' on '%s' has been setup", addr, prefix, ifname);

	return 0;
}

static int setup_hw_addr(char *hwaddr, const char *ifname)
{
	struct sockaddr sockaddr;
	struct ifreq ifr;
	int ret, fd;

	if (lxc_convert_mac(hwaddr, &sockaddr)) {
		ERROR("conversion has failed");
		return -1;
	}

	memcpy(ifr.ifr_name, ifname, IFNAMSIZ);
	memcpy((char *) &ifr.ifr_hwaddr, (char *) &sockaddr, sizeof(sockaddr));

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		ERROR("socket failure : %s", strerror(errno));
		return -1;
	}

	ret = ioctl(fd, SIOCSIFHWADDR, &ifr);
	close(fd);
	if (ret)
		ERROR("ioctl failure : %s", strerror(errno));

	DEBUG("mac address '%s' on '%s' has been setup", hwaddr, ifname);

	return ret;
}

static int setup_ip_addr(const char *directory, const char *ifname)
{
	char path[MAXPATHLEN], line[MAXLINELEN];
	struct stat s;
	int ret = 0;

	snprintf(path, MAXPATHLEN, "%s/ipv4/addresses", directory);
	if (!stat(path, &s))
		ret = lxc_file_for_each_line(path, setup_ipv4_addr_cb,
					     line, MAXPATHLEN, (void*)ifname);
	return ret;
}

static int setup_ip6_addr(const char *directory, const char *ifname)
{
	char path[MAXPATHLEN], line[MAXLINELEN];
	struct stat s;
	int ret = 0;

	snprintf(path, MAXLINELEN, "%s/ipv6/addresses", directory);
	if (!stat(path, &s))
		ret = lxc_file_for_each_line(path, setup_ipv6_addr_cb,
					     line, MAXPATHLEN, (void*)ifname);
	return ret;
}

static int setup_network_cb(const char *name, const char *directory,
			    const char *file, void *data)
{
	char path[MAXPATHLEN];
	char strindex[MAXINDEXLEN];
	char ifname[IFNAMSIZ];
	char newname[IFNAMSIZ];
	char hwaddr[MAXHWLEN];
	char *current_ifname = ifname;
	int ifindex;

	snprintf(path, MAXPATHLEN, "%s/%s", directory, file);

	if (read_info(path, "ifindex", strindex, sizeof(strindex))) {
		ERROR("failed to read ifindex info");
		return -1;
	}

	ifindex = atoi(strindex);
	if (!ifindex) {
		if (!read_info(path, "up", strindex, sizeof(strindex)))
		    if (lxc_device_up("lo")) {
			    ERROR("failed to set the loopback up");
			    return -1;
		    }
		    return 0;
	}

	if (!if_indextoname(ifindex, current_ifname)) {
		ERROR("no interface corresponding to index '%d'",
			      ifindex);
		return -1;
	}

	/* default: let the system to choose one interface name */
	if (read_info(path, "name", newname, sizeof(newname)))
		strcpy(newname, "eth%d");

	if (lxc_device_rename(ifname, newname)) {
		ERROR("failed to rename %s->%s", ifname, current_ifname);
		return -1;
	}

	/* Re-read the name of the interface because its name has changed
	 * and would be automatically allocated by the system
	 */
	if (!if_indextoname(ifindex, current_ifname)) {
		ERROR("no interface corresponding to index '%d'",
			      ifindex);
		return -1;
	}

	if (!read_info(path, "hwaddr", hwaddr, sizeof(hwaddr))) {
		if (setup_hw_addr(hwaddr, current_ifname)) {
			ERROR("failed to setup hw address for '%s'",
				      current_ifname);
			return -1;
		}
	}

	if (setup_ip_addr(path, current_ifname)) {
		ERROR("failed to setup ip addresses for '%s'",
			      ifname);
		return -1;
	}

	if (setup_ip6_addr(path, current_ifname)) {
		ERROR("failed to setup ipv6 addresses for '%s'",
			      ifname);
		return -1;
	}

	if (!read_info(path, "up", strindex, sizeof(strindex))) {
		if (lxc_device_up(current_ifname)) {
			ERROR("failed to set '%s' up", current_ifname);
			return -1;
		}

		/* the network is up, make the loopback up too */
		if (lxc_device_up("lo")) {
			ERROR("failed to set the loopback up");
			return -1;
		}
	}

	DEBUG("'%s' has been setup", current_ifname);

	return 0;
}

static int setup_network(const char *name)
{
	char directory[MAXPATHLEN];
	int ret;

	snprintf(directory, MAXPATHLEN, LXCPATH "/%s/network", name);

	ret = lxc_dir_for_each(name, directory, setup_network_cb, NULL);
	if (ret)
		return ret;

	INFO("network has been setup");

	return 0;
}

int conf_has(const char *name, const char *info)
{
	int ret = 0;
	char path[MAXPATHLEN];
	struct stat st;

	snprintf(path, MAXPATHLEN, LXCPATH "/%s/%s", name, info);

	if (!stat(path, &st) || !lstat(path, &st)) {
		ret = 1;
		goto out;
	}

	if (errno == ENOENT) {
		ret = 0;
		goto out;
	}

	SYSERROR("failed to stat %s info", info);
out:
	return ret;
}

int lxc_conf_init(struct lxc_conf *conf)
{
	conf->rootfs = NULL;
	conf->fstab = NULL;
	conf->utsname = NULL;
	conf->tty = 0;
	conf->pts = 0;
	lxc_list_init(&conf->cgroup);
	lxc_list_init(&conf->networks);
	return 0;
}

int lxc_configure(const char *name, struct lxc_conf *conf)
{
	if (!conf)
		return 0;

	if (conf->utsname && configure_utsname(name, conf->utsname)) {
		ERROR("failed to configure the utsname");
		return -1;
	}

	if (configure_cgroup(name, &conf->cgroup)) {
		ERROR("failed to configure the control group");
		return -1;
	}

	if (configure_network(name, &conf->networks)) {
		ERROR("failed to configure the network");
		return -1;
	}

	if (conf->tty && configure_tty(name, conf->tty)) {
		ERROR("failed to configure the tty");
		return -1;
	}

	if (conf->fstab && configure_mount(name, conf->fstab)) {
		ERROR("failed to configure the mount points");
		return -1;
	}

	if (conf->rootfs && configure_rootfs(name, conf->rootfs)) {
		ERROR("failed to configure the rootfs");
		return -1;
	}

	if (conf->pts && configure_pts(name, conf->pts)) {
		ERROR("failed to configure a new pts instance");
		return -1;
	}

	return 0;
}

int lxc_unconfigure(const char *name)
{
	if (conf_has_utsname(name) && unconfigure_utsname(name))
		ERROR("failed to cleanup utsname");

	if (conf_has_network(name) && unconfigure_network(name))
		ERROR("failed to cleanup the network");

	if (conf_has_cgroup(name) && unconfigure_cgroup(name))
		ERROR("failed to cleanup cgroup");

	if (conf_has_tty(name) && unconfigure_tty(name))
		ERROR("failed to cleanup tty");

	if (conf_has_rootfs(name) && unconfigure_rootfs(name))
		ERROR("failed to cleanup rootfs");

	if (conf_has_fstab(name) && unconfigure_mount(name))
		ERROR("failed to cleanup mount");

	if (conf_has_pts(name) && unconfigure_pts(name))
		ERROR("failed to cleanup pts");

	return 0;
}

static int instanciate_veth(const char *directory, const char *file, pid_t pid)
{
	char *path = NULL, *strindex = NULL, *veth1 = NULL, *veth2 = NULL;
	char bridge[IFNAMSIZ];
	char strmtu[MAXMTULEN];
	int ifindex, mtu = 0, ret = -1;

	if (!asprintf(&veth1, "%s_%d", file, pid) ||
	    !asprintf(&veth2, "%s~%d", file, pid) ||
	    !asprintf(&path, "%s/%s", directory, file)) {
		SYSERROR("failed to allocate memory");
		goto out;
	}

	if (read_info(path, "link", bridge, IFNAMSIZ)) {
		ERROR("failed to read bridge info");
		goto out;
	}

	if (lxc_veth_create(veth1, veth2)) {
		ERROR("failed to create %s-%s/%s", veth1, veth2, bridge);
		goto out;
	}

	if (!read_info(path, "mtu", strmtu, MAXMTULEN)) {
		if (sscanf(strmtu, "%u", &mtu) < 1) {
			ERROR("invalid mtu size '%d'", mtu);
			goto out_delete;
		}

		if (lxc_device_set_mtu(veth1, mtu)) {
			ERROR("failed to set mtu for '%s'", veth1);
			goto out_delete;
		}

		if (lxc_device_set_mtu(veth2, mtu)) {
			ERROR("failed to set mtu for '%s'", veth2);
			goto out_delete;
		}
	}

	if (lxc_bridge_attach(bridge, veth1)) {
		ERROR("failed to attach '%s' to the bridge '%s'",
			      veth1, bridge);
		goto out_delete;
	}

	ifindex = if_nametoindex(veth2);
	if (!ifindex) {
		ERROR("failed to retrieve the index for %s", veth2);
		goto out_delete;
	}

	if (!asprintf(&strindex, "%d", ifindex)) {
		SYSERROR("failed to allocate memory");
		goto out_delete;
	}

	if (write_info(path, "ifindex", strindex)) {
		ERROR("failed to write interface index to %s", path);
		goto out_delete;
	}

	if (!read_info(path, "up", strindex, sizeof(strindex))) {
		if (lxc_device_up(veth1)) {
			ERROR("failed to set %s up", veth1);
			goto out_delete;
		}
	}

	ret = 0;
out:
	free(path);
	free(strindex);
	free(veth1);
	free(veth2);
	return ret;

out_delete:
	lxc_device_delete(veth1);
	goto out;
}
static int instanciate_macvlan(const char *directory, const char *file, pid_t pid)
{
	char path[MAXPATHLEN], *strindex = NULL, *peer = NULL;
	char link[IFNAMSIZ];
	int ifindex, ret = -1;

	if (!asprintf(&peer, "%s~%d", file, pid)) {
		SYSERROR("failed to allocate memory");
		return -1;
	}

	snprintf(path, MAXPATHLEN, "%s/%s", directory, file);
	if (read_info(path, "link", link, IFNAMSIZ)) {
		ERROR("failed to read bridge info");
		goto out;
	}

	if (lxc_macvlan_create(link, peer)) {
		ERROR("failed to create macvlan interface '%s' on '%s'",
			      peer, link);
		goto out;
	}

	ifindex = if_nametoindex(peer);
	if (!ifindex) {
		ERROR("failed to retrieve the index for %s", peer);
		goto out;
	}

	if (!asprintf(&strindex, "%d", ifindex)) {
		SYSERROR("failed to allocate memory");
		return -1;
	}

	if (write_info(path, "ifindex", strindex)) {
		ERROR("failed to write interface index to %s", path);
		goto out;
	}

	ret = 0;
out:
	free(strindex);
	free(peer);
	return ret;
}

static int instanciate_phys(const char *directory, const char *file, pid_t pid)
{
	char path[MAXPATHLEN], *strindex = NULL;
	char link[IFNAMSIZ];
	int ifindex, ret = -1;

	snprintf(path, MAXPATHLEN, "%s/%s", directory, file);
	if (read_info(path, "link", link, IFNAMSIZ)) {
		ERROR("failed to read link info");
		goto out;
	}

	ifindex = if_nametoindex(link);
	if (!ifindex) {
		ERROR("failed to retrieve the index for %s", link);
		goto out;
	}

	if (!asprintf(&strindex, "%d", ifindex)) {
		SYSERROR("failed to allocate memory");
		return -1;
	}

	if (write_info(path, "ifindex", strindex)) {
		ERROR("failed to write interface index to %s", path);
		goto out;
	}

	ret = 0;
out:
	free(strindex);
	return ret;
}

static int instanciate_empty(const char *directory, const char *file, pid_t pid)
{
	char path[MAXPATHLEN], *strindex = NULL;
	int ret = -1;

	snprintf(path, MAXPATHLEN, "%s/%s", directory, file);
	if (!asprintf(&strindex, "%d", 0)) {
		ERROR("not enough memory");
		return -1;
	}

	if (write_info(path, "ifindex", strindex)) {
		ERROR("failed to write interface index to %s", path);
		goto out;
	}

	ret = 0;
out:
	free(strindex);
	return ret;
}

static int instanciate_netdev_cb(const char *name, const char *directory,
				 const char *file, void *data)
{
	pid_t *pid = data;

	if (!strncmp("veth", file, strlen("veth")))
		return instanciate_veth(directory, file, *pid);
	else if (!strncmp("macvlan", file, strlen("macvlan")))
		return instanciate_macvlan(directory, file, *pid);
	else if (!strncmp("phys", file, strlen("phys")))
		return instanciate_phys(directory, file, *pid);
	else if (!strncmp("empty", file, strlen("empty")))
		 return instanciate_empty(directory, file, *pid);

	return -1;
}

static int instanciate_netdev(const char *name, pid_t pid)
{
	char directory[MAXPATHLEN];

	snprintf(directory, MAXPATHLEN, LXCPATH "/%s/network", name);
	return lxc_dir_for_each(name, directory, instanciate_netdev_cb, &pid);
}

static int move_netdev_cb(const char *name, const char *directory,
			  const char *file, void *data)
{
	char path[MAXPATHLEN], ifname[IFNAMSIZ], strindex[MAXINDEXLEN];
	pid_t *pid = data;
	int ifindex;

	snprintf(path, MAXPATHLEN, "%s/%s", directory, file);
	if (read_info(path, "ifindex", strindex, MAXINDEXLEN) < 0) {
		ERROR("failed to read index to from %s", path);
		return -1;
	}

	ifindex = atoi(strindex);
	if (!ifindex)
		return 0;

	if (!if_indextoname(ifindex, ifname)) {
		ERROR("interface with index %d does not exist",
			      ifindex);
		return -1;
	}

	if (lxc_device_move(ifname, *pid)) {
		ERROR("failed to move %s to %d", ifname, *pid);
		return -1;
	}

	return 0;
}

static int move_netdev(const char *name, pid_t pid)
{
	char directory[MAXPATHLEN];
	snprintf(directory, MAXPATHLEN, LXCPATH "/%s/network", name);
	return lxc_dir_for_each(name, directory, move_netdev_cb, &pid);
}

int conf_create_network(const char *name, pid_t pid)
{
	if (instanciate_netdev(name, pid)) {
		ERROR("failed to instantiate the network devices");
		return -1;
	}

	if (move_netdev(name, pid)) {
		ERROR("failed to move the netdev to the container");
		return -1;
	}

	return 0;
}

int lxc_create_tty(const char *name, struct lxc_tty_info *tty_info)
{
	char path[MAXPATHLEN];
	char tty[4];
	int i, ret = -1;

	tty_info->nbtty = 0;

	if (!conf_has_tty(name))
		return 0;

	snprintf(path, MAXPATHLEN, LXCPATH "/%s", name);

	if (read_info(path, "tty", tty, sizeof(tty)) < 0) {
		SYSERROR("failed to read tty info");
		goto out;
	}

	tty_info->nbtty = atoi(tty);
	tty_info->pty_info =
		malloc(sizeof(*tty_info->pty_info)*tty_info->nbtty);

	if (!tty_info->pty_info) {
		SYSERROR("failed to allocate pty_info");
		goto out;
	}

	for (i = 0; i < tty_info->nbtty; i++) {

		struct lxc_pty_info *pty_info = &tty_info->pty_info[i];

		if (openpty(&pty_info->master, &pty_info->slave,
			    pty_info->name, NULL, NULL)) {
			SYSERROR("failed to create pty #%d", i);
			goto out_free;
		}

                /* Prevent leaking the file descriptors to the container */
		fcntl(pty_info->master, F_SETFD, FD_CLOEXEC);
		fcntl(pty_info->slave, F_SETFD, FD_CLOEXEC);

		pty_info->busy = 0;
	}

	ret = 0;

	INFO("tty's configured");

out:
	return ret;

out_free:
	free(tty_info->pty_info);
	goto out;
}

void lxc_delete_tty(struct lxc_tty_info *tty_info)
{
	int i;

	for (i = 0; i < tty_info->nbtty; i++) {
		struct lxc_pty_info *pty_info = &tty_info->pty_info[i];

		close(pty_info->master);
		close(pty_info->slave);
	}

	free(tty_info->pty_info);
	tty_info->nbtty = 0;
}

enum { utsname, network, cgroup, fstab, console, tty, rootfs, pts };

static int conf_is_set(long flags, int subsystem)
{
	return flags & (1 << subsystem);
}

static void conf_set_flag(long *flags, int subsystem)
{
	*flags |= 1 << subsystem;
}

static long make_conf_flagset(const char *name, const char *cons,
			      const struct lxc_tty_info *tty_info)
{
	long flags = 0;

	if (conf_has_utsname(name))
		conf_set_flag(&flags, utsname);

	if (conf_has_network(name))
		conf_set_flag(&flags, network);

	if (conf_has_cgroup(name))
		conf_set_flag(&flags, cgroup);

	if (conf_has_fstab(name))
		conf_set_flag(&flags, fstab);

	if (conf_has_rootfs(name))
		conf_set_flag(&flags, rootfs);

	if (conf_has_pts(name))
		conf_set_flag(&flags, pts);

	if (tty_info->nbtty)
		conf_set_flag(&flags, tty);

	if (cons[0])
		conf_set_flag(&flags, console);

	return flags;
}

int lxc_setup(const char *name, const char *cons,
	      const struct lxc_tty_info *tty_info)

{
	/* store the conf flags set otherwise conf_has will not
	 * work after chrooting */
	long flags = make_conf_flagset(name, cons, tty_info);

	if (conf_is_set(flags, utsname) && setup_utsname(name)) {
		ERROR("failed to setup the utsname for '%s'", name);
		return -1;
	}

	if (conf_is_set(flags, network) && setup_network(name)) {
		ERROR("failed to setup the network for '%s'", name);
		return -1;
	}

	if (conf_is_set(flags, cgroup) && setup_cgroup(name)) {
		ERROR("failed to setup the cgroups for '%s'", name);
		return -1;
	}

	if (conf_is_set(flags, fstab) && setup_mount(name)) {
		ERROR("failed to setup the mounts for '%s'", name);
		return -1;
	}

	if (conf_is_set(flags, console) && setup_console(name, cons)) {
		ERROR("failed to setup the console for '%s'", name);
		return -1;
	}

	if (conf_is_set(flags, tty) && setup_tty(name, tty_info)) {
		ERROR("failed to setup the ttys for '%s'", name);
		return -1;
	}

	if (conf_is_set(flags, rootfs) && setup_rootfs(name)) {
		ERROR("failed to set rootfs for '%s'", name);
		return -1;
	}

	if (conf_is_set(flags, pts) && setup_pts(name)) {
		ERROR("failed to setup the new pts instance");
		return -1;
	}

	NOTICE("'%s' is setup.", name);

	return 0;
}
