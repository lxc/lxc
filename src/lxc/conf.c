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
#include "config.h"

#include <lxc/conf.h>
#include <lxc/log.h>
#include <lxc/lxc.h>	/* for lxc_cgroup_set() */

lxc_log_define(lxc_conf, lxc);

#define MAXHWLEN    18
#define MAXINDEXLEN 20
#define MAXMTULEN   16
#define MAXLINELEN  128

#ifndef MS_REC
#define MS_REC 16384
#endif

typedef int (*instanciate_cb)(struct lxc_netdev *);

struct mount_opt {
	char *name;
	int clear;
	int flag;
};

static int instanciate_veth(struct lxc_netdev *);
static int instanciate_macvlan(struct lxc_netdev *);
static int instanciate_phys(struct lxc_netdev *);
static int instanciate_empty(struct lxc_netdev *);

static  instanciate_cb netdev_conf[MAXCONFTYPE + 1] = {
	[VETH]    = instanciate_veth,
	[MACVLAN] = instanciate_macvlan,
	[PHYS]    = instanciate_phys,
	[EMPTY]   = instanciate_empty,
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

static int setup_utsname(struct utsname *utsname)
{
	if (!utsname)
		return 0;

	if (sethostname(utsname->nodename, strlen(utsname->nodename))) {
		SYSERROR("failed to set the hostname to '%s'", utsname->nodename);
		return -1;
	}

	INFO("'%s' hostname has been setup", utsname->nodename);

	return 0;
}

static int setup_tty(const char *rootfs, const struct lxc_tty_info *tty_info)
{
	char path[MAXPATHLEN];
	int i;

	for (i = 0; i < tty_info->nbtty; i++) {

		struct lxc_pty_info *pty_info = &tty_info->pty_info[i];

		snprintf(path, sizeof(path), "%s/dev/tty%d",
			 rootfs ? rootfs : "", i + 1);

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

static int setup_rootfs(const char *rootfs)
{
	char *tmpname;
	int ret = -1;

	if (!rootfs)
		return 0;

	tmpname = tempnam("/tmp", "lxc-rootfs");
	if (!tmpname) {
		SYSERROR("failed to generate temporary name");
		return -1;
	}

	if (mkdir(tmpname, 0700)) {
		SYSERROR("failed to create temporary directory '%s'", tmpname);
		return -1;
	}

	if (mount(rootfs, tmpname, "none", MS_BIND|MS_REC, NULL)) {
		SYSERROR("failed to mount '%s'->'%s'", rootfs, tmpname);
		goto out;
	}

	if (chroot(tmpname)) {
		SYSERROR("failed to set chroot %s", tmpname);
		goto out;
	}

	if (chdir(getenv("HOME")) && chdir("/")) {
		SYSERROR("failed to change to home directory");
		goto out;
	}

	INFO("chrooted to '%s'", rootfs);

	ret = 0;
out:
	rmdir(tmpname);
	return ret;
}

static int setup_pts(int pts)
{
	if (!pts)
		return 0;

	if (!access("/dev/pts/ptmx", F_OK) && umount("/dev/pts")) {
		SYSERROR("failed to umount 'dev/pts'");
		return -1;
	}

	if (mount("devpts", "/dev/pts", "devpts", MS_MGC_VAL, "newinstance")) {
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

static int setup_console(const char *rootfs, const char *tty)
{
	char console[MAXPATHLEN];

	snprintf(console, sizeof(console), "%s/dev/console",
		 rootfs ? rootfs : "");

	/* we have the rootfs with /dev/console but no tty
	 * to be used as console, let's remap /dev/console
	 * to /dev/null to avoid to log to the system console
	 */
	if (rootfs && !tty[0]) {

		if (!access(console, F_OK)) {

			if (mount("/dev/null", console, "none", MS_BIND, 0)) {
				SYSERROR("failed to mount '/dev/null'->'%s'",
					 console);
				return -1;
			}
		}
	}

	if (!tty[0])
		return 0;

	if (access(console, R_OK|W_OK))
		return 0;

	if (mount(tty, console, "none", MS_BIND, 0)) {
		ERROR("failed to mount the console");
		return -1;
	}

	INFO("console '%s' mounted to '%s'", tty, console);

	return 0;
}

static int setup_cgroup(const char *name, struct lxc_list *cgroups)
{
	struct lxc_list *iterator;
	struct lxc_cgroup *cg;
	int ret = -1;

	if (lxc_list_empty(cgroups))
		return 0;

	lxc_list_for_each(iterator, cgroups) {

		cg = iterator->elem;

		if (lxc_cgroup_set(name, cg->subsystem, cg->value))
			goto out;

		DEBUG("cgroup '%s' set to '%s'", cg->subsystem, cg->value);
	}

	ret = 0;
	INFO("cgroup has been setup");
out:
	return ret;
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

static int mount_file_entries(FILE *file)
{
	struct mntent *mntent;
	int ret = -1;
	unsigned long mntflags;
	char *mntdata;

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
	return ret;
}

static int setup_mount(const char *fstab)
{
	FILE *file;
	int ret;

	if (!fstab)
		return 0;

	file = setmntent(fstab, "r");
	if (!file) {
		SYSERROR("failed to use '%s'", fstab);
		return -1;
	}

	ret = mount_file_entries(file);

	endmntent(file);
	return ret;
}

static int setup_mount_entries(struct lxc_list *mount)
{
	FILE *file;
	struct lxc_list *iterator;
	char *mount_entry;
	int ret;

	file = tmpfile();
	if (!file) {
		ERROR("tmpfile error: %m");
		return -1;
	}

	lxc_list_for_each(iterator, mount) {
		mount_entry = iterator->elem;
		fprintf(file, "%s", mount_entry);
	}

	rewind(file);

	ret = mount_file_entries(file);

	fclose(file);
	return ret;
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

static int setup_ipv4_addr(struct lxc_list *ip, int ifindex)
{
	struct lxc_list *iterator;
	struct lxc_inetdev *inetdev;

	lxc_list_for_each(iterator, ip) {

		inetdev = iterator->elem;

		if (lxc_ip_addr_add(AF_INET, ifindex,
				    &inetdev->addr, inetdev->prefix)) {
			return -1;
		}
	}

	return 0;
}

static int setup_ipv6_addr(struct lxc_list *ip, int ifindex)
{
	struct lxc_list *iterator;
	struct lxc_inet6dev *inet6dev;

	lxc_list_for_each(iterator, ip) {

		inet6dev = iterator->elem;

		if (lxc_ip_addr_add(AF_INET6, ifindex,
				    & inet6dev->addr, inet6dev->prefix))
			return -1;
	}

	return 0;
}

static int setup_netdev(struct lxc_netdev *netdev)
{
	char ifname[IFNAMSIZ];
	char *current_ifname = ifname;

	/* empty network namespace */
	if (!netdev->ifindex) {
		if (netdev->flags | IFF_UP) {
			if (lxc_device_up("lo")) {
				ERROR("failed to set the loopback up");
				return -1;
			}
			return 0;
		}
	}

	/* retrieve the name of the interface */
	if (!if_indextoname(netdev->ifindex, current_ifname)) {
		ERROR("no interface corresponding to index '%d'",
		      netdev->ifindex);
		return -1;
	}

	/* default: let the system to choose one interface name */
	if (!netdev->name)
		netdev->name = "eth%d";

	/* rename the interface name */
	if (lxc_device_rename(ifname, netdev->name)) {
		ERROR("failed to rename %s->%s", ifname, current_ifname);
		return -1;
	}

	/* Re-read the name of the interface because its name has changed
	 * and would be automatically allocated by the system
	 */
	if (!if_indextoname(netdev->ifindex, current_ifname)) {
		ERROR("no interface corresponding to index '%d'",
		      netdev->ifindex);
		return -1;
	}

	/* set a mac address */
	if (netdev->hwaddr) {
		if (setup_hw_addr(netdev->hwaddr, current_ifname)) {
			ERROR("failed to setup hw address for '%s'",
			      current_ifname);
			return -1;
		}
	}

	/* setup ipv4 addresses on the interface */
	if (setup_ipv4_addr(&netdev->ipv4, netdev->ifindex)) {
		ERROR("failed to setup ip addresses for '%s'",
			      ifname);
		return -1;
	}

	/* setup ipv6 addresses on the interface */
	if (setup_ipv6_addr(&netdev->ipv6, netdev->ifindex)) {
		ERROR("failed to setup ipv6 addresses for '%s'",
			      ifname);
		return -1;
	}

	/* set the network device up */
	if (netdev->flags | IFF_UP) {
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

static int setup_network(struct lxc_list *network)
{
	struct lxc_list *iterator;
	struct lxc_netdev *netdev;

	lxc_list_for_each(iterator, network) {

		netdev = iterator->elem;

		if (setup_netdev(netdev)) {
			ERROR("failed to setup netdev");
			return -1;
		}
	}

	if (!lxc_list_empty(network))
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
	conf->console[0] = '\0';
	lxc_list_init(&conf->cgroup);
	lxc_list_init(&conf->network);
	lxc_list_init(&conf->mount_list);
	return 0;
}

static int instanciate_veth(struct lxc_netdev *netdev)
{
	char veth1[IFNAMSIZ];
	char veth2[IFNAMSIZ];
	int ret = -1;

	snprintf(veth1, sizeof(veth1), "vethXXXXXX");
	snprintf(veth2, sizeof(veth2), "vethXXXXXX");

	mktemp(veth1);
	mktemp(veth2);

	if (!strlen(veth1) || !strlen(veth2)) {
		ERROR("failed to allocate a temporary name");
		return -1;
	}

	if (lxc_veth_create(veth1, veth2)) {
		ERROR("failed to create %s-%s", veth1, veth2);
		goto out;
	}

	if (netdev->mtu) {
		if (lxc_device_set_mtu(veth1, atoi(netdev->mtu))) {
			ERROR("failed to set mtu '%s' for '%s'",
			      netdev->mtu, veth1);
			goto out_delete;
		}

		if (lxc_device_set_mtu(veth2, atoi(netdev->mtu))) {
			ERROR("failed to set mtu '%s' for '%s'",
			      netdev->mtu, veth2);
			goto out_delete;
		}
	}

	if (netdev->link && lxc_bridge_attach(netdev->link, veth1)) {
		ERROR("failed to attach '%s' to the bridge '%s'",
			      veth1, netdev->link);
		goto out_delete;
	}

	netdev->ifindex = if_nametoindex(veth2);
	if (!netdev->ifindex) {
		ERROR("failed to retrieve the index for %s", veth2);
		goto out_delete;
	}

	if (netdev->flags & IFF_UP) {
		if (lxc_device_up(veth1)) {
			ERROR("failed to set %s up", veth1);
			goto out_delete;
		}
	}

	DEBUG("instanciated veth '%s/%s', index is '%d'",
	      veth1, veth2, netdev->ifindex);

	ret = 0;
out:
	return ret;

out_delete:
	lxc_device_delete(veth1);
	goto out;
}

static int instanciate_macvlan(struct lxc_netdev *netdev)
{
	char peer[IFNAMSIZ];

	if (!netdev->link) {
		ERROR("no link specified for macvlan netdev");
		return -1;
	}

	snprintf(peer, sizeof(peer), "mcXXXXXX");

	mktemp(peer);

	if (!strlen(peer)) {
		ERROR("failed to make a temporary name");
		return -1;
	}

	if (lxc_macvlan_create(netdev->link, peer)) {
		ERROR("failed to create macvlan interface '%s' on '%s'",
		      peer, netdev->link);
		return -1;
	}

	netdev->ifindex = if_nametoindex(peer);
	if (!netdev->ifindex) {
		ERROR("failed to retrieve the index for %s", peer);
		lxc_device_delete(peer);
		return -1;
	}

	DEBUG("instanciated macvlan '%s', index is '%d'", peer, netdev->ifindex);

	return 0;
}

static int instanciate_phys(struct lxc_netdev *netdev)
{
	netdev->ifindex = if_nametoindex(netdev->link);
	if (!netdev->ifindex) {
		ERROR("failed to retrieve the index for %s", netdev->link);
		return -1;
	}

	return 0;
}

static int instanciate_empty(struct lxc_netdev *netdev)
{
	netdev->ifindex = 0;
	return 0;
}

int lxc_create_network(struct lxc_list *network)
{
	struct lxc_list *iterator;
	struct lxc_netdev *netdev;

	lxc_list_for_each(iterator, network) {

		netdev = iterator->elem;

		if (netdev->type < 0 || netdev->type > MAXCONFTYPE) {
			ERROR("invalid network configuration type '%d'",
			      netdev->type);
			return -1;
		}

		if (netdev_conf[netdev->type](netdev)) {
			ERROR("failed to create netdev");
			return -1;
		}
	}

	return 0;
}

int lxc_assign_network(struct lxc_list *network, pid_t pid)
{
	struct lxc_list *iterator;
	struct lxc_netdev *netdev;

	lxc_list_for_each(iterator, network) {

		netdev = iterator->elem;

		if (lxc_device_move(netdev->ifindex, pid)) {
			ERROR("failed to move '%s' to the container",
			      netdev->link);
			return -1;
		}

		DEBUG("move '%s' to '%d'", netdev->link, pid);
	}

	return 0;
}

int lxc_create_tty(const char *name, struct lxc_conf *conf)
{
	struct lxc_tty_info *tty_info = &conf->tty_info;
	int i;

	/* no tty in the configuration */
	if (!conf->tty)
		return 0;

	tty_info->pty_info =
		malloc(sizeof(*tty_info->pty_info)*tty_info->nbtty);
	if (!tty_info->pty_info) {
		SYSERROR("failed to allocate pty_info");
		return -1;
	}

	for (i = 0; i < conf->tty; i++) {

		struct lxc_pty_info *pty_info = &tty_info->pty_info[i];

		if (openpty(&pty_info->master, &pty_info->slave,
			    pty_info->name, NULL, NULL)) {
			SYSERROR("failed to create pty #%d", i);
			tty_info->nbtty = i;
			lxc_delete_tty(tty_info);
			return -1;
		}

                /* Prevent leaking the file descriptors to the container */
		fcntl(pty_info->master, F_SETFD, FD_CLOEXEC);
		fcntl(pty_info->slave, F_SETFD, FD_CLOEXEC);

		pty_info->busy = 0;
	}

	tty_info->nbtty = conf->tty;

	INFO("tty's configured");

	return 0;
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

int lxc_setup(const char *name, struct lxc_conf *lxc_conf)
{
	if (setup_utsname(lxc_conf->utsname)) {
		ERROR("failed to setup the utsname for '%s'", name);
		return -1;
	}

	if (setup_network(&lxc_conf->network)) {
		ERROR("failed to setup the network for '%s'", name);
		return -1;
	}

	if (setup_cgroup(name, &lxc_conf->cgroup)) {
		ERROR("failed to setup the cgroups for '%s'", name);
		return -1;
	}

	if (setup_mount(lxc_conf->fstab)) {
		ERROR("failed to setup the mounts for '%s'", name);
		return -1;
	}

	if (setup_mount_entries(&lxc_conf->mount_list)) {
		ERROR("failed to setup the mount entries for '%s'", name);
		return -1;
	}

	if (setup_console(lxc_conf->rootfs, lxc_conf->console)) {
		ERROR("failed to setup the console for '%s'", name);
		return -1;
	}

	if (setup_tty(lxc_conf->rootfs, &lxc_conf->tty_info)) {
		ERROR("failed to setup the ttys for '%s'", name);
		return -1;
	}

	if (setup_rootfs(lxc_conf->rootfs)) {
		ERROR("failed to set rootfs for '%s'", name);
		return -1;
	}

	if (setup_pts(lxc_conf->pts)) {
		ERROR("failed to setup the new pts instance");
		return -1;
	}

	NOTICE("'%s' is setup.", name);

	return 0;
}
