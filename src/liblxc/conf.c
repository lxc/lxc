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

#include <network.h>
#include <list.h>
#include <conf.h>
#include <log.h>
#include <lxc.h>

#define MAXHWLEN    18
#define MAXINDEXLEN 20
#define MAXLINELEN  128

typedef int (*instanciate_cb)(const char *dirname, 
			      const char *file, pid_t pid);

typedef int (*dir_cb)(const char *name, const char *dirname, 
		      const char *file, void *data);

typedef int (*file_cb)(void* buffer, void *data);

struct netdev_conf {
	const char *type;
	instanciate_cb cb;
	int count;
};

static int instanciate_veth(const char *, const char *, pid_t);
static int instanciate_macvlan(const char *, const char *, pid_t);
static int instanciate_phys(const char *, const char *, pid_t);

static struct netdev_conf netdev_conf[] = {
	{ "veth",    instanciate_veth,    0  },
	{ "macvlan", instanciate_macvlan, 0, },
	{ "phys",    instanciate_phys,    0, },
};

static int dir_filter(const struct dirent *dirent)
{
	if (!strcmp(dirent->d_name, ".") ||
            !strcmp(dirent->d_name, ".."))
                return 0;
        return 1;
}

static int dir_for_each(const char *name, const char *dirname, 
			dir_cb callback, void *data)
{
	struct dirent **namelist;
	int n;
	
	n = scandir(dirname, &namelist, dir_filter, alphasort);
	if (n < 0) {
		lxc_log_syserror("failed to scan %s directory", dirname);
		return -1;
	}
	
	while (n--) {
		if (callback(name, dirname, namelist[n]->d_name, data)) {
			lxc_log_error("callback failed");
			free(namelist[n]);
			return -1;
		}
		free(namelist[n]);
	}

	return 0;
}

static int file_for_each_line(const char *file, file_cb callback, 
			      void *buffer, size_t len, void* data)
{
	FILE *f;
	int err = -1;

	f = fopen(file, "r");
	if (!f) {
		lxc_log_syserror("failed to open %s", file);
		return -1;
	}
	
	while (fgets(buffer, len, f))
		if (callback(buffer, data))
			goto out;
	err = 0;
out:
	fclose(f);
	return err;
}

static int write_info(const char *path, const char *file, const char *info)
{
	int fd, err = -1;
	char *f;

	asprintf(&f, "%s/%s", path, file);
	fd = creat(f, 0755);
	if (fd < 0)
		goto out;

	if (write(fd, info, strlen(info)) < 0 ||
	    write(fd, "\n", strlen("\n") + 1) < 0)
		goto out_write;
	err = 0;
out:
	close(fd);
	free(f);
	return err;

out_write:
	unlink(f);
	goto out;
}

static int read_info(const char *path, const char *file, char *info, size_t len)
{
	int fd, ret = -1;
	char *f, *token;

	asprintf(&f, "%s/%s", path, file);
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
	free(f);
	return ret;
}

static int delete_info(const char *path, const char *file)
{
	char *info;
	int ret;

	asprintf(&info, "%s/%s", path, file);
	ret = unlink(info);
	free(info);

	return ret;
}

static int configure_ip_address(const char *path, struct list *ip, int family)
{
	struct list *iterator;
	char *file = NULL, *line = NULL;
	char addr[INET6_ADDRSTRLEN];
	char bcast[INET_ADDRSTRLEN];
	int fd, err = -1;

	if (mkdir(path, 0755)) {
		lxc_log_syserror("failed to create directory %s", path);
		return -1;
	}

	asprintf(&file, "%s/addresses", path);
	fd = creat(file, 0755);
	if (fd < 0) {
		lxc_log_syserror("failed to create %s file", file);
		goto err;
	}

	if (family == AF_INET) {
		struct inetdev *in;

		list_for_each(iterator, ip) {

			in = iterator->elem;

			if (!inet_ntop(family, &in->addr, addr, sizeof(addr))) {
				lxc_log_syserror("failed to convert ipv4 address");
				goto err;
			}

			if (!inet_ntop(family, &in->bcast, bcast, sizeof(bcast))) {
				lxc_log_syserror("failed to convert ipv4 broadcast");
				goto err;
			}


			if (in->prefix)
				asprintf(&line, "%s/%d %s\n", addr, 
					 in->prefix, bcast);
			else
				asprintf(&line, "%s %s\n", addr, bcast);

			if (write(fd, line, strlen(line)) < 0) {
				lxc_log_syserror("failed to write address info");
				goto err;
			}
		}
	} else {
		struct inet6dev *in6;

		list_for_each(iterator, ip) {

			in6 = iterator->elem;

			if (!inet_ntop(family, &in6->addr, addr, sizeof(addr))) {
				lxc_log_syserror("failed to convert ipv4 address");
				goto err;
			}

			asprintf(&line, "%s/%d\n", addr,
				 in6->prefix?in6->prefix:64);

			if (write(fd, line, strlen(line)) < 0) {
				lxc_log_syserror("failed to write address info to %s", 
						 file);
				goto err;
			}
		}
	}

	err = 0;
out:
	free(file);
	free(line);
	close(fd);
	return err;
err:
	unlink(file);
	rmdir(path);
	goto out;
}

static int configure_netdev(const char *path, struct netdev *netdev)
{
	int err = -1;
	char dir[MAXPATHLEN];

	if (mkdir(path, 0755)) {
		lxc_log_syserror("failed to create %s directory", path);
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
			goto out_up;
	}

	if (netdev->flags & IFF_UP) {
		if (write_info(path, "up", ""))
			goto out_hwaddr;
	}

	if (!list_empty(&netdev->ipv4)) {
		snprintf(dir, MAXPATHLEN, "%s/ipv4", path);
		if (configure_ip_address(dir, &netdev->ipv4, AF_INET))
			goto out_ipv4;
	}

	if (!list_empty(&netdev->ipv6)) {
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
out_hwaddr:
	delete_info(path, "hwaddr");
out_up:
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

	if (!utsname)
		return 0;

	snprintf(path, MAXPATHLEN, LXCPATH "/%s", name);
	if (write_info(path, "utsname", utsname->nodename)) {
		lxc_log_error("failed to write the utsname info");
		return -1;
	}

	return 0;
}

static int configure_network(const char *name, struct list *network)
{
	struct list *iterator;
	struct network *n;
	char *networkpath = NULL, *path = NULL;
	int err = -1;
	
	if (list_empty(network))
		return 0;
	
	asprintf(&networkpath, LXCPATH "/%s/network", name);
	if (mkdir(networkpath, 0755)) {
		lxc_log_syserror("failed to create %s directory", networkpath);
		goto out;
	}

 	list_for_each(iterator, network) {

		n = iterator->elem;

		if (n->type < 0 || n->type > MAXCONFTYPE) {
			lxc_log_error("invalid network configuration type %d",
				      n->type);
			goto out;
		}

		asprintf(&path, "%s/%s%d", networkpath,
			 netdev_conf[n->type].type, netdev_conf[n->type].count++);

		if (configure_netdev(path, list_first_elem(&n->netdev))) {
			lxc_log_error("failed to configure network type %s", 
				      netdev_conf[n->type].type);
			goto out;
		}
	}

	err = 0;
out:
	free(path);
	free(networkpath);
	return err;
}

static int configure_cgroup(const char *name, struct cgroup *cgroup)
{
	if (!cgroup)
		return 0;
	return 0;
}

static int configure_chroot(const char *name, const char *chroot)
{
	int ret;
	char *path;

	if (!chroot)
		return 0;

	asprintf(&path, LXCPATH "/%s/chroot", name);
	ret = symlink(chroot, path);
	free(path);

	return ret;
}

static int configure_mount(const char *name, const char *fstab)
{
	char *path;
	struct stat stat;
	int infd, outfd;
	void *src, *dst;
	char c = '\0';
	int ret = -1;

	if (!fstab)
		return 0;

	asprintf(&path, LXCPATH "/%s/fstab", name);

	outfd = open(path, O_RDWR|O_CREAT|O_EXCL, 0640);
	if (outfd < 0) {
		lxc_log_syserror("failed to creat '%s'", path);
		goto out;
	}
	
	infd = open(fstab, O_RDONLY);
	if (infd < 0) {
		lxc_log_syserror("failed to open '%s'", fstab);
		goto out;
	}

	if (fstat(infd, &stat)) {
		lxc_log_syserror("failed to stat '%s'", fstab);
		goto out;
	}

	if (lseek(outfd, stat.st_size - 1, SEEK_SET) < 0) {
		lxc_log_syserror("failed to seek dest file '%s'", path);
		goto out;
	}

	/* fixup length */
	if (write(outfd, &c, 1) < 0) {
		lxc_log_syserror("failed to write to '%s'", path);
		goto out;
	}

	src = mmap(NULL, stat.st_size, PROT_READ, MAP_SHARED, infd, 0L);
	if (src == MAP_FAILED) {
		lxc_log_syserror("failed to mmap '%s'", fstab);
		goto out;
	}

	dst = mmap(NULL, stat.st_size, PROT_WRITE, MAP_SHARED, outfd, 0L);
	if (dst == MAP_FAILED) {
		lxc_log_syserror("failed to mmap '%s'", path);
		goto out;
	}

	memcpy(dst, src, stat.st_size);

	munmap(src, stat.st_size);
	munmap(dst, stat.st_size);

	ret = 0;
out:
	free(path);
	return ret;
}

static int unconfigure_ip_addresses(const char *dirname)
{
	char path[MAXPATHLEN];

	snprintf(path, MAXPATHLEN, "%s/ipv4", dirname);
	delete_info(path, "addresses");
	rmdir(path);

	snprintf(path, MAXPATHLEN, "%s/ipv6", dirname);
	delete_info(path, "addresses");
	rmdir(path);

	return 0;
}

static int unconfigure_network_cb(const char *name, const char *dirname, 
				  const char *file, void *data)
{
	char *path;

	asprintf(&path, "%s/%s", dirname, file);
	delete_info(path, "name");
	delete_info(path, "addr");
	delete_info(path, "link");
	delete_info(path, "hwaddr");
	delete_info(path, "up");
	unconfigure_ip_addresses(path);
	rmdir(path);
	free(path);

	return 0;
}

static int unconfigure_network(const char *name)
{
	char *dirname;

	if (!conf_has_network(name))
		return 0;

	asprintf(&dirname, LXCPATH "/%s/network", name);
	dir_for_each(name, dirname, unconfigure_network_cb, NULL);
	rmdir(dirname);
	free(dirname);

	return 0;
}

static int unconfigure_cgroup(const char *name)
{
	return 0;
}

static int unconfigure_chroot(const char *name)
{
	char *path;

	asprintf(&path, LXCPATH "/%s", name);
	delete_info(path, "chroot");
	free(path);

	return 0;
}

static int unconfigure_mount(const char *name)
{
	char *path;
	
	if (!conf_has_fstab(name))
		return 0;

	asprintf(&path, LXCPATH "/%s", name);
	delete_info(path, "fstab");
	free(path);

	return 0;
}

static int unconfigure_utsname(const char *name)
{
	char *path;

	if (!conf_has_utsname(name))
		return 0;

	asprintf(&path, LXCPATH "/%s", name);
	delete_info(path, "utsname");
	free(path);

	return 0;
}

static int setup_utsname(const char *name)
{
	int ret;
	char *path;
	struct utsname utsname;

	if (!conf_has_utsname(name))
		return 0;

	asprintf(&path, LXCPATH "/%s", name);

	ret = read_info(path, "utsname", utsname.nodename, 
			sizeof(utsname.nodename));
	if (ret < 0) {
		lxc_log_syserror("failed to read utsname info");
		goto out;
	}

	if (!ret && sethostname(utsname.nodename, strlen(utsname.nodename))) {
		lxc_log_syserror("failed to set the hostname to '%s'",
				 utsname.nodename);
		goto out;
	}
	
	ret = 0;
out:
	free(path);
	return ret;
}

static int setup_chroot(const char *name)
{
	char *path, chrt[MAXPATHLEN];
	int ret = -1;

	asprintf(&path, LXCPATH "/%s/chroot", name);

	if (readlink(path, chrt, MAXPATHLEN) > 0) {
		if (chroot(chrt)) {
			lxc_log_syserror("failed to set chroot %s", path);
			goto out;
		}
		if (chdir(getenv("HOME")) && chdir("/")) {
			lxc_log_syserror("failed to change to home directory");
			goto out;
		}
	}

	ret = 0;
out:
	free(path);
	return ret;
}

static int setup_mount(const char *name)
{
	char *path;
	struct mntent *mntent;
	FILE *file;
	int ret = -1;

	if (!conf_has_fstab(name))
		return 0;

	asprintf(&path, LXCPATH "/%s/fstab", name);

	file = setmntent(path, "r");
	if (!file) {
		if (errno == ENOENT)
			return 0;
		lxc_log_syserror("failed to open '%s'", path);
		goto out;
	}

	while((mntent = getmntent(file))) {
		if (mount(mntent->mnt_fsname, mntent->mnt_dir,
			  mntent->mnt_type, 0, NULL)) {
			lxc_log_syserror("failed to mount '%s' on '%s'",
					 mntent->mnt_fsname, mntent->mnt_dir);
			goto out;
		}
	}
	ret = 0;
out:
	free(path);
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
	
	if (ip_addr_add(ifname, addr, p, bcast)) {
		lxc_log_error("failed to set %s to addr %s/%d %s", ifname,
			      addr, p, bcast?bcast:"");
		return -1;
	}

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
	
	if (ip6_addr_add(ifname, addr, p, bcast)) {
		lxc_log_error("failed to set %s to addr %s/%d %s", ifname,
			      addr, p, bcast?bcast:"");
		return -1;
	}

	return 0;
}

static int setup_hw_addr(char *hwaddr, const char *ifname)
{
	struct sockaddr sockaddr;
	struct ifreq ifr;
	int ret, fd;

	if (lxc_convert_mac(hwaddr, &sockaddr)) {
		fprintf(stderr, "conversion has failed\n");
		return -1;
	}

	memcpy(ifr.ifr_name, ifname, IFNAMSIZ);
	memcpy((char *) &ifr.ifr_hwaddr, (char *) &sockaddr, sizeof(sockaddr));

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		return -1;
	}

	ret = ioctl(fd, SIOCSIFHWADDR, &ifr);
	close(fd);
	if (ret)
		perror("ioctl");

	return ret;
}

static int setup_ip_addr(const char *dirname, const char *ifname)
{
	char *path, line[MAXLINELEN];
	struct stat s;
	int ret = 0;

	asprintf(&path, "%s/ipv4/addresses", dirname);
	if (!stat(path, &s))
		ret = file_for_each_line(path, setup_ipv4_addr_cb, 
					 line, MAXPATHLEN, (void*)ifname);
	free(path);

	return ret;
}

static int setup_ip6_addr(const char *dirname, const char *ifname)
{
	char *path, line[MAXLINELEN];
	struct stat s;
	int ret = 0;

	asprintf(&path, "%s/ipv6/addresses", dirname);
	if (!stat(path, &s))
		ret = file_for_each_line(path, setup_ipv6_addr_cb, 
					 line, MAXPATHLEN, (void*)ifname);
	free(path);

	return ret;
}

static int setup_network_cb(const char *name, const char *dirname, 
			    const char *file, void *data)
{
	char *path;
	char strindex[MAXINDEXLEN];
	char ifname[IFNAMSIZ];
	char newname[IFNAMSIZ];
	char hwaddr[MAXHWLEN];
	char *current_ifname = ifname;
	int ifindex, ret = -1;

	asprintf(&path, "%s/%s", dirname, file);

	if (read_info(path, "ifindex", strindex, sizeof(strindex))) {
		lxc_log_error("failed to read ifindex info");
		goto out;
	}
	
	ifindex = atoi(strindex);
	if (!ifindex) {
		lxc_log_error("bad index %s", strindex);
		goto out;
	}
	
	if (!if_indextoname(ifindex, current_ifname)) {
		lxc_log_error("no interface corresponding to index '%d'",
			      ifindex);
		goto out;
	}
	
	if (!read_info(path, "name", newname, sizeof(newname))) {
		if (device_rename(ifname, newname)) {
			lxc_log_error("failed to rename %s->%s", 
				      ifname, newname);
			goto out;
		}
		current_ifname = newname;
	}

	if (!read_info(path, "hwaddr", hwaddr, sizeof(hwaddr))) {
		if (setup_hw_addr(hwaddr, current_ifname)) {
			lxc_log_error("failed to setup hw address for '%s'", 
				      current_ifname);
			goto out;
		}
	}

	if (setup_ip_addr(path, current_ifname)) {
		lxc_log_error("failed to setup ip addresses for '%s'",
			      ifname);
		goto out;
	}

	if (setup_ip6_addr(path, current_ifname)) {
		lxc_log_error("failed to setup ipv6 addresses for '%s'",
			      ifname);
		goto out;
	}

	if (!read_info(path, "up", strindex, sizeof(strindex))) {
		if (device_up(current_ifname)) {
			lxc_log_error("failed to set '%s' up", current_ifname);
			goto out;
		}

		/* the network is up, make the loopback up too */
		if (device_up("lo")) {
			lxc_log_error("failed to set the loopback up");
			goto out;
		}
	}

	ret = 0;
out:
	return ret;
}

static int setup_network(const char *name)
{
	char *dirname;
	int ret = -1;

	if (!conf_has_network(name))
		return 0;

	asprintf(&dirname, LXCPATH "/%s/network", name);
	ret = dir_for_each(name, dirname, setup_network_cb, NULL);
	free(dirname);
	return ret;
}

int conf_has(const char *name, const char *info)
{
	int ret;
	char *path;
	struct stat st;

	asprintf(&path, LXCPATH "/%s/%s", name, info);

	ret = stat(path, &st);
	if (!ret) {
		ret = 1;
		goto out;
	}

	if (errno == ENOENT) {
		ret = 0;
		goto out;
	}

	lxc_log_syserror("failed to stat %s info", info);
out:
	free(path);
	return ret;
}

int lxc_configure(const char *name, struct lxc_conf *conf)
{
	if (!conf)
		return 0;

	if (configure_utsname(name, conf->utsname)) {
		lxc_log_error("failed to configure the utsname");
		return -1;
	}

	if (configure_network(name, &conf->networks)) {
		lxc_log_error("failed to configure the network");
		return -1;
	}

	if (configure_cgroup(name, conf->cgroup)) {
		lxc_log_error("failed to configure the control group");
		return -1;
	}

	if (configure_chroot(name, conf->chroot)) {
		lxc_log_error("failed to configure the chroot");
		return -1;
	}

	if (configure_mount(name, conf->fstab)) {
		lxc_log_error("failed to configure the mount points");
		return -1;
	}

	return 0;
}

int lxc_unconfigure(const char *name)
{
	if (unconfigure_utsname(name))
		lxc_log_error("failed to cleanup utsname");
	
	if (unconfigure_network(name))
		lxc_log_error("failed to cleanup the network");

	if (unconfigure_cgroup(name))
		lxc_log_error("failed to cleanup cgroup");

	if (unconfigure_chroot(name))
		lxc_log_error("failed to cleanup chroot");

	if (unconfigure_mount(name))
		lxc_log_error("failed to cleanup mount");

	return 0;
}

static int instanciate_veth(const char *dirname, const char *file, pid_t pid)
{
	char *path = NULL, *strindex = NULL, *veth1 = NULL, *veth2 = NULL;
	char bridge[IFNAMSIZ];
	int ifindex, ret = -1;
			
	asprintf(&veth1, "%s_%d", file, pid);
	asprintf(&veth2, "%s~%d", file, pid);
	asprintf(&path, "%s/%s", dirname, file);
	
	if (read_info(path, "link", bridge, IFNAMSIZ)) {
		lxc_log_error("failed to read bridge info");
		goto out;
	}

	if (lxc_configure_veth(veth1, veth2, bridge)) {
		lxc_log_error("failed to create %s-%s/%s", veth1, veth2, bridge);
		goto out;
	}
	
	ifindex = if_nametoindex(veth2);
	if (!ifindex) {
		lxc_log_error("failed to retrieve the index for %s", veth2);
		goto out;
	}
	
	asprintf(&strindex, "%d", ifindex);
	if (write_info(path, "ifindex", strindex)) {
		lxc_log_error("failed to write interface index to %s", path);
		goto out;
	}

	if (!read_info(path, "up", strindex, sizeof(strindex))) {
		if (device_up(veth1)) {
			lxc_log_error("failed to set %s up", veth1);
			goto out;
		}
	}

	ret = 0;
out:
	free(path);
	free(strindex);
	free(veth1);
	free(veth2);
	return ret;
} 
static int instanciate_macvlan(const char *dirname, const char *file, pid_t pid)
{
	char *path = NULL, *strindex = NULL, *peer = NULL;
	char link[IFNAMSIZ]; 
	int ifindex, ret = -1;
			
	asprintf(&peer, "%s~%d", file, pid);
	asprintf(&path, "%s/%s", dirname, file);
	if (read_info(path, "link", link, IFNAMSIZ)) {
		lxc_log_error("failed to read bridge info");
		goto out;
	}

	if (lxc_configure_macvlan(link, peer)) {
		lxc_log_error("failed to create macvlan interface %s", peer);
		goto out;
	}

	ifindex = if_nametoindex(peer);
	if (!ifindex) {
		lxc_log_error("failed to retrieve the index for %s", peer);
		goto out;
	}

	asprintf(&strindex, "%d", ifindex);
	if (write_info(path, "ifindex", strindex)) {
		lxc_log_error("failed to write interface index to %s", path);
		goto out;
	}

	ret = 0;
out:
	free(path);
	free(strindex);
	free(peer);
	return ret;
}

static int instanciate_phys(const char *dirname, const char *file, pid_t pid)
{
	char *path = NULL, *strindex = NULL;
	char link[IFNAMSIZ];
	int ifindex, ret = -1;

	asprintf(&path, "%s/%s", dirname, file);
	if (read_info(path, "link", link, IFNAMSIZ)) {
		lxc_log_error("failed to read link info");
		goto out;
	}

	ifindex = if_nametoindex(link);
	if (!ifindex) {
		lxc_log_error("failed to retrieve the index for %s", link);
		goto out;
	}

	asprintf(&strindex, "%d", ifindex);
	if (write_info(path, "ifindex", strindex)) {
		lxc_log_error("failed to write interface index to %s", path);
		goto out;
	}

	ret = 0;
out:
	free(path);
	free(strindex);
	return ret;
}

static int instanciate_netdev_cb(const char *name, const char *dirname, 
				 const char *file, void *data)
{
	pid_t *pid = data;

	if (!strncmp("veth", file, strlen("veth")))
		return instanciate_veth(dirname, file, *pid);
	else if (!strncmp("macvlan", file, strlen("macvlan")))
		return instanciate_macvlan(dirname, file, *pid);
	else if (!strncmp("phys", file, strlen("phys")))
		return instanciate_phys(dirname, file, *pid);

	return -1;
}

static int instanciate_netdev(const char *name, pid_t pid)
{
	char *dirname;
	int ret;

	asprintf(&dirname, LXCPATH "/%s/network", name);
	ret =  dir_for_each(name, dirname, instanciate_netdev_cb, &pid);
	free(dirname);

	return ret;
}

static int move_netdev_cb(const char *name, const char *dirname, 
			  const char *file, void *data)
{
	char *path, ifname[IFNAMSIZ], strindex[MAXINDEXLEN];
	pid_t *pid = data;
	int ifindex, ret = -1;

	asprintf(&path, "%s/%s", dirname, file);
	if (read_info(path, "ifindex", strindex, MAXINDEXLEN) < 0) {
		lxc_log_error("failed to read index to from %s", path);
		goto out;
	}
	
	ifindex = atoi(strindex);
	if (!if_indextoname(ifindex, ifname)) {
		lxc_log_error("interface with index %d does not exist",
			      ifindex);
		goto out;
	}
	
	if (device_move(ifname, *pid)) {
		lxc_log_error("failed to move %s to %d", ifname, *pid);
		goto out;
	}

	ret = 0;
out:
	free(path);
	return ret;
}

static int move_netdev(const char *name, pid_t pid)
{
	char *dirname;
	int ret;

	asprintf(&dirname, LXCPATH "/%s/network", name);
	ret = dir_for_each(name, dirname, move_netdev_cb, &pid);
	free(dirname);

	return ret;
}

int conf_create_network(const char *name, pid_t pid)
{
	if (instanciate_netdev(name, pid)) {
		lxc_log_error("failed to instantiate the network devices");
		return -1;
	}

	if (move_netdev(name, pid)) {
		lxc_log_error("failed to move the netdev to the container");
		return -1;
	}

	return 0;
}

static int delete_netdev_cb(const char *name, const char *dirname, 
			    const char *file, void *data)
{
	char strindex[MAXINDEXLEN];
	char path[MAXPATHLEN];
	char ifname[IFNAMSIZ];
	int i, ifindex;
	
	snprintf(path, MAXPATHLEN, "%s/%s", dirname, file);
	
	if (read_info(path, "ifindex", strindex, MAXINDEXLEN)) {
		lxc_log_error("failed to read ifindex info");
		return -1;
	}
		
	ifindex = atoi(strindex);
	if (!ifindex) {
		lxc_log_error("bad index %s", strindex);
		return -1;
	}

	/* TODO : temporary code - needs wait on namespace */
	for (i = 0; i < 120; i++) {
		if (if_indextoname(ifindex, ifname))
			break;
		if (!i)
			printf("waiting for interface #%d to come back\n", ifindex);
		else
			printf("."); fflush(stdout);
		sleep(1);
	}

	/* do not delete a physical network device */
	if (strncmp("phys", file, strlen("phys")))
		if (device_delete(ifname)) {
			lxc_log_error("failed to remove the netdev %s", ifname);
		}

	delete_info(path, "ifindex");

	return 0;
}

static int delete_netdev(const char *name)
{
	char *dirname;
	int ret;

	asprintf(&dirname, LXCPATH "/%s/network", name);
	ret = dir_for_each(name, dirname, delete_netdev_cb, NULL);
	free(dirname);

	return ret;
}

int conf_destroy_network(const char *name)
{
	if (delete_netdev(name)) {
		lxc_log_error("failed to remove the network devices");
		return -1;
	}

	return 0;
}

int lxc_setup(const char *name)
{
	if (setup_utsname(name)) {
		lxc_log_error("failed to setup the utsname for '%s'", name);
		return -1;
	}

	if (setup_network(name)) {
		lxc_log_error("failed to setup the network for '%s'", name);
		return -1;
	}

	if (setup_mount(name)) {
		lxc_log_error("failed to setup the mount points for '%s'", name);
		return -1;
	}

	if (setup_chroot(name)) {
		lxc_log_error("failed to set chroot for '%s'", name);
		return -1;
	}

	return 0;
}
