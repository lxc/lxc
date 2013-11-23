/*
 *
 * Copyright © 2013 Serge Hallyn <serge.hallyn@ubuntu.com>.
 * Copyright © 2013 Canonical Ltd.
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
 */

#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <pwd.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/file.h>
#include <alloca.h>
#include <string.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <errno.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/netlink.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <linux/if_bridge.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <sys/param.h>
#include <sched.h>
#include "config.h"
#include "utils.h"

#if ISTEST
#define CONF_FILE "/tmp/lxc-usernet"
#define DB_FILE "/tmp/nics"
#else
#define CONF_FILE LXC_USERNIC_CONF
#define DB_FILE LXC_USERNIC_DB
#endif

#include "nl.h"

#ifndef IFLA_LINKMODE
#  define IFLA_LINKMODE 17
#endif

#ifndef IFLA_LINKINFO
#  define IFLA_LINKINFO 18
#endif

#ifndef IFLA_NET_NS_PID
#  define IFLA_NET_NS_PID 19
#endif

#ifndef IFLA_INFO_KIND
# define IFLA_INFO_KIND 1
#endif

#ifndef IFLA_VLAN_ID
# define IFLA_VLAN_ID 1
#endif

#ifndef IFLA_INFO_DATA
#  define IFLA_INFO_DATA 2
#endif

#ifndef VETH_INFO_PEER
# define VETH_INFO_PEER 1
#endif

#ifndef IFLA_MACVLAN_MODE
# define IFLA_MACVLAN_MODE 1
#endif

void usage(char *me, bool fail)
{
	fprintf(stderr, "Usage: %s pid type bridge nicname\n", me);
	fprintf(stderr, " nicname is the name to use inside the container\n");
	exit(fail ? 1 : 0);
}

static int open_and_lock(char *path)
{
	int fd;
	struct flock lk;

	fd = open(path, O_RDWR|O_CREAT, S_IWUSR | S_IRUSR);
	if (fd < 0) {
		fprintf(stderr, "Failed to open %s: %s\n",
			path, strerror(errno));
		return(fd);
	}

	lk.l_type = F_WRLCK;
	lk.l_whence = SEEK_SET;
	lk.l_start = 0;
	lk.l_len = 0;
	if (fcntl(fd, F_SETLKW, &lk) < 0) {
		fprintf(stderr, "Failed to lock %s: %s\n",
			path, strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}


static char *get_username(void)
{
	struct passwd *pwd = getpwuid(getuid());

	if (pwd == NULL) {
		perror("getpwuid");
		return NULL;
	}

	return pwd->pw_name;
}

/* The configuration file consists of lines of the form:
 *
 * user type bridge count
 *
 * Return the count entry for the calling user if there is one.  Else
 * return -1.
 */
static int get_alloted(char *me, char *intype, char *link)
{
	FILE *fin = fopen(CONF_FILE, "r");
	char *line = NULL;
	char user[100], type[100], br[100];
	size_t len = 0;
	int n = -1, ret;

	if (!fin) {
		fprintf(stderr, "Failed to open %s: %s\n", CONF_FILE,
			strerror(errno));
		return -1;
	}

	while ((getline(&line, &len, fin)) != -1) {
		ret = sscanf(line, "%99[^ \t] %99[^ \t] %99[^ \t] %d", user, type, br, &n);

		if (ret != 4)
			continue;
		if (strcmp(user, me) != 0)
			continue;
		if (strcmp(type, intype) != 0)
			continue;
		if (strcmp(link, br) != 0)
			continue;
		free(line);
		fclose(fin);
		return n;
	}
	fclose(fin);
	if (line)
		free(line);
	return -1;
}

static char *get_eol(char *s, char *e)
{
	while (s<e && *s && *s != '\n')
		s++;
	return s;
}

static char *get_eow(char *s, char *e)
{
	while (s<e && *s && !isblank(*s) && *s != '\n')
		s++;
	return s;
}

static char *find_line(char *p, char *e, char *u, char *t, char *l)
{
	char *p1, *p2, *ret;
	
	while (p<e  && (p1 = get_eol(p, e)) < e) {
		ret = p;
		if (*p == '#')
			goto next;
		while (p<e && isblank(*p)) p++;
		p2 = get_eow(p, e);
		if (!p2 || p2-p != strlen(u) || strncmp(p, u, strlen(u)) != 0)
			goto next;
		p = p2+1;
		while (p<e && isblank(*p)) p++;
		p2 = get_eow(p, e);
		if (!p2 || p2-p != strlen(t) || strncmp(p, t, strlen(t)) != 0)
			goto next;
		p = p2+1;
		while (p<e && isblank(*p)) p++;
		p2 = get_eow(p, e);
		if (!p2 || p2-p != strlen(l) || strncmp(p, l, strlen(l)) != 0)
			goto next;
		return ret;
next:
		p = p1 + 1;
	}

	return NULL;
}

static bool nic_exists(char *nic)
{
	char path[MAXPATHLEN];
	int ret;
	struct stat sb;

#if ISTEST
	ret = snprintf(path, MAXPATHLEN, "/tmp/lxcnettest/%s", nic);
#else
	ret = snprintf(path, MAXPATHLEN, "/sys/class/net/%s", nic);
#endif
	if (ret < 0 || ret >= MAXPATHLEN) // should never happen!
		return true;
	ret = stat(path, &sb);
	if (ret != 0)
		return false;
	return true;
}

struct link_req {
	struct nlmsg nlmsg;
	struct ifinfomsg ifinfomsg;
};

#if ! ISTEST

static int lxc_veth_create(const char *name1, const char *name2)
{
	struct nl_handler nlh;
	struct nlmsg *nlmsg = NULL, *answer = NULL;
	struct link_req *link_req;
	struct rtattr *nest1, *nest2, *nest3;
	int len, err;

	err = netlink_open(&nlh, NETLINK_ROUTE);
	if (err)
		return err;

	err = -EINVAL;
	len = strlen(name1);
	if (len == 1 || len >= IFNAMSIZ)
		goto out;

	len = strlen(name2);
	if (len == 1 || len >= IFNAMSIZ)
		goto out;

	err = -ENOMEM;
	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		goto out;

	answer = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!answer)
		goto out;

	link_req = (struct link_req *)nlmsg;
	link_req->ifinfomsg.ifi_family = AF_UNSPEC;
	nlmsg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	nlmsg->nlmsghdr.nlmsg_flags =
		NLM_F_REQUEST|NLM_F_CREATE|NLM_F_EXCL|NLM_F_ACK;
	nlmsg->nlmsghdr.nlmsg_type = RTM_NEWLINK;

	err = -EINVAL;
	nest1 = nla_begin_nested(nlmsg, IFLA_LINKINFO);
	if (!nest1)
		goto out;

	if (nla_put_string(nlmsg, IFLA_INFO_KIND, "veth"))
		goto out;

	nest2 = nla_begin_nested(nlmsg, IFLA_INFO_DATA);
	if (!nest2)
		goto out;

	nest3 = nla_begin_nested(nlmsg, VETH_INFO_PEER);
	if (!nest3)
		goto out;

	nlmsg->nlmsghdr.nlmsg_len += sizeof(struct ifinfomsg);

	if (nla_put_string(nlmsg, IFLA_IFNAME, name2))
		goto out;

	nla_end_nested(nlmsg, nest3);

	nla_end_nested(nlmsg, nest2);

	nla_end_nested(nlmsg, nest1);

	if (nla_put_string(nlmsg, IFLA_IFNAME, name1))
		goto out;

	err = netlink_transaction(&nlh, nlmsg, answer);
out:
	netlink_close(&nlh);
	nlmsg_free(answer);
	nlmsg_free(nlmsg);
	return err;
}

static int lxc_netdev_move(char *ifname, pid_t pid)
{
	struct nl_handler nlh;
	struct nlmsg *nlmsg = NULL;
	struct link_req *link_req;
	int err, index;

	index = if_nametoindex(ifname);
	if (!ifname)
		return -EINVAL;

	err = netlink_open(&nlh, NETLINK_ROUTE);
	if (err)
		return err;

	err = -ENOMEM;
	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		goto out;

	link_req = (struct link_req *)nlmsg;
	link_req->ifinfomsg.ifi_family = AF_UNSPEC;
	link_req->ifinfomsg.ifi_index = index;
	nlmsg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	nlmsg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST|NLM_F_ACK;
	nlmsg->nlmsghdr.nlmsg_type = RTM_NEWLINK;

	if (nla_put_u32(nlmsg, IFLA_NET_NS_PID, pid))
		goto out;

	err = netlink_transaction(&nlh, nlmsg, nlmsg);
out:
	netlink_close(&nlh);
	nlmsg_free(nlmsg);
	return err;
}

static int setup_private_host_hw_addr(char *veth1)
{
	struct ifreq ifr;
	int err;
	int sockfd;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
		return -errno;

	snprintf((char *)ifr.ifr_name, IFNAMSIZ, "%s", veth1);
	err = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
	if (err < 0) {
		close(sockfd);
		return -errno;
	}

	ifr.ifr_hwaddr.sa_data[0] = 0xfe;
	err = ioctl(sockfd, SIOCSIFHWADDR, &ifr);
	close(sockfd);
	if (err < 0)
		return -errno;

	return 0;
}

static int netdev_set_flag(const char *name, int flag)
{
	struct nl_handler nlh;
	struct nlmsg *nlmsg = NULL, *answer = NULL;
	struct link_req *link_req;
	int index, len, err;

	err = netlink_open(&nlh, NETLINK_ROUTE);
	if (err)
		return err;

	err = -EINVAL;
	len = strlen(name);
	if (len == 1 || len >= IFNAMSIZ)
		goto out;

	err = -ENOMEM;
	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		goto out;

	answer = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!answer)
		goto out;

	err = -EINVAL;
	index = if_nametoindex(name);
	if (!index)
		goto out;

	link_req = (struct link_req *)nlmsg;
	link_req->ifinfomsg.ifi_family = AF_UNSPEC;
	link_req->ifinfomsg.ifi_index = index;
	link_req->ifinfomsg.ifi_change |= IFF_UP;
	link_req->ifinfomsg.ifi_flags |= flag;
	nlmsg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	nlmsg->nlmsghdr.nlmsg_flags = NLM_F_REQUEST|NLM_F_ACK;
	nlmsg->nlmsghdr.nlmsg_type = RTM_NEWLINK;

	err = netlink_transaction(&nlh, nlmsg, answer);
out:
	netlink_close(&nlh);
	nlmsg_free(nlmsg);
	nlmsg_free(answer);
	return err;
}

static int instanciate_veth(char *n1, char **n2)
{
	int err;

	err = snprintf(*n2, IFNAMSIZ, "%sp", n1);
	if (err < 0 || err >= IFNAMSIZ) {
		fprintf(stderr, "nic name too long\n");
		return -1;
	}

	err = lxc_veth_create(n1, *n2);
	if (err) {
		fprintf(stderr, "failed to create %s-%s : %s\n", n1, *n2,
		      strerror(-err));
		return -1;
	}

	/* changing the high byte of the mac address to 0xfe, the bridge interface
	 * will always keep the host's mac address and not take the mac address
	 * of a container */
	err = setup_private_host_hw_addr(n1);
	if (err) {
		fprintf(stderr, "failed to change mac address of host interface '%s' : %s",
			n1, strerror(-err));
	}

	return netdev_set_flag(n1, IFF_UP);
}

static int lxc_bridge_attach(const char *bridge, const char *ifname)
{
	int fd, index, err;
	struct ifreq ifr;

	if (strlen(ifname) >= IFNAMSIZ)
		return -EINVAL;

	index = if_nametoindex(ifname);
	if (!index)
		return -EINVAL;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		return -errno;

	strncpy(ifr.ifr_name, bridge, IFNAMSIZ-1);
	ifr.ifr_name[IFNAMSIZ-1] = '\0';
	ifr.ifr_ifindex = index;
	err = ioctl(fd, SIOCBRADDIF, &ifr);
	close(fd);
	if (err)
		err = -errno;

	return err;
}

static int lxc_netdev_delete_by_index(int ifindex)
{
	struct nl_handler nlh;
	struct nlmsg *nlmsg = NULL, *answer = NULL;
	struct link_req *link_req;
	int err;

	err = netlink_open(&nlh, NETLINK_ROUTE);
	if (err)
		return err;

	err = -ENOMEM;
	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		goto out;

	answer = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!answer)
		goto out;

	link_req = (struct link_req *)nlmsg;
	link_req->ifinfomsg.ifi_family = AF_UNSPEC;
	link_req->ifinfomsg.ifi_index = ifindex;
	nlmsg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	nlmsg->nlmsghdr.nlmsg_flags = NLM_F_ACK|NLM_F_REQUEST;
	nlmsg->nlmsghdr.nlmsg_type = RTM_DELLINK;

	err = netlink_transaction(&nlh, nlmsg, answer);
out:
	netlink_close(&nlh);
	nlmsg_free(answer);
	nlmsg_free(nlmsg);
	return err;
}

static int lxc_netdev_delete_by_name(const char *name)
{
	int index;

	index = if_nametoindex(name);
	if (!index)
		return -EINVAL;

	return lxc_netdev_delete_by_index(index);
}
#else
static int lxc_netdev_delete_by_name(const char *name)
{
	char path[200];
	sprintf(path, "/tmp/lxcnettest/%s", name);
	return unlink(path);
}

#endif

static bool create_nic(char *nic, char *br, int pid, char **cnic)
{
#if ISTEST
	char path[200];
	sprintf(path, "/tmp/lxcnettest/%s", nic);
	int fd = open(path, O_RDWR|O_CREAT, S_IWUSR | S_IRUSR);
	if (fd < 0)
		return false;
	close(fd);
	return true;
#else
	char *veth1buf, *veth2buf;
	veth1buf = alloca(IFNAMSIZ);
	veth2buf = alloca(IFNAMSIZ);
	int ret;

	ret = snprintf(veth1buf, IFNAMSIZ, "%s", nic);
	if (ret < 0 || ret >= IFNAMSIZ) {
		fprintf(stderr, "host nic name too long\n");
		return false;
	}

	/* create the nics */
	if (instanciate_veth(veth1buf, &veth2buf) < 0) {
		fprintf(stderr, "Error creating veth tunnel\n");
		return false;
	}

	/* attach veth1 to bridge */
	if (lxc_bridge_attach(br, veth1buf) < 0) {
		fprintf(stderr, "Error attaching %s to %s\n", veth1buf, br);
		goto out_del;
	}

	/* pass veth2 to target netns */
	ret = lxc_netdev_move(veth2buf, pid);
	if (ret < 0) {
		fprintf(stderr, "Error moving %s to netns %d\n", veth2buf, pid);
		goto out_del;
	}
	*cnic = strdup(veth2buf);
	return true;

out_del:
	lxc_netdev_delete_by_name(veth1buf);
	return false;
#endif
}

/*
 * Get a new nic.
 * *dest will container the name (lxcuser-%d) which is attached
 * on the host to the lxc bridge
 */
static void get_new_nicname(char **dest, char *br, int pid, char **cnic)
{
	int i = 0;
	// TODO - speed this up.  For large installations we won't
	// want n stats for every nth container startup.
	while (1) {
		sprintf(*dest, "lxcuser-%d", i);
		if (!nic_exists(*dest) && create_nic(*dest, br, pid, cnic))
			return;
		i++;
	}
}

static bool get_nic_from_line(char *p, char **nic)
{
	char user[100], type[100], br[100];
	int ret;

	ret = sscanf(p, "%99[^ \t\n] %99[^ \t\n] %99[^ \t\n] %99[^ \t\n]", user, type, br, *nic);
	if (ret != 4)
		return false;
	return true;
}

struct entry_line {
	char *start;
	int len;
	bool keep;
};

static bool cull_entries(int fd, char *me, char *t, char *br)
{
	struct stat sb;
	char *buf, *p, *e, *nic;
	off_t len;
	struct entry_line *entry_lines = NULL;
	int i, n = 0;

	nic = alloca(100);

	fstat(fd, &sb);
	len = sb.st_size;
	if (len == 0)
		return true;
	buf = mmap(NULL, len, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (buf == MAP_FAILED) {
		fprintf(stderr, "Failed to create mapping: %s\n", strerror(errno));
		return false;
	}

	p = buf;
	e = buf + len;
	while ((p = find_line(p, e, me, t, br)) != NULL) {
		struct entry_line *newe = realloc(entry_lines, n+1);
		if (!newe) {
			free(entry_lines);
			return false;
		}
		entry_lines = newe;
		entry_lines[n].start = p;
		entry_lines[n].len = get_eol(p, e) - entry_lines[n].start;
		entry_lines[n].keep = true;
		n++;
		if (!get_nic_from_line(p, &nic))
			continue;
		if (nic && !nic_exists(nic))
			entry_lines[n-1].keep = false;
		p += entry_lines[n-1].len + 1;
		if (p >= e)
			break;
	}
	p = buf;
	for (i=0; i<n; i++) {
		if (!entry_lines[i].keep)
			continue;
		memcpy(p, entry_lines[i].start, entry_lines[i].len);
		p += entry_lines[i].len;
		*p = '\n';
		p++;
	}
	free(entry_lines);
	munmap(buf, sb.st_size);
	if (ftruncate(fd, p-buf))
		fprintf(stderr, "Failed to set new file size\n");
	return true;
}

static int count_entries(char *buf, off_t len, char *me, char *t, char *br)
{
	char *e = &buf[len];
	int count = 0;
	while ((buf = find_line(buf, e, me, t, br)) != NULL) {
		count++;
		buf = get_eol(buf, e)+1;
		if (buf >= e)
			break;
	}

	return count;
}

/*
 * The dbfile has lines of the format:
 * user type bridge nicname
 */
static bool get_nic_if_avail(int fd, char *me, int pid, char *intype, char *br, int allowed, char **nicname, char **cnic)
{
	off_t len, slen;
	struct stat sb;
	char *buf = NULL, *newline;
	int ret, count = 0;

	cull_entries(fd, me, intype, br);

	fstat(fd, &sb);
	len = sb.st_size;
	if (len != 0) {
		buf = mmap(NULL, len, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
		if (buf == MAP_FAILED) {
			fprintf(stderr, "Failed to create mapping\n");
			return false;
		}

		count = count_entries(buf, len, me, intype, br);
		if (count >= allowed)
			return false;
	}


	get_new_nicname(nicname, br, pid, cnic);
	/* me  ' ' intype ' ' br ' ' *nicname + '\n' + '\0' */
	slen = strlen(me) + strlen(intype) + strlen(br) + strlen(*nicname) + 5;
	newline = alloca(slen);
	ret = snprintf(newline, slen, "%s %s %s %s\n", me, intype, br, *nicname);
	if (ret < 0 || ret >= slen) {
		if (lxc_netdev_delete_by_name(*nicname) != 0)
			fprintf(stderr, "Error unlinking %s!\n", *nicname);
		return false;
	}
	if (len)
		munmap(buf, len);
	if (ftruncate(fd, len + slen))
		fprintf(stderr, "Failed to set new file size\n");
	buf = mmap(NULL, len + slen, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (buf == MAP_FAILED) {
		fprintf(stderr, "Failed to create mapping after extending: %s\n", strerror(errno));
		if (lxc_netdev_delete_by_name(*nicname) != 0)
			fprintf(stderr, "Error unlinking %s!\n", *nicname);
		return false;
	}
	strcpy(buf+len, newline);
	munmap(buf, len+slen);
	return true;
}

static bool create_db_dir(char *fnam)
{
	char *p = alloca(strlen(fnam)+1);

	strcpy(p, fnam);
	fnam = p;
	p = p + 1;
again:
	while (*p && *p != '/') p++;
	if (!*p)
		return true;
	*p = '\0';
	if (mkdir(fnam, 0755) && errno != EEXIST) {
		fprintf(stderr, "failed to create %s\n", fnam);
		*p = '/';
		return false;
	}
	*(p++) = '/';
	goto again;
}

static int lxc_netdev_rename_by_index(int ifindex, const char *newname)
{
	struct nl_handler nlh;
	struct nlmsg *nlmsg = NULL, *answer = NULL;
	struct link_req *link_req;
	int len, err;

	err = netlink_open(&nlh, NETLINK_ROUTE);
	if (err)
		return err;

	len = strlen(newname);
	if (len == 1 || len >= IFNAMSIZ)
		goto out;

	err = -ENOMEM;
	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		goto out;

	answer = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!answer)
		goto out;

	link_req = (struct link_req *)nlmsg;
	link_req->ifinfomsg.ifi_family = AF_UNSPEC;
	link_req->ifinfomsg.ifi_index = ifindex;
	nlmsg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	nlmsg->nlmsghdr.nlmsg_flags = NLM_F_ACK|NLM_F_REQUEST;
	nlmsg->nlmsghdr.nlmsg_type = RTM_NEWLINK;

	if (nla_put_string(nlmsg, IFLA_IFNAME, newname))
		goto out;

	err = netlink_transaction(&nlh, nlmsg, answer);
out:
	netlink_close(&nlh);
	nlmsg_free(answer);
	nlmsg_free(nlmsg);
	return err;
}

static int lxc_netdev_rename_by_name(const char *oldname, const char *newname)
{
	int len, index;

	len = strlen(oldname);
	if (len == 1 || len >= IFNAMSIZ)
		return -EINVAL;

	index = if_nametoindex(oldname);
	if (!index) {
		fprintf(stderr, "Error getting ifindex for %s\n", oldname);
		return -EINVAL;
	}

	return lxc_netdev_rename_by_index(index, newname);
}

static int rename_in_ns(int pid, char *oldname, char *newname)
{
	char nspath[MAXPATHLEN];
	int fd = -1, ofd = -1, ret;

	ret = snprintf(nspath, MAXPATHLEN, "/proc/%d/ns/net", getpid());
	if (ret < 0 || ret >= MAXPATHLEN)
		return -1;
	if ((ofd = open(nspath, O_RDONLY)) < 0) {
		fprintf(stderr, "Opening %s\n", nspath);
		return -1;
	}
	ret = snprintf(nspath, MAXPATHLEN, "/proc/%d/ns/net", pid);
	if (ret < 0 || ret >= MAXPATHLEN)
		goto out_err;

	if ((fd = open(nspath, O_RDONLY)) < 0) {
		fprintf(stderr, "Opening %s\n", nspath);
		goto out_err;
	}
	if (setns(fd, 0) < 0) {
		fprintf(stderr, "setns to container network namespace\n");
		goto out_err;
	}
	close(fd); fd = -1;
	if ((ret = lxc_netdev_rename_by_name(oldname, newname)) < 0) {
		fprintf(stderr, "Error %d renaming netdev %s to %s in container\n", ret, oldname, newname);
		goto out_err;
	}
	if (setns(ofd, 0) < 0) {
		fprintf(stderr, "Error returning to original netns\n");
		close(ofd);
		return -1;
	}
	close(ofd);

	return 0;

out_err:
	if (ofd >= 0)
		close(ofd);
	if (setns(ofd, 0) < 0)
		fprintf(stderr, "Error returning to original network namespace\n");
	if (fd >= 0)
		close(fd);
	return -1;
}

/*
 * If the caller (real uid, not effective uid) may read the
 * /proc/pid/net/ns, then it is either the caller's netns or one
 * which it created.
 */
static bool may_access_netns(int pid)
{
	int ret;
	char s[200];
	uid_t ruid, suid, euid;
	bool may_access = false;

	ret = getresuid(&ruid, &euid, &suid);
	if (ret) {
		fprintf(stderr, "Failed to get my uids: %s\n", strerror(errno));
		return false;
	}
	ret = setresuid(ruid, ruid, euid);
	if (ret) {
		fprintf(stderr, "Failed to set temp uids to (%d,%d,%d): %s\n",
				(int)ruid, (int)ruid, (int)euid, strerror(errno));
		return false;
	}
	ret = snprintf(s, 200, "/proc/%d/ns/net", pid);
	if (ret < 0 || ret >= 200)  // can't happen
		return false;
	ret = access(s, R_OK);
	if (ret) {
		fprintf(stderr, "Uid %d may not access %s: %s\n",
				(int)ruid, s, strerror(errno));
	}
	may_access = ret == 0;
	ret = setresuid(ruid, euid, suid);
	if (ret) {
		fprintf(stderr, "Failed to restore uids to (%d,%d,%d): %s\n",
				(int)ruid, (int)euid, (int)suid, strerror(errno));
		may_access = false;
	}
	return may_access;
}

int main(int argc, char *argv[])
{
	int n, fd;
	bool gotone = false;
	char *me;
	char *nicname = alloca(40);
	char *cnic = NULL; // created nic name in container is returned here.
	char *vethname;
	int pid;

	if ((me = get_username()) == NULL) {
		fprintf(stderr, "Failed to get username\n");
		exit(1);
	}

	if (argc < 4)
		usage(argv[0], true);
	if (argc >= 5)
		vethname = argv[4];
	else
		vethname = "eth0";

	errno = 0;
	pid = (int) strtol(argv[1], NULL, 10);
	if (errno) {
		fprintf(stderr, "Could not read pid: %s\n", argv[1]);
		exit(1);
	}

	if (!create_db_dir(DB_FILE)) {
		fprintf(stderr, "Failed to create directory for db file\n");
		exit(1);
	}

	if ((fd = open_and_lock(DB_FILE)) < 0) {
		fprintf(stderr, "Failed to lock %s\n", DB_FILE);
		exit(1);
	}

	if (!may_access_netns(pid)) {
		fprintf(stderr, "User %s may not modify netns for pid %d\n",
				me, pid);
		exit(1);
	}

	n = get_alloted(me, argv[2], argv[3]);
	if (n > 0)
		gotone = get_nic_if_avail(fd, me, pid, argv[2], argv[3], n, &nicname, &cnic);
	close(fd);
	if (!gotone) {
		fprintf(stderr, "Quota reached\n");
		exit(1);
	}

	// Now rename the link
	if (rename_in_ns(pid, cnic, vethname) < 0) {
		fprintf(stderr, "Failed to rename the link\n");
		exit(1);
	}

	exit(0);
}
