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
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include "config.h"

#ifndef HAVE_GETLINE
#ifdef HAVE_FGETLN
#include <../include/getline.h>
#endif
#endif

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
	fprintf(stderr, "Usage: %s pid type bridge\n", me);
	exit(fail ? 1 : 0);
}

int open_and_lock(char *path)
{
	int fd;
	struct flock lk;

	fd = open(path, O_RDWR|O_CREAT, S_IWUSR | S_IRUSR);
	if (fd < 0) {
		perror("open");
		return(fd);
	}

	lk.l_type = F_WRLCK;
	lk.l_whence = SEEK_SET;
	lk.l_start = 0;
	lk.l_len = 0;
	if (fcntl(fd, F_SETLKW, &lk) < 0) {
		perror("fcntl lock");
		exit(1);
	}

	return fd;
}


char *get_username(char **buf)
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
 * user type bridge nic-name count
 *
 * We simply count the number of lines in the file, making sure that
 * every listed nic is still present.  Any nics which have disappeared
 * is removed when we count, in case the container died a harsh death
 * without being able to clean up after itself.
 */
int get_alloted(char *me, char *intype, char *link)
{
	FILE *fin = fopen(CONF_FILE, "r");
	char *line = NULL;
	char user[100], type[100], br[100];
	size_t len = 0;
	int n = -1, ret;

	if (!fin)
		return -1;

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
		return n;
	}
	fclose(fin);
	if (line)
		free(line);
	return -1;
}

char *get_eol(char *s)
{
	while (*s && *s != '\n')
		s++;
	return s;
}

char *get_eow(char *s)
{
	while (*s && !isblank(*s) && *s != '\n')
		s++;
	return s;
}

char *find_line(char *p, char *e, char *u, char *t, char *l)
{
	char *p1, *p2, *ret;
	
	while (p < e  && (p1 = get_eol(p)) < e) {
		ret = p;
		if (*p == '#')
			goto next;
		while (isblank(*p)) p++;
		p2 = get_eow(p);
		if (!p2 || p2-p != strlen(u) || strncmp(p, u, strlen(u)) != 0)
			goto next;
		p = p2+1;
		while (isblank(*p)) p++;
		p2 = get_eow(p);
		if (!p2 || p2-p != strlen(t) || strncmp(p, t, strlen(t)) != 0)
			goto next;
		p = p2+1;
		while (isblank(*p)) p++;
		p2 = get_eow(p);
		if (!p2 || p2-p != strlen(l) || strncmp(p, l, strlen(l)) != 0)
			goto next;
		return ret;
next:
		p = p1 + 1;
	}

	return NULL;
}

bool nic_exists(char *nic)
{
	char path[200];
	int ret;
	struct stat sb;

#if ISTEST
	ret = snprintf(path, 200, "/tmp/lxcnettest/%s", nic);
#else
	ret = snprintf(path, 200, "/sys/class/net/%s", nic);
#endif
	if (ret < 0 || ret >= 200)
		exit(1);
	ret = stat(path, &sb);
	if (ret != 0)
		return false;
	return true;
}

#if ! ISTEST
struct link_req {
	struct nlmsg nlmsg;
	struct ifinfomsg ifinfomsg;
};

int lxc_veth_create(const char *name1, const char *name2)
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

int lxc_netdev_move(char *ifname, pid_t pid)
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
		exit(1);
	}

	err = lxc_veth_create(n1, *n2);
	if (err) {
		fprintf(stderr, "failed to create %s-%s : %s\n", n1, *n2,
		      strerror(-err));
		exit(1);
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

int lxc_bridge_attach(const char *bridge, const char *ifname)
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

	strncpy(ifr.ifr_name, bridge, IFNAMSIZ);
	ifr.ifr_ifindex = index;
	err = ioctl(fd, SIOCBRADDIF, &ifr);
	close(fd);
	if (err)
		err = -errno;

	return err;
}

int lxc_netdev_delete_by_index(int ifindex)
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

int lxc_netdev_delete_by_name(const char *name)
{
	int index;

	index = if_nametoindex(name);
	if (!index)
		return -EINVAL;

	return lxc_netdev_delete_by_index(index);
}
#else
int lxc_netdev_delete_by_name(const char *name)
{
	char path[200];
	sprintf(path, "/tmp/lxcnettest/%s", name);
	return unlink(path);
}

#endif

bool create_nic(char *nic, char *br, char *pidstr)
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
	// not yet implemented
	char *veth1buf, *veth2buf;
	veth1buf = alloca(IFNAMSIZ);
	veth2buf = alloca(IFNAMSIZ);
	int ret;
	int pid = atoi(pidstr);

	ret = snprintf(veth1buf, IFNAMSIZ, "%s", nic);
	if (ret < 0 || ret >= IFNAMSIZ) {
		fprintf(stderr, "nic name too long\n");
		exit(1);
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
	return true;

out_del:
	lxc_netdev_delete_by_name(veth1buf);
	exit(1);
#endif
}

void get_new_nicname(char **dest, char *br, char *pid)
{
	int i = 0;
	// TODO - speed this up.  For large installations we won't
	// want n stats for every nth container startup.
	while (1) {
		sprintf(*dest, "lxcuser-%d", i);
		if (!nic_exists(*dest) && create_nic(*dest, br, pid))
			return;
		i++;
	}
}

bool get_nic_from_line(char *p, char **nic)
{
	char user[100], type[100], br[100];
	int ret;

	ret = sscanf(p, "%99[^ \t\n] %99[^ \t\n] %99[^ \t\n] %99[^ \t\n]", user, type, br, *nic);
	if (ret != 4)
		return false;
	return true;
}

bool cull_entries(int fd, char *me, char *t, char *br)
{
	struct stat sb;
	char *buf, *p, *e, *nic;
	off_t len;

	nic = alloca(100);

	fstat(fd, &sb);
	len = sb.st_size;
	if (len == 0)
		return true;
	buf = mmap(NULL, len, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (buf == MAP_FAILED) {
		fprintf(stderr, "Failed to create mapping: error %d\n", errno);
		return false;
	}

	p = buf;
	e = buf + len;
	while ((p = find_line(p, e, me, t, br)) != NULL) {
		if (!get_nic_from_line(p, &nic))
			continue;
		if (nic && !nic_exists(nic)) {
			// copy from eol(p)+1..e to p
			char *src = get_eol(p) + 1, *dest = p;
			int diff = src - p;
			while (src < e)
				*(dest++) = *(src)++;
			e -= diff;
		} else
			p = get_eol(p) + 1;
		if (p >= e)
			break;
	}
	munmap(buf, sb.st_size);
	if (ftruncate(fd, e-buf))
		fprintf(stderr, "Failed to set new file size\n");
	return true;
}

int count_entries(char *buf, off_t len, char *me, char *t, char *br)
{
	char *e = &buf[len];
	int count = 0;
	while ((buf = find_line(buf, e, me, t, br)) != NULL) {
		count++;
		buf = get_eol(buf)+1;
		if (buf >= e)
			break;
	}

	return count;
}

/*
 * The dbfile has lines of the format:
 * user type bridge nicname
 */
bool get_nic_if_avail(int fd, char *me, char *pid, char *intype, char *br, int allowed, char **nicname)
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


	get_new_nicname(nicname, br, pid);
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
		fprintf(stderr, "Failed to create mapping after extending: error %d\n", errno);
		if (lxc_netdev_delete_by_name(*nicname) != 0)
			fprintf(stderr, "Error unlinking %s!\n", *nicname);
		return false;
	}
	strcpy(buf+len, newline);
	munmap(buf, len+slen);
	return true;
}

bool create_db_dir(char *fnam)
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

int main(int argc, char *argv[])
{
	int n, fd;
	bool gotone = false;
	char *me, *buf = alloca(400);
	char *nicname = alloca(40);

	if ((me = get_username(&buf)) == NULL) {
		fprintf(stderr, "Failed to get username\n");
		exit(1);
	}

	if (argc != 4)
		usage(argv[0], true);

	if (!create_db_dir(DB_FILE)) {
		fprintf(stderr, "Failed to create directory for db file\n");
		exit(1);
	}

	if ((fd = open_and_lock(DB_FILE)) < 0) {
		fprintf(stderr, "Failed to lock %s\n", DB_FILE);
		exit(1);
	}

	n = get_alloted(me, argv[2], argv[3]);
	if (n > 0)
		gotone = get_nic_if_avail(fd, me, argv[1], argv[2], argv[3], n, &nicname);
	close(fd);
	if (!gotone) {
		fprintf(stderr, "Quota reached\n");
		exit(1);
	}

	// Now create the link

	exit(0);
}
