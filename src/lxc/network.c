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
#define _GNU_SOURCE
#include <stdio.h>
#undef _GNU_SOURCe
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/inotify.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>

#include "nl.h"
#include "network.h"
#include "conf.h"
#include "utils.h"

#if HAVE_IFADDRS_H
#include <ifaddrs.h>
#else
#include <../include/ifaddrs.h>
#endif

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


int lxc_netdev_move_by_index(int ifindex, pid_t pid, const char* ifname)
{
	struct nl_handler nlh;
	struct nlmsg *nlmsg = NULL;
	struct ifinfomsg *ifi;
	int err;

	err = netlink_open(&nlh, NETLINK_ROUTE);
	if (err)
		return err;

	err = -ENOMEM;
	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		goto out;

	nlmsg->nlmsghdr->nlmsg_flags = NLM_F_REQUEST|NLM_F_ACK;
	nlmsg->nlmsghdr->nlmsg_type = RTM_NEWLINK;

	ifi = nlmsg_reserve(nlmsg, sizeof(struct ifinfomsg));
	if (!ifi)
		goto out;
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index = ifindex;

	if (nla_put_u32(nlmsg, IFLA_NET_NS_PID, pid))
		goto out;

	if (ifname != NULL) {
		if (nla_put_string(nlmsg, IFLA_IFNAME, ifname))
			goto out;
	}

	err = netlink_transaction(&nlh, nlmsg, nlmsg);
out:
	netlink_close(&nlh);
	nlmsg_free(nlmsg);
	return err;
}

/*
 * If we are asked to move a wireless interface, then
 * we must actually move its phyN device.  Detect
 * that condition and return the physname here.  The
 * physname will be passed to lxc_netdev_move_wlan()
 * which will free it when done
 */
#define PHYSNAME "/sys/class/net/%s/phy80211/name"
static char * is_wlan(const char *ifname)
{
	char *path, *physname = NULL;
	size_t len = strlen(ifname) + strlen(PHYSNAME) - 1;
	struct stat sb;
	long physlen;
	FILE *f;
	int ret, i;

	path = alloca(len+1);
	ret = snprintf(path, len, PHYSNAME, ifname);
	if (ret < 0 || ret >= len)
		goto bad;
	ret = stat(path, &sb);
	if (ret)
		goto bad;
	if (!(f = fopen(path, "r")))
		goto bad;
	// feh - sb.st_size is always 4096
	fseek(f, 0, SEEK_END);
	physlen = ftell(f);
	fseek(f, 0, SEEK_SET);
	physname = malloc(physlen+1);
	if (!physname) {
		fclose(f);
		goto bad;
	}
	memset(physname, 0, physlen+1);
	ret = fread(physname, 1, physlen, f);
	fclose(f);
	if (ret < 0)
		goto bad;

	for (i = 0;  i < physlen; i++) {
		if (physname[i] == '\n')
			physname[i] = '\0';
		if (physname[i] == '\0')
			break;
	}

	return physname;

bad:
	free(physname);
	return NULL;
}

static int
lxc_netdev_rename_by_name_in_netns(pid_t pid, const char *old, const char *new)
{
	pid_t fpid = fork();

	if (fpid < 0)
		return -1;
	if (fpid != 0)
		return wait_for_pid(fpid);
	if (!switch_to_ns(pid, "net"))
		return -1;
	exit(lxc_netdev_rename_by_name(old, new));
}

static int
lxc_netdev_move_wlan(char *physname, const char *ifname, pid_t pid, const char* newname)
{
	int err = -1;
	pid_t fpid;
	char *cmd;

	/* Move phyN into the container.  TODO - do this using netlink.
	 * However, IIUC this involves a bit more complicated work to
	 * talk to the 80211 module, so for now just call out to iw
	 */
	cmd = on_path("iw", NULL);
	if (!cmd)
		goto out1;
	free(cmd);

	fpid = fork();
	if (fpid < 0)
		goto out1;
	if (fpid == 0) {
		char pidstr[30];
		sprintf(pidstr, "%d", pid);
		if (execlp("iw", "iw", "phy", physname, "set", "netns", pidstr, (char *)NULL))
			exit(1);
		exit(0); // notreached
	}
	if (wait_for_pid(fpid))
		goto out1;

	err = 0;
	if (newname)
		err = lxc_netdev_rename_by_name_in_netns(pid, ifname, newname);

out1:
	free(physname);
	return err;
}

int lxc_netdev_move_by_name(const char *ifname, pid_t pid, const char* newname)
{
	int index;
	char *physname;

	if (!ifname)
		return -EINVAL;

	index = if_nametoindex(ifname);
	if (!index)
		return -EINVAL;

	if ((physname = is_wlan(ifname)))
		return lxc_netdev_move_wlan(physname, ifname, pid, newname);

	return lxc_netdev_move_by_index(index, pid, newname);
}

int lxc_netdev_delete_by_index(int ifindex)
{
	struct nl_handler nlh;
	struct nlmsg *nlmsg = NULL, *answer = NULL;
	struct ifinfomsg *ifi;
	int err;

	err = netlink_open(&nlh, NETLINK_ROUTE);
	if (err)
		return err;

	err = -ENOMEM;
	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		goto out;

	answer = nlmsg_alloc_reserve(NLMSG_GOOD_SIZE);
	if (!answer)
		goto out;

	nlmsg->nlmsghdr->nlmsg_flags = NLM_F_ACK|NLM_F_REQUEST;
	nlmsg->nlmsghdr->nlmsg_type = RTM_DELLINK;

	ifi = nlmsg_reserve(nlmsg, sizeof(struct ifinfomsg));
	if (!ifi)
		goto out;
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index = ifindex;

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

int lxc_netdev_rename_by_index(int ifindex, const char *newname)
{
	struct nl_handler nlh;
	struct nlmsg *nlmsg = NULL, *answer = NULL;
	struct ifinfomsg *ifi;
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

	answer = nlmsg_alloc_reserve(NLMSG_GOOD_SIZE);
	if (!answer)
		goto out;

	nlmsg->nlmsghdr->nlmsg_flags = NLM_F_ACK|NLM_F_REQUEST;
	nlmsg->nlmsghdr->nlmsg_type = RTM_NEWLINK;

	ifi = nlmsg_reserve(nlmsg, sizeof(struct ifinfomsg));
	if (!ifi)
		goto out;
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index = ifindex;

	if (nla_put_string(nlmsg, IFLA_IFNAME, newname))
		goto out;

	err = netlink_transaction(&nlh, nlmsg, answer);
out:
	netlink_close(&nlh);
	nlmsg_free(answer);
	nlmsg_free(nlmsg);
	return err;
}

int lxc_netdev_rename_by_name(const char *oldname, const char *newname)
{
	int len, index;

	len = strlen(oldname);
	if (len == 1 || len >= IFNAMSIZ)
		return -EINVAL;

	index = if_nametoindex(oldname);
	if (!index)
		return -EINVAL;

	return lxc_netdev_rename_by_index(index, newname);
}

int netdev_set_flag(const char *name, int flag)
{
	struct nl_handler nlh;
	struct nlmsg *nlmsg = NULL, *answer = NULL;
	struct ifinfomsg *ifi;
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

	answer = nlmsg_alloc_reserve(NLMSG_GOOD_SIZE);
	if (!answer)
		goto out;

	err = -EINVAL;
	index = if_nametoindex(name);
	if (!index)
		goto out;

	nlmsg->nlmsghdr->nlmsg_flags = NLM_F_REQUEST|NLM_F_ACK;
	nlmsg->nlmsghdr->nlmsg_type = RTM_NEWLINK;

	ifi = nlmsg_reserve(nlmsg, sizeof(struct ifinfomsg));
	if (!ifi) {
		err = -ENOMEM;
		goto out;
	}
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index = index;
	ifi->ifi_change |= IFF_UP;
	ifi->ifi_flags |= flag;

	err = netlink_transaction(&nlh, nlmsg, answer);
out:
	netlink_close(&nlh);
	nlmsg_free(nlmsg);
	nlmsg_free(answer);
	return err;
}

int netdev_get_flag(const char* name, int *flag)
{
	struct nl_handler nlh;
	struct nlmsg *nlmsg = NULL, *answer = NULL;
	struct ifinfomsg *ifi;
	int index, len, err;

	if (!name)
		return -EINVAL;

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

	answer = nlmsg_alloc_reserve(NLMSG_GOOD_SIZE);
	if (!answer)
		goto out;

	err = -EINVAL;
	index = if_nametoindex(name);
	if (!index)
		goto out;

	nlmsg->nlmsghdr->nlmsg_flags = NLM_F_REQUEST;
	nlmsg->nlmsghdr->nlmsg_type = RTM_GETLINK;

	ifi = nlmsg_reserve(nlmsg, sizeof(struct ifinfomsg));
	if (!ifi) {
		err = -ENOMEM;
		goto out;
	}
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index = index;

	err = netlink_transaction(&nlh, nlmsg, answer);
	if (err)
		goto out;

	ifi = NLMSG_DATA(answer->nlmsghdr);

	*flag = ifi->ifi_flags;
out:
	netlink_close(&nlh);
	nlmsg_free(nlmsg);
	nlmsg_free(answer);
	return err;
}

/*
 * \brief Check a interface is up or not.
 *
 * \param name: name for the interface.
 *
 * \return int.
 * 0 means interface is down.
 * 1 means interface is up.
 * Others means error happened, and ret-value is the error number.
 */
int lxc_netdev_isup(const char* name)
{
	int flag;
	int err;

	err = netdev_get_flag(name, &flag);
	if (err)
		goto out;
	if (flag & IFF_UP)
		return 1;
	return 0;
out:
	return err;
}

int netdev_get_mtu(int ifindex)
{
	struct nl_handler nlh;
	struct nlmsg *nlmsg = NULL, *answer = NULL;
	struct ifinfomsg *ifi;
	struct nlmsghdr *msg;
	int err, res;
	int recv_len = 0, answer_len;
	int readmore = 0;

	err = netlink_open(&nlh, NETLINK_ROUTE);
	if (err)
		return err;

	err = -ENOMEM;
	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		goto out;

	answer = nlmsg_alloc_reserve(NLMSG_GOOD_SIZE);
	if (!answer)
		goto out;

	/* Save the answer buffer length, since it will be overwritten
	 * on the first receive (and we might need to receive more than
	 * once. */
	answer_len = answer->nlmsghdr->nlmsg_len;

	nlmsg->nlmsghdr->nlmsg_flags = NLM_F_REQUEST|NLM_F_DUMP;
	nlmsg->nlmsghdr->nlmsg_type = RTM_GETLINK;

	ifi = nlmsg_reserve(nlmsg, sizeof(struct ifinfomsg));
	if (!ifi)
		goto out;
	ifi->ifi_family = AF_UNSPEC;

	/* Send the request for addresses, which returns all addresses
	 * on all interfaces. */
	err = netlink_send(&nlh, nlmsg);
	if (err < 0)
		goto out;

	do {
		/* Restore the answer buffer length, it might have been
		 * overwritten by a previous receive. */
		answer->nlmsghdr->nlmsg_len = answer_len;

		/* Get the (next) batch of reply messages */
		err = netlink_rcv(&nlh, answer);
		if (err < 0)
			goto out;

		recv_len = err;
		err = 0;

		/* Satisfy the typing for the netlink macros */
		msg = answer->nlmsghdr;

		while (NLMSG_OK(msg, recv_len)) {

			/* Stop reading if we see an error message */
			if (msg->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *errmsg = (struct nlmsgerr*)NLMSG_DATA(msg);
				err = errmsg->error;
				goto out;
			}

			/* Stop reading if we see a NLMSG_DONE message */
			if (msg->nlmsg_type == NLMSG_DONE) {
				readmore = 0;
				break;
			}

			ifi = NLMSG_DATA(msg);
			if (ifi->ifi_index == ifindex) {
				struct rtattr *rta = IFLA_RTA(ifi);
				int attr_len = msg->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi));
				res = 0;
				while(RTA_OK(rta, attr_len)) {
					/* Found a local address for the requested interface,
					 * return it. */
					if (rta->rta_type == IFLA_MTU) {
						memcpy(&res, RTA_DATA(rta), sizeof(int));
						err = res;
						goto out;
					}
					rta = RTA_NEXT(rta, attr_len);
				}

			}

			/* Keep reading more data from the socket if the
			 * last message had the NLF_F_MULTI flag set */
			readmore = (msg->nlmsg_flags & NLM_F_MULTI);

			/* Look at the next message received in this buffer */
			msg = NLMSG_NEXT(msg, recv_len);
		}
	} while (readmore);

	/* If we end up here, we didn't find any result, so signal an
	 * error */
	err = -1;

out:
	netlink_close(&nlh);
	nlmsg_free(answer);
	nlmsg_free(nlmsg);
	return err;
}

int lxc_netdev_set_mtu(const char *name, int mtu)
{
	struct nl_handler nlh;
	struct nlmsg *nlmsg = NULL, *answer = NULL;
	struct ifinfomsg *ifi;
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

	answer = nlmsg_alloc_reserve(NLMSG_GOOD_SIZE);
	if (!answer)
		goto out;

	err = -EINVAL;
	index = if_nametoindex(name);
	if (!index)
		goto out;

	nlmsg->nlmsghdr->nlmsg_flags = NLM_F_REQUEST|NLM_F_ACK;
	nlmsg->nlmsghdr->nlmsg_type = RTM_NEWLINK;

	ifi = nlmsg_reserve(nlmsg, sizeof(struct ifinfomsg));
	if (!ifi) {
		err = -ENOMEM;
		goto out;
	}
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index = index;

	if (nla_put_u32(nlmsg, IFLA_MTU, mtu))
		goto out;

	err = netlink_transaction(&nlh, nlmsg, answer);
out:
	netlink_close(&nlh);
	nlmsg_free(nlmsg);
	nlmsg_free(answer);
	return err;
}

int lxc_netdev_up(const char *name)
{
	return netdev_set_flag(name, IFF_UP);
}

int lxc_netdev_down(const char *name)
{
	return netdev_set_flag(name, 0);
}

int lxc_veth_create(const char *name1, const char *name2)
{
	struct nl_handler nlh;
	struct nlmsg *nlmsg = NULL, *answer = NULL;
	struct ifinfomsg *ifi;
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

	answer = nlmsg_alloc_reserve(NLMSG_GOOD_SIZE);
	if (!answer)
		goto out;

	nlmsg->nlmsghdr->nlmsg_flags =
		NLM_F_REQUEST|NLM_F_CREATE|NLM_F_EXCL|NLM_F_ACK;
	nlmsg->nlmsghdr->nlmsg_type = RTM_NEWLINK;

	ifi = nlmsg_reserve(nlmsg, sizeof(struct ifinfomsg));
	if (!ifi)
		goto out;
	ifi->ifi_family = AF_UNSPEC;

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

	ifi = nlmsg_reserve(nlmsg, sizeof(struct ifinfomsg));
	if (!ifi) {
		err = -ENOMEM;
		goto out;
	}

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

/* XXX: merge with lxc_macvlan_create */
int lxc_vlan_create(const char *master, const char *name, unsigned short vlanid)
{
	struct nl_handler nlh;
	struct nlmsg *nlmsg = NULL, *answer = NULL;
	struct ifinfomsg *ifi;
	struct rtattr *nest, *nest2;
	int lindex, len, err;

	err = netlink_open(&nlh, NETLINK_ROUTE);
	if (err)
		return err;

	err = -EINVAL;
	len = strlen(master);
	if (len == 1 || len >= IFNAMSIZ)
		goto err3;

	len = strlen(name);
	if (len == 1 || len >= IFNAMSIZ)
		goto err3;

	err = -ENOMEM;
	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		goto err3;

	answer = nlmsg_alloc_reserve(NLMSG_GOOD_SIZE);
	if (!answer)
		goto err2;

	err = -EINVAL;
	lindex = if_nametoindex(master);
	if (!lindex)
		goto err1;

	nlmsg->nlmsghdr->nlmsg_flags =
		NLM_F_REQUEST|NLM_F_CREATE|NLM_F_EXCL|NLM_F_ACK;
	nlmsg->nlmsghdr->nlmsg_type = RTM_NEWLINK;

	ifi = nlmsg_reserve(nlmsg, sizeof(struct ifinfomsg));
	if (!ifi) {
		err = -ENOMEM;
		goto err1;
	}
	ifi->ifi_family = AF_UNSPEC;

	nest = nla_begin_nested(nlmsg, IFLA_LINKINFO);
	if (!nest)
		goto err1;

	if (nla_put_string(nlmsg, IFLA_INFO_KIND, "vlan"))
		goto err1;

	nest2 = nla_begin_nested(nlmsg, IFLA_INFO_DATA);
	if (!nest2)
		goto err1;

	if (nla_put_u16(nlmsg, IFLA_VLAN_ID, vlanid))
		goto err1;

	nla_end_nested(nlmsg, nest2);

	nla_end_nested(nlmsg, nest);

	if (nla_put_u32(nlmsg, IFLA_LINK, lindex))
		goto err1;

	if (nla_put_string(nlmsg, IFLA_IFNAME, name))
		goto err1;

	err = netlink_transaction(&nlh, nlmsg, answer);
err1:
	nlmsg_free(answer);
err2:
	nlmsg_free(nlmsg);
err3:
	netlink_close(&nlh);
	return err;
}

int lxc_macvlan_create(const char *master, const char *name, int mode)
{
	struct nl_handler nlh;
	struct nlmsg *nlmsg = NULL, *answer = NULL;
	struct ifinfomsg *ifi;
	struct rtattr *nest, *nest2;
	int index, len, err;

	err = netlink_open(&nlh, NETLINK_ROUTE);
	if (err)
		return err;

	err = -EINVAL;
	len = strlen(master);
	if (len == 1 || len >= IFNAMSIZ)
		goto out;

	len = strlen(name);
	if (len == 1 || len >= IFNAMSIZ)
		goto out;

	err = -ENOMEM;
	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		goto out;

	answer = nlmsg_alloc_reserve(NLMSG_GOOD_SIZE);
	if (!answer)
		goto out;

	err = -EINVAL;
	index = if_nametoindex(master);
	if (!index)
		goto out;

	nlmsg->nlmsghdr->nlmsg_flags =
		NLM_F_REQUEST|NLM_F_CREATE|NLM_F_EXCL|NLM_F_ACK;
	nlmsg->nlmsghdr->nlmsg_type = RTM_NEWLINK;

	ifi = nlmsg_reserve(nlmsg, sizeof(struct ifinfomsg));
	if (!ifi) {
		err = -ENOMEM;
		goto out;
	}
	ifi->ifi_family = AF_UNSPEC;

	nest = nla_begin_nested(nlmsg, IFLA_LINKINFO);
	if (!nest)
		goto out;

	if (nla_put_string(nlmsg, IFLA_INFO_KIND, "macvlan"))
		goto out;

	if (mode) {
		nest2 = nla_begin_nested(nlmsg, IFLA_INFO_DATA);
		if (!nest2)
			goto out;

		if (nla_put_u32(nlmsg, IFLA_MACVLAN_MODE, mode))
			goto out;

		nla_end_nested(nlmsg, nest2);
	}

	nla_end_nested(nlmsg, nest);

	if (nla_put_u32(nlmsg, IFLA_LINK, index))
		goto out;

	if (nla_put_string(nlmsg, IFLA_IFNAME, name))
		goto out;

	err = netlink_transaction(&nlh, nlmsg, answer);
out:
	netlink_close(&nlh);
	nlmsg_free(answer);
	nlmsg_free(nlmsg);
	return err;
}

static int proc_sys_net_write(const char *path, const char *value)
{
	int fd, err = 0;

	fd = open(path, O_WRONLY);
	if (fd < 0)
		return -errno;

	if (write(fd, value, strlen(value)) < 0)
		err = -errno;

	close(fd);
	return err;
}

static int ip_forward_set(const char *ifname, int family, int flag)
{
	char path[MAXPATHLEN];
	int rc;

	if (family != AF_INET && family != AF_INET6)
		return -EINVAL;

	rc = snprintf(path, MAXPATHLEN, "/proc/sys/net/%s/conf/%s/forwarding",
		 family == AF_INET?"ipv4":"ipv6" , ifname);
	if (rc >= MAXPATHLEN)
		return -E2BIG;

	return proc_sys_net_write(path, flag?"1":"0");
}

int lxc_ip_forward_on(const char *ifname, int family)
{
	return ip_forward_set(ifname, family, 1);
}

int lxc_ip_forward_off(const char *ifname, int family)
{
	return ip_forward_set(ifname, family, 0);
}

static int neigh_proxy_set(const char *ifname, int family, int flag)
{
	char path[MAXPATHLEN];
	int ret;

	if (family != AF_INET && family != AF_INET6)
		return -EINVAL;

	ret = snprintf(path, MAXPATHLEN, "/proc/sys/net/%s/conf/%s/%s",
		family == AF_INET?"ipv4":"ipv6" , ifname,
		family == AF_INET?"proxy_arp":"proxy_ndp");
	if (ret < 0 || ret >= MAXPATHLEN)
		return -E2BIG;

	return proc_sys_net_write(path, flag?"1":"0");
}

int lxc_neigh_proxy_on(const char *name, int family)
{
	return neigh_proxy_set(name, family, 1);
}

int lxc_neigh_proxy_off(const char *name, int family)
{
	return neigh_proxy_set(name, family, 0);
}

int lxc_convert_mac(char *macaddr, struct sockaddr *sockaddr)
{
	unsigned char *data;
	char c;
	int i = 0;
	unsigned val;

	sockaddr->sa_family = ARPHRD_ETHER;
	data = (unsigned char *)sockaddr->sa_data;

	while ((*macaddr != '\0') && (i < ETH_ALEN)) {
	    val = 0;
	    c = *macaddr++;
	    if (isdigit(c))
		    val = c - '0';
	    else if (c >= 'a' && c <= 'f')
		    val = c - 'a' + 10;
	    else if (c >= 'A' && c <= 'F')
		    val = c - 'A' + 10;
	    else {
		    return -EINVAL;
	    }
	    val <<= 4;
	    c = *macaddr;
	    if (isdigit(c))
		    val |= c - '0';
	    else if (c >= 'a' && c <= 'f')
		    val |= c - 'a' + 10;
	    else if (c >= 'A' && c <= 'F')
		    val |= c - 'A' + 10;
	    else if (c == ':' || c == 0)
		    val >>= 4;
	    else {
		    return -EINVAL;
	    }
	    if (c != 0)
		    macaddr++;
	    *data++ = (unsigned char) (val & 0377);
	    i++;

	    if (*macaddr == ':')
		    macaddr++;
	}

	return 0;
}

static int ip_addr_add(int family, int ifindex,
		       void *addr, void *bcast, void *acast, int prefix)
{
	struct nl_handler nlh;
	struct nlmsg *nlmsg = NULL, *answer = NULL;
	struct ifaddrmsg *ifa;
	int addrlen;
	int err;

	addrlen = family == AF_INET ? sizeof(struct in_addr) :
		sizeof(struct in6_addr);

	err = netlink_open(&nlh, NETLINK_ROUTE);
	if (err)
		return err;

	err = -ENOMEM;
	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		goto out;

	answer = nlmsg_alloc_reserve(NLMSG_GOOD_SIZE);
	if (!answer)
		goto out;

	nlmsg->nlmsghdr->nlmsg_flags =
		NLM_F_ACK|NLM_F_REQUEST|NLM_F_CREATE|NLM_F_EXCL;
	nlmsg->nlmsghdr->nlmsg_type = RTM_NEWADDR;

	ifa = nlmsg_reserve(nlmsg, sizeof(struct ifaddrmsg));
	if (!ifa)
		goto out;
	ifa->ifa_prefixlen = prefix;
	ifa->ifa_index = ifindex;
	ifa->ifa_family = family;
	ifa->ifa_scope = 0;

	err = -EINVAL;
	if (nla_put_buffer(nlmsg, IFA_LOCAL, addr, addrlen))
		goto out;

	if (nla_put_buffer(nlmsg, IFA_ADDRESS, addr, addrlen))
		goto out;

	if (nla_put_buffer(nlmsg, IFA_BROADCAST, bcast, addrlen))
		goto out;

	/* TODO : multicast, anycast with ipv6 */
	err = -EPROTONOSUPPORT;
	if (family == AF_INET6 &&
	    (memcmp(bcast, &in6addr_any, sizeof(in6addr_any)) ||
	     memcmp(acast, &in6addr_any, sizeof(in6addr_any))))
		goto out;

	err = netlink_transaction(&nlh, nlmsg, answer);
out:
	netlink_close(&nlh);
	nlmsg_free(answer);
	nlmsg_free(nlmsg);
	return err;
}

int lxc_ipv6_addr_add(int ifindex, struct in6_addr *addr,
		      struct in6_addr *mcast,
		      struct in6_addr *acast, int prefix)
{
	return ip_addr_add(AF_INET6, ifindex, addr, mcast, acast, prefix);
}

int lxc_ipv4_addr_add(int ifindex, struct in_addr *addr,
		      struct in_addr *bcast, int prefix)
{
	return ip_addr_add(AF_INET, ifindex, addr, bcast, NULL, prefix);
}

/* Find an IFA_LOCAL (or IFA_ADDRESS if not IFA_LOCAL is present)
 * address from the given RTM_NEWADDR message.  Allocates memory for the
 * address and stores that pointer in *res (so res should be an
 * in_addr** or in6_addr**).
 */
static int ifa_get_local_ip(int family, struct nlmsghdr *msg, void** res) {
	struct ifaddrmsg *ifa = NLMSG_DATA(msg);
	struct rtattr *rta = IFA_RTA(ifa);
	int attr_len = NLMSG_PAYLOAD(msg, sizeof(struct ifaddrmsg));
	int addrlen;

	if (ifa->ifa_family != family)
		return 0;

	addrlen = family == AF_INET ? sizeof(struct in_addr) :
		sizeof(struct in6_addr);

	/* Loop over the rtattr's in this message */
	while(RTA_OK(rta, attr_len)) {
		/* Found a local address for the requested interface,
		 * return it. */
		if (rta->rta_type == IFA_LOCAL || rta->rta_type == IFA_ADDRESS) {
			/* Sanity check. The family check above should
			 * make sure the address length is correct, but
			 * check here just in case */
			if (RTA_PAYLOAD(rta) != addrlen)
				return -1;

			/* We might have found an IFA_ADDRESS before,
			 * which we now overwrite with an IFA_LOCAL. */
			if (!*res) {
				*res = malloc(addrlen);
				if (!*res)
					return -1;
			}

			memcpy(*res, RTA_DATA(rta), addrlen);

			if (rta->rta_type == IFA_LOCAL)
				break;
		}
		rta = RTA_NEXT(rta, attr_len);
	}
	return 0;
}

static int ip_addr_get(int family, int ifindex, void **res)
{
	struct nl_handler nlh;
	struct nlmsg *nlmsg = NULL, *answer = NULL;
	struct ifaddrmsg *ifa;
	struct nlmsghdr *msg;
	int err;
	int recv_len = 0, answer_len;
	int readmore = 0;

	err = netlink_open(&nlh, NETLINK_ROUTE);
	if (err)
		return err;

	err = -ENOMEM;
	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		goto out;

	answer = nlmsg_alloc_reserve(NLMSG_GOOD_SIZE);
	if (!answer)
		goto out;

	/* Save the answer buffer length, since it will be overwritten
	 * on the first receive (and we might need to receive more than
	 * once. */
	answer_len = answer->nlmsghdr->nlmsg_len;

	nlmsg->nlmsghdr->nlmsg_flags = NLM_F_REQUEST|NLM_F_ROOT;
	nlmsg->nlmsghdr->nlmsg_type = RTM_GETADDR;

	ifa = nlmsg_reserve(nlmsg, sizeof(struct ifaddrmsg));
	if (!ifa)
		goto out;
	ifa->ifa_family = family;

	/* Send the request for addresses, which returns all addresses
	 * on all interfaces. */
	err = netlink_send(&nlh, nlmsg);
	if (err < 0)
		goto out;

	do {
		/* Restore the answer buffer length, it might have been
		 * overwritten by a previous receive. */
		answer->nlmsghdr->nlmsg_len = answer_len;

		/* Get the (next) batch of reply messages */
		err = netlink_rcv(&nlh, answer);
		if (err < 0)
			goto out;

		recv_len = err;
		err = 0;

		/* Satisfy the typing for the netlink macros */
		msg = answer->nlmsghdr;

		while (NLMSG_OK(msg, recv_len)) {
			/* Stop reading if we see an error message */
			if (msg->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *errmsg = (struct nlmsgerr*)NLMSG_DATA(msg);
				err = errmsg->error;
				goto out;
			}

			/* Stop reading if we see a NLMSG_DONE message */
			if (msg->nlmsg_type == NLMSG_DONE) {
				readmore = 0;
				break;
			}

			if (msg->nlmsg_type != RTM_NEWADDR) {
				err = -1;
				goto out;
			}

			ifa = (struct ifaddrmsg *)NLMSG_DATA(msg);
			if (ifa->ifa_index == ifindex) {
				if (ifa_get_local_ip(family, msg, res) < 0) {
					err = -1;
					goto out;
				}

				/* Found a result, stop searching */
				if (*res)
					goto out;
			}

			/* Keep reading more data from the socket if the
			 * last message had the NLF_F_MULTI flag set */
			readmore = (msg->nlmsg_flags & NLM_F_MULTI);

			/* Look at the next message received in this buffer */
			msg = NLMSG_NEXT(msg, recv_len);
		}
	} while (readmore);

	/* If we end up here, we didn't find any result, so signal an
	 * error */
	err = -1;

out:
	netlink_close(&nlh);
	nlmsg_free(answer);
	nlmsg_free(nlmsg);
	return err;
}

int lxc_ipv6_addr_get(int ifindex, struct in6_addr **res)
{
	return ip_addr_get(AF_INET6, ifindex, (void**)res);
}

int lxc_ipv4_addr_get(int ifindex, struct in_addr** res)
{
	return ip_addr_get(AF_INET, ifindex, (void**)res);
}

static int ip_gateway_add(int family, int ifindex, void *gw)
{
	struct nl_handler nlh;
	struct nlmsg *nlmsg = NULL, *answer = NULL;
	struct rtmsg *rt;
	int addrlen;
	int err;

	addrlen = family == AF_INET ? sizeof(struct in_addr) :
		sizeof(struct in6_addr);

	err = netlink_open(&nlh, NETLINK_ROUTE);
	if (err)
		return err;

	err = -ENOMEM;
	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		goto out;

	answer = nlmsg_alloc_reserve(NLMSG_GOOD_SIZE);
	if (!answer)
		goto out;

	nlmsg->nlmsghdr->nlmsg_flags =
		NLM_F_ACK|NLM_F_REQUEST|NLM_F_CREATE|NLM_F_EXCL;
	nlmsg->nlmsghdr->nlmsg_type = RTM_NEWROUTE;

	rt = nlmsg_reserve(nlmsg, sizeof(struct rtmsg));
	if (!rt)
		goto out;
	rt->rtm_family = family;
	rt->rtm_table = RT_TABLE_MAIN;
	rt->rtm_scope = RT_SCOPE_UNIVERSE;
	rt->rtm_protocol = RTPROT_BOOT;
	rt->rtm_type = RTN_UNICAST;
	/* "default" destination */
	rt->rtm_dst_len = 0;

	err = -EINVAL;
	if (nla_put_buffer(nlmsg, RTA_GATEWAY, gw, addrlen))
		goto out;

	/* Adding the interface index enables the use of link-local
	 * addresses for the gateway */
	if (nla_put_u32(nlmsg, RTA_OIF, ifindex))
		goto out;

	err = netlink_transaction(&nlh, nlmsg, answer);
out:
	netlink_close(&nlh);
	nlmsg_free(answer);
	nlmsg_free(nlmsg);
	return err;
}

int lxc_ipv4_gateway_add(int ifindex, struct in_addr *gw)
{
	return ip_gateway_add(AF_INET, ifindex, gw);
}

int lxc_ipv6_gateway_add(int ifindex, struct in6_addr *gw)
{
	return ip_gateway_add(AF_INET6, ifindex, gw);
}

static int ip_route_dest_add(int family, int ifindex, void *dest)
{
	struct nl_handler nlh;
	struct nlmsg *nlmsg = NULL, *answer = NULL;
	struct rtmsg *rt;
	int addrlen;
	int err;

	addrlen = family == AF_INET ? sizeof(struct in_addr) :
		sizeof(struct in6_addr);

	err = netlink_open(&nlh, NETLINK_ROUTE);
	if (err)
		return err;

	err = -ENOMEM;
	nlmsg = nlmsg_alloc(NLMSG_GOOD_SIZE);
	if (!nlmsg)
		goto out;

	answer = nlmsg_alloc_reserve(NLMSG_GOOD_SIZE);
	if (!answer)
		goto out;

	nlmsg->nlmsghdr->nlmsg_flags =
		NLM_F_ACK|NLM_F_REQUEST|NLM_F_CREATE|NLM_F_EXCL;
	nlmsg->nlmsghdr->nlmsg_type = RTM_NEWROUTE;

	rt = nlmsg_reserve(nlmsg, sizeof(struct rtmsg));
	if (!rt)
		goto out;
	rt->rtm_family = family;
	rt->rtm_table = RT_TABLE_MAIN;
	rt->rtm_scope = RT_SCOPE_LINK;
	rt->rtm_protocol = RTPROT_BOOT;
	rt->rtm_type = RTN_UNICAST;
	rt->rtm_dst_len = addrlen*8;

	err = -EINVAL;
	if (nla_put_buffer(nlmsg, RTA_DST, dest, addrlen))
		goto out;
	if (nla_put_u32(nlmsg, RTA_OIF, ifindex))
		goto out;
	err = netlink_transaction(&nlh, nlmsg, answer);
out:
	netlink_close(&nlh);
	nlmsg_free(answer);
	nlmsg_free(nlmsg);
	return err;
}

int lxc_ipv4_dest_add(int ifindex, struct in_addr *dest)
{
	return ip_route_dest_add(AF_INET, ifindex, dest);
}

int lxc_ipv6_dest_add(int ifindex, struct in6_addr *dest)
{
	return ip_route_dest_add(AF_INET6, ifindex, dest);
}

static bool is_ovs_bridge(const char *bridge)
{
	char brdirname[22 + IFNAMSIZ + 1] = {0};
	struct stat sb;

	snprintf(brdirname, 22 +IFNAMSIZ + 1, "/sys/class/net/%s/bridge", bridge);
	if (stat(brdirname, &sb) == -1 && errno == ENOENT)
		return true;
	return false;
}

/*
 * Called from a background thread - when nic goes away, remove
 * it from the bridge
 */
static void ovs_cleanup_nic(const char *lxcpath, const char *name, const char *bridge, const char *nic)
{
	if (lxc_check_inherited(NULL, true, -1) < 0)
		return;
	if (lxc_wait(name, "STOPPED", -1, lxcpath) < 0)
		return;
	execlp("ovs-vsctl", "ovs-vsctl", "del-port", bridge, nic, (char *)NULL);
	exit(1); /* not reached */
}

static int attach_to_ovs_bridge(const char *lxcpath, const char *name, const char *bridge, const char *nic)
{
	pid_t pid;
	char *cmd;
	int ret;

	cmd = on_path("ovs-vsctl", NULL);
	if (!cmd)
		return -1;
	free(cmd);

	pid = fork();
	if (pid < 0)
		return -1;
	if (pid > 0) {
		ret = wait_for_pid(pid);
		if (ret < 0)
			return ret;
		pid = fork();
		if (pid < 0)
			return -1;  // how to properly recover?
		if (pid > 0)
			return 0;
		ovs_cleanup_nic(lxcpath, name, bridge, nic);
		exit(0);
	}

	if (execlp("ovs-vsctl", "ovs-vsctl", "add-port", bridge, nic, (char *)NULL))
		exit(1);
	// not reached
	exit(1);
}

/*
 * There is a lxc_bridge_attach, but no need of a bridge detach
 * as automatically done by kernel when a netdev is deleted.
 */
int lxc_bridge_attach(const char *lxcpath, const char *name, const char *bridge, const char *ifname)
{
	int fd, index, err;
	struct ifreq ifr;

	if (strlen(ifname) >= IFNAMSIZ)
		return -EINVAL;

	index = if_nametoindex(ifname);
	if (!index)
		return -EINVAL;

	if (is_ovs_bridge(bridge))
		return attach_to_ovs_bridge(lxcpath, name, bridge, ifname);

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

static const char* const lxc_network_types[LXC_NET_MAXCONFTYPE + 1] = {
	[LXC_NET_EMPTY]   = "empty",
	[LXC_NET_VETH]    = "veth",
	[LXC_NET_MACVLAN] = "macvlan",
	[LXC_NET_PHYS]    = "phys",
	[LXC_NET_VLAN]    = "vlan",
	[LXC_NET_NONE]    = "none",
};

const char *lxc_net_type_to_str(int type)
{
	if (type < 0 || type > LXC_NET_MAXCONFTYPE)
		return NULL;
	return lxc_network_types[type];
}

static const char padchar[] =
"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

char *lxc_mkifname(char *template)
{
	char *name = NULL;
	size_t i = 0;
	FILE *urandom;
	unsigned int seed;
	struct ifaddrs *ifaddr, *ifa;
	int ifexists = 0;

	/* Get all the network interfaces */
	getifaddrs(&ifaddr);

	/* Initialize the random number generator */
	urandom = fopen ("/dev/urandom", "r");
	if (urandom != NULL) {
		if (fread (&seed, sizeof(seed), 1, urandom) <= 0)
			seed = time(0);
		fclose(urandom);
	}
	else
		seed = time(0);

#ifndef HAVE_RAND_R
	srand(seed);
#endif

	/* Generate random names until we find one that doesn't exist */
	while(1) {
		ifexists = 0;
		name = strdup(template);

		if (name == NULL)
			return NULL;

		for (i = 0; i < strlen(name); i++) {
			if (name[i] == 'X') {
#ifdef HAVE_RAND_R
				name[i] = padchar[rand_r(&seed) % (strlen(padchar) - 1)];
#else
				name[i] = padchar[rand() % (strlen(padchar) - 1)];
#endif
			}
		}

		for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
			if (strcmp(ifa->ifa_name, name) == 0) {
				ifexists = 1;
				break;
			}
		}

		if (ifexists == 0)
			break;

		free(name);
	}

	freeifaddrs(ifaddr);
	return name;
}

int setup_private_host_hw_addr(char *veth1)
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
