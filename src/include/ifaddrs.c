#define _GNU_SOURCE
#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "ifaddrs.h"

#define IFADDRS_HASH_SIZE 64

#define __NETLINK_ALIGN(len) (((len) + 3) & ~3)

#define __NLMSG_OK(nlh, end) \
	((char *)(end) - (char *)(nlh) >= sizeof(struct nlmsghdr))

#define __NLMSG_NEXT(nlh) \
	(struct nlmsghdr *)((char *)(nlh) + __NETLINK_ALIGN((nlh)->nlmsg_len))

#define __NLMSG_DATA(nlh) ((void *)((char *)(nlh) + sizeof(struct nlmsghdr)))

#define __NLMSG_DATAEND(nlh) ((char *)(nlh) + (nlh)->nlmsg_len)

#define __NLMSG_RTA(nlh, len)                               \
	((void *)((char *)(nlh) + sizeof(struct nlmsghdr) + \
		  __NETLINK_ALIGN(len)))

#define __RTA_DATALEN(rta) ((rta)->rta_len - sizeof(struct rtattr))

#define __RTA_NEXT(rta) \
	(struct rtattr *)((char *)(rta) + __NETLINK_ALIGN((rta)->rta_len))

#define __RTA_OK(nlh, end) \
	((char *)(end) - (char *)(rta) >= sizeof(struct rtattr))

#define __NLMSG_RTAOK(rta, nlh) __RTA_OK(rta, __NLMSG_DATAEND(nlh))

#define __IN6_IS_ADDR_LINKLOCAL(a) \
	((((uint8_t *)(a))[0]) == 0xfe && (((uint8_t *)(a))[1] & 0xc0) == 0x80)

#define __IN6_IS_ADDR_MC_LINKLOCAL(a) \
	(IN6_IS_ADDR_MULTICAST(a) && ((((uint8_t *)(a))[1] & 0xf) == 0x2))

#define __RTA_DATA(rta) ((void *)((char *)(rta) + sizeof(struct rtattr)))

/* getifaddrs() reports hardware addresses with PF_PACKET that implies
 * struct sockaddr_ll.  But e.g. Infiniband socket address length is
 * longer than sockaddr_ll.ssl_addr[8] can hold. Use this hack struct
 * to extend ssl_addr - callers should be able to still use it. */
struct sockaddr_ll_hack {
	unsigned short sll_family, sll_protocol;
	int sll_ifindex;
	unsigned short sll_hatype;
	unsigned char sll_pkttype, sll_halen;
	unsigned char sll_addr[24];
};

union sockany {
	struct sockaddr sa;
	struct sockaddr_ll_hack ll;
	struct sockaddr_in v4;
	struct sockaddr_in6 v6;
};

struct ifaddrs_storage {
	struct ifaddrs ifa;
	struct ifaddrs_storage *hash_next;
	union sockany addr, netmask, ifu;
	unsigned int index;
	char name[IFNAMSIZ + 1];
};

struct ifaddrs_ctx {
	struct ifaddrs_storage *first;
	struct ifaddrs_storage *last;
	struct ifaddrs_storage *hash[IFADDRS_HASH_SIZE];
};

void freeifaddrs(struct ifaddrs *ifp)
{
	struct ifaddrs *n;

	while (ifp) {
		n = ifp->ifa_next;
		free(ifp);
		ifp = n;
	}
}

static void copy_addr(struct sockaddr **r, int af, union sockany *sa,
		      void *addr, size_t addrlen, int ifindex)
{
	uint8_t *dst;
	size_t len;

	switch (af) {
	case AF_INET:
		dst = (uint8_t *)&sa->v4.sin_addr;
		len = 4;
		break;
	case AF_INET6:
		dst = (uint8_t *)&sa->v6.sin6_addr;
		len = 16;
		if (__IN6_IS_ADDR_LINKLOCAL(addr) || __IN6_IS_ADDR_MC_LINKLOCAL(addr))
			sa->v6.sin6_scope_id = ifindex;
		break;
	default:
		return;
	}

	if (addrlen < len)
		return;

	sa->sa.sa_family = af;

	memcpy(dst, addr, len);

	*r = &sa->sa;
}

static void gen_netmask(struct sockaddr **r, int af, union sockany *sa,
			int prefixlen)
{
	uint8_t addr[16] = {0};
	int i;

	if ((size_t)prefixlen > 8 * sizeof(addr))
		prefixlen = 8 * sizeof(addr);

	i = prefixlen / 8;

	memset(addr, 0xff, i);

	if ((size_t)i < sizeof(addr))
		addr[i++] = 0xff << (8 - (prefixlen % 8));

	copy_addr(r, af, sa, addr, sizeof(addr), 0);
}

static void copy_lladdr(struct sockaddr **r, union sockany *sa, void *addr,
			size_t addrlen, int ifindex, unsigned short hatype)
{
	if (addrlen > sizeof(sa->ll.sll_addr))
		return;

	sa->ll.sll_family = AF_PACKET;
	sa->ll.sll_ifindex = ifindex;
	sa->ll.sll_hatype = hatype;
	sa->ll.sll_halen = addrlen;

	memcpy(sa->ll.sll_addr, addr, addrlen);

	*r = &sa->sa;
}

static int nl_msg_to_ifaddr(void *pctx, struct nlmsghdr *h)
{
	struct ifaddrs_storage *ifs, *ifs0;
	struct rtattr *rta;
	int stats_len = 0;
	struct ifinfomsg *ifi = __NLMSG_DATA(h);
	struct ifaddrmsg *ifa = __NLMSG_DATA(h);
	struct ifaddrs_ctx *ctx = pctx;

	if (h->nlmsg_type == RTM_NEWLINK) {
		for (rta = __NLMSG_RTA(h, sizeof(*ifi)); __NLMSG_RTAOK(rta, h);
		     rta = __RTA_NEXT(rta)) {
			if (rta->rta_type != IFLA_STATS)
				continue;

			stats_len = __RTA_DATALEN(rta);
			break;
		}
	} else {
		for (ifs0 = ctx->hash[ifa->ifa_index % IFADDRS_HASH_SIZE]; ifs0;
		     ifs0 = ifs0->hash_next)
			if (ifs0->index == ifa->ifa_index)
				break;
		if (!ifs0)
			return 0;
	}

	ifs = calloc(1, sizeof(struct ifaddrs_storage) + stats_len);
	if (!ifs) {
		errno = ENOMEM;
		return -1;
	}

	if (h->nlmsg_type == RTM_NEWLINK) {
		ifs->index = ifi->ifi_index;
		ifs->ifa.ifa_flags = ifi->ifi_flags;

		for (rta = __NLMSG_RTA(h, sizeof(*ifi)); __NLMSG_RTAOK(rta, h);
		     rta = __RTA_NEXT(rta)) {
			switch (rta->rta_type) {
			case IFLA_IFNAME:
				if (__RTA_DATALEN(rta) < sizeof(ifs->name)) {
					memcpy(ifs->name, __RTA_DATA(rta),
					       __RTA_DATALEN(rta));
					ifs->ifa.ifa_name = ifs->name;
				}
				break;
			case IFLA_ADDRESS:
				copy_lladdr(&ifs->ifa.ifa_addr, &ifs->addr,
					    __RTA_DATA(rta), __RTA_DATALEN(rta),
					    ifi->ifi_index, ifi->ifi_type);
				break;
			case IFLA_BROADCAST:
				copy_lladdr(&ifs->ifa.ifa_broadaddr, &ifs->ifu,
					    __RTA_DATA(rta), __RTA_DATALEN(rta),
					    ifi->ifi_index, ifi->ifi_type);
				break;
			case IFLA_STATS:
				ifs->ifa.ifa_data = (void *)(ifs + 1);
				memcpy(ifs->ifa.ifa_data, __RTA_DATA(rta),
				       __RTA_DATALEN(rta));
				break;
			}
		}

		if (ifs->ifa.ifa_name) {
			unsigned int bucket = ifs->index % IFADDRS_HASH_SIZE;
			ifs->hash_next = ctx->hash[bucket];
			ctx->hash[bucket] = ifs;
		}
	} else {
		ifs->ifa.ifa_name = ifs0->ifa.ifa_name;
		ifs->ifa.ifa_flags = ifs0->ifa.ifa_flags;

		for (rta = __NLMSG_RTA(h, sizeof(*ifa)); __NLMSG_RTAOK(rta, h);
		     rta = __RTA_NEXT(rta)) {
			switch (rta->rta_type) {
			case IFA_ADDRESS:
				/* If ifa_addr is already set we, received an
				 * IFA_LOCAL before so treat this as destination
				 * address.
				 */
				if (ifs->ifa.ifa_addr)
					copy_addr(&ifs->ifa.ifa_dstaddr,
						  ifa->ifa_family, &ifs->ifu,
						  __RTA_DATA(rta),
						  __RTA_DATALEN(rta),
						  ifa->ifa_index);
				else
					copy_addr(&ifs->ifa.ifa_addr,
						  ifa->ifa_family, &ifs->addr,
						  __RTA_DATA(rta),
						  __RTA_DATALEN(rta),
						  ifa->ifa_index);
				break;
			case IFA_BROADCAST:
				copy_addr(&ifs->ifa.ifa_broadaddr,
					  ifa->ifa_family, &ifs->ifu,
					  __RTA_DATA(rta), __RTA_DATALEN(rta),
					  ifa->ifa_index);
				break;
			case IFA_LOCAL:
				/* If ifa_addr is set and we get IFA_LOCAL,
				 * assume we have a point-to-point network. Move
				 * address to correct field.
				 */
				if (ifs->ifa.ifa_addr) {
					ifs->ifu = ifs->addr;
					ifs->ifa.ifa_dstaddr = &ifs->ifu.sa;

					memset(&ifs->addr, 0, sizeof(ifs->addr));
				}

				copy_addr(&ifs->ifa.ifa_addr, ifa->ifa_family,
					  &ifs->addr, __RTA_DATA(rta),
					  __RTA_DATALEN(rta), ifa->ifa_index);
				break;
			case IFA_LABEL:
				if (__RTA_DATALEN(rta) < sizeof(ifs->name)) {
					memcpy(ifs->name, __RTA_DATA(rta),
					       __RTA_DATALEN(rta));
					ifs->ifa.ifa_name = ifs->name;
				}
				break;
			}
		}

		if (ifs->ifa.ifa_addr)
			gen_netmask(&ifs->ifa.ifa_netmask, ifa->ifa_family,
				    &ifs->netmask, ifa->ifa_prefixlen);
	}

	if (ifs->ifa.ifa_name) {
		if (!ctx->first)
			ctx->first = ifs;

		if (ctx->last)
			ctx->last->ifa.ifa_next = &ifs->ifa;

		ctx->last = ifs;
	} else {
		free(ifs);
	}

	return 0;
}

static int __nl_recv(int fd, unsigned int seq, int type, int af,
			       int (*cb)(void *ctx, struct nlmsghdr *h),
			       void *ctx)
{
	struct nlmsghdr *h;
	union {
		uint8_t buf[8192];
		struct {
			struct nlmsghdr nlh;
			struct rtgenmsg g;
		} req;
		struct nlmsghdr reply;
	} u;
	int r, ret;

	memset(&u.req, 0, sizeof(u.req));
	u.req.nlh.nlmsg_len = sizeof(u.req);
	u.req.nlh.nlmsg_type = type;
	u.req.nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
	u.req.nlh.nlmsg_seq = seq;
	u.req.g.rtgen_family = af;
	r = send(fd, &u.req, sizeof(u.req), 0);
	if (r < 0)
		return r;

	for (;;) {
		r = recv(fd, u.buf, sizeof(u.buf), MSG_DONTWAIT);
		if (r <= 0)
			return -1;

		for (h = &u.reply; __NLMSG_OK(h, (void *)&u.buf[r]);
		     h = __NLMSG_NEXT(h)) {
			if (h->nlmsg_type == NLMSG_DONE)
				return 0;

			if (h->nlmsg_type == NLMSG_ERROR) {
				errno = EINVAL;
				return -1;
			}

			ret = cb(ctx, h);
			if (ret)
				return ret;
		}
	}
}

static int __rtnl_enumerate(int link_af, int addr_af,
			    int (*cb)(void *ctx, struct nlmsghdr *h), void *ctx)
{
	int fd, r, saved_errno;

	fd = socket(PF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (fd < 0)
		return -1;

	r = __nl_recv(fd, 1, RTM_GETLINK, link_af, cb, ctx);
	if (!r)
		r = __nl_recv(fd, 2, RTM_GETADDR, addr_af, cb, ctx);

	saved_errno = errno;
	close(fd);
	errno = saved_errno;

	return r;
}

int getifaddrs(struct ifaddrs **ifap)
{
	int r, saved_errno;
	struct ifaddrs_ctx _ctx;
	struct ifaddrs_ctx *ctx = &_ctx;

	memset(ctx, 0, sizeof *ctx);

	r = __rtnl_enumerate(AF_UNSPEC, AF_UNSPEC, nl_msg_to_ifaddr, ctx);
	saved_errno = errno;
	if (r < 0)
		freeifaddrs(&ctx->first->ifa);
	else
		*ifap = &ctx->first->ifa;
	errno = saved_errno;

	return r;
}
