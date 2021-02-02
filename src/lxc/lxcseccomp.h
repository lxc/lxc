/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_LXCSECCOMP_H
#define __LXC_LXCSECCOMP_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <errno.h>
#ifdef HAVE_SECCOMP
#include <linux/seccomp.h>
#include <seccomp.h>
#endif
#if HAVE_DECL_SECCOMP_NOTIFY_FD
#include <sys/socket.h>
#include <sys/un.h>
#endif

#include "compiler.h"
#include "conf.h"
#include "config.h"
#include "memory_utils.h"

struct lxc_conf;
struct lxc_epoll_descr;
struct lxc_handler;

#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
#endif

#ifdef HAVE_SECCOMP


#if HAVE_DECL_SECCOMP_NOTIFY_FD

#if !HAVE_STRUCT_SECCOMP_NOTIF_SIZES
struct seccomp_notif_sizes {
	__u16 seccomp_notif;
	__u16 seccomp_notif_resp;
	__u16 seccomp_data;
};
#endif

struct seccomp_notify_proxy_msg {
	uint64_t __reserved;
	pid_t monitor_pid;
	pid_t init_pid;
	struct seccomp_notif_sizes sizes;
	uint64_t cookie_len;
	/* followed by: seccomp_notif, seccomp_notif_resp, cookie */
};

struct seccomp_notify {
	bool wants_supervision;
	int notify_fd;
	int proxy_fd;
	struct sockaddr_un proxy_addr;
	struct seccomp_notif_sizes sizes;
	struct seccomp_notif *req_buf;
	struct seccomp_notif_resp *rsp_buf;
	char *cookie;
};

#define HAVE_SECCOMP_NOTIFY 1

#endif /* HAVE_DECL_SECCOMP_NOTIFY_FD */

struct lxc_seccomp {
	char *seccomp;
#if HAVE_SCMP_FILTER_CTX
	unsigned int allow_nesting;
	scmp_filter_ctx seccomp_ctx;
#endif /* HAVE_SCMP_FILTER_CTX */

#if HAVE_DECL_SECCOMP_NOTIFY_FD
	struct seccomp_notify notifier;
#endif /* HAVE_DECL_SECCOMP_NOTIFY_FD */
};

__hidden extern int lxc_seccomp_load(struct lxc_conf *conf);
__hidden extern int lxc_read_seccomp_config(struct lxc_conf *conf);
__hidden extern void lxc_seccomp_free(struct lxc_seccomp *seccomp);
__hidden extern int seccomp_notify_handler(int fd, uint32_t events, void *data,
					   struct lxc_epoll_descr *descr);
__hidden extern void seccomp_conf_init(struct lxc_conf *conf);
__hidden extern int lxc_seccomp_setup_proxy(struct lxc_seccomp *seccomp,
					    struct lxc_epoll_descr *descr,
					    struct lxc_handler *handler);
__hidden extern int lxc_seccomp_send_notifier_fd(struct lxc_seccomp *seccomp, int socket_fd);
__hidden extern int lxc_seccomp_recv_notifier_fd(struct lxc_seccomp *seccomp, int socket_fd);
__hidden extern int lxc_seccomp_add_notifier(const char *name, const char *lxcpath,
					     struct lxc_seccomp *seccomp);
static inline void lxc_seccomp_close_notifier_fd(struct lxc_seccomp *seccomp)
{
#if HAVE_DECL_SECCOMP_NOTIFY_FD
	if (seccomp->notifier.wants_supervision)
		close_prot_errno_disarm(seccomp->notifier.notify_fd);
#endif
}

static inline int lxc_seccomp_get_notify_fd(struct lxc_seccomp *seccomp)
{
#if HAVE_DECL_SECCOMP_NOTIFY_FD
	return seccomp->notifier.notify_fd;
#else
	errno = ENOSYS;
	return -EBADF;
#endif
}

#else /* HAVE_SECCOMP */

struct lxc_seccomp {
	char *seccomp;
};

static inline int lxc_seccomp_load(struct lxc_conf *conf)
{
	return 0;
}

static inline int lxc_read_seccomp_config(struct lxc_conf *conf)
{
	return 0;
}

static inline void lxc_seccomp_free(struct lxc_seccomp *seccomp)
{
	free_disarm(seccomp->seccomp);
}

static inline int seccomp_notify_handler(int fd, uint32_t events, void *data,
				  struct lxc_epoll_descr *descr)
{
	return -ENOSYS;
}

static inline void seccomp_conf_init(struct lxc_conf *conf)
{
}

static inline int lxc_seccomp_setup_proxy(struct lxc_seccomp *seccomp,
					  struct lxc_epoll_descr *descr,
					  struct lxc_handler *handler)
{
	return 0;
}

static inline int lxc_seccomp_send_notifier_fd(struct lxc_seccomp *seccomp,
					       int socket_fd)
{
	return 0;
}

static inline int lxc_seccomp_recv_notifier_fd(struct lxc_seccomp *seccomp,
					int socket_fd)
{
	return 0;
}

static inline int lxc_seccomp_add_notifier(const char *name, const char *lxcpath,
					   struct lxc_seccomp *seccomp)
{
	return 0;
}

static inline int lxc_seccomp_get_notify_fd(struct lxc_seccomp *seccomp)
{
	return -EBADF;
}

static inline void lxc_seccomp_close_notifier_fd(struct lxc_seccomp *seccomp)
{
}

#endif /* HAVE_SECCOMP */
#endif /* __LXC_LXCSECCOMP_H */
