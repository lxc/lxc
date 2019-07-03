/*
 * lxc: linux Container library
 *
 * (C) Copyright Canonical, Inc. 2012
 *
 * Authors:
 * Serge Hallyn <serge.hallyn@canonical.com>
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

struct seccomp_notify_proxy_msg {
	uint32_t version;
	struct seccomp_notif req;
	struct seccomp_notif_resp resp;
	pid_t monitor_pid;
	pid_t init_pid;
};

struct seccomp_notify {
	bool wants_supervision;
	int notify_fd;
	int proxy_fd;
	struct sockaddr_un proxy_addr;
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

extern int lxc_seccomp_load(struct lxc_conf *conf);
extern int lxc_read_seccomp_config(struct lxc_conf *conf);
extern void lxc_seccomp_free(struct lxc_seccomp *seccomp);
extern int seccomp_notify_handler(int fd, uint32_t events, void *data,
				  struct lxc_epoll_descr *descr);
extern void seccomp_conf_init(struct lxc_conf *conf);
extern int lxc_seccomp_setup_proxy(struct lxc_seccomp *seccomp,
				   struct lxc_epoll_descr *descr,
				   struct lxc_handler *handler);
extern int lxc_seccomp_send_notifier_fd(struct lxc_seccomp *seccomp,
					int socket_fd);
extern int lxc_seccomp_recv_notifier_fd(struct lxc_seccomp *seccomp,
					int socket_fd);
extern int lxc_seccomp_add_notifier(const char *name, const char *lxcpath,
				    struct lxc_seccomp *seccomp);
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

#endif /* HAVE_SECCOMP */
#endif /* __LXC_LXCSECCOMP_H */
