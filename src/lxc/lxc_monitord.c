/*
 * lxc: linux Container library
 *
 * Copyright © 2012 Oracle.
 *
 * Authors:
 * Dwight Engen <dwight.engen@oracle.com>
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
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <net/if.h>

#include "af_unix.h"
#include "log.h"
#include "mainloop.h"
#include "monitor.h"
#include "utils.h"

#define CLIENTFDS_CHUNK 64

lxc_log_define(lxc_monitord, lxc);

static void lxc_monitord_cleanup(void);

/*
 * Defines the structure to store the monitor information
 * @lxcpath        : the path being monitored
 * @fifofd         : the file descriptor for publishers (containers) to write state
 * @listenfd       : the file descriptor for subscribers (lxc-monitors) to connect
 * @clientfds      : accepted client file descriptors
 * @clientfds_size : number of file descriptors clientfds can hold
 * @clientfds_cnt  : the count of valid fds in clientfds
 * @descr          : the lxc_mainloop state
 */
struct lxc_monitor {
	const char *lxcpath;
	int fifofd;
	int listenfd;
	int *clientfds;
	int clientfds_size;
	int clientfds_cnt;
	struct lxc_epoll_descr descr;
};

static struct lxc_monitor mon;
static int quit;

static int lxc_monitord_fifo_create(struct lxc_monitor *mon)
{
	struct flock lk;
	char fifo_path[PATH_MAX];
	int ret;

	ret = lxc_monitor_fifo_name(mon->lxcpath, fifo_path, sizeof(fifo_path), 1);
	if (ret < 0)
		return ret;

	ret = mknod(fifo_path, S_IFIFO|S_IRUSR|S_IWUSR, 0);
	if (ret < 0 && errno != EEXIST) {
		INFO("failed to mknod monitor fifo %s %s", fifo_path, strerror(errno));
		return -1;
	}

	mon->fifofd = open(fifo_path, O_RDWR);
	if (mon->fifofd < 0) {
		unlink(fifo_path);
		ERROR("failed to open monitor fifo");
		return -1;
	}

	lk.l_type = F_WRLCK;
	lk.l_whence = SEEK_SET;
	lk.l_start = 0;
	lk.l_len = 0;
	if (fcntl(mon->fifofd, F_SETLK, &lk) != 0) {
		/* another lxc-monitord is already running, don't start up */
		DEBUG("lxc-monitord already running on lxcpath %s", mon->lxcpath);
		close(mon->fifofd);
		return -1;
	}
	return 0;
}

static int lxc_monitord_fifo_delete(struct lxc_monitor *mon)
{
	char fifo_path[PATH_MAX];
	int ret;

	ret = lxc_monitor_fifo_name(mon->lxcpath, fifo_path, sizeof(fifo_path), 0);
	if (ret < 0)
		return ret;

	unlink(fifo_path);
	return 0;
}

static void lxc_monitord_sockfd_remove(struct lxc_monitor *mon, int fd) {
	int i;

	if (lxc_mainloop_del_handler(&mon->descr, fd))
		CRIT("fd:%d not found in mainloop", fd);
	close(fd);

	for (i = 0; i < mon->clientfds_cnt; i++) {
		if (mon->clientfds[i] == fd)
			break;
	}
	if (i >= mon->clientfds_cnt) {
		CRIT("fd:%d not found in clients array", fd);
		lxc_monitord_cleanup();
		exit(EXIT_FAILURE);
	}

	memmove(&mon->clientfds[i], &mon->clientfds[i+1],
		(mon->clientfds_cnt - i - 1) * sizeof(mon->clientfds[0]));
	mon->clientfds_cnt--;
}

static int lxc_monitord_sock_handler(int fd, uint32_t events, void *data,
				     struct lxc_epoll_descr *descr)
{
	struct lxc_monitor *mon = data;

	if (events & EPOLLIN) {
		int rc;
		char buf[4];

		rc = read(fd, buf, sizeof(buf));
		if (rc > 0 && !strncmp(buf, "quit", 4))
			quit = 1;
	}

	if (events & EPOLLHUP)
		lxc_monitord_sockfd_remove(mon, fd);
	return quit;
}

static int lxc_monitord_sock_accept(int fd, uint32_t events, void *data,
				    struct lxc_epoll_descr *descr)
{
	int ret,clientfd;
	struct lxc_monitor *mon = data;
	struct ucred cred;
	socklen_t credsz = sizeof(cred);

	ret = -1;
	clientfd = accept(fd, NULL, 0);
	if (clientfd < 0) {
		SYSERROR("failed to accept connection");
		goto out;
	}

	if (fcntl(clientfd, F_SETFD, FD_CLOEXEC)) {
		SYSERROR("failed to set close-on-exec on incoming connection");
		goto err1;
	}

	if (getsockopt(clientfd, SOL_SOCKET, SO_PEERCRED, &cred, &credsz))
	{
		ERROR("failed to get credentials on socket");
		goto err1;
	}
	if (cred.uid && cred.uid != geteuid()) {
		WARN("monitor denied for uid:%d", cred.uid);
		ret = -EACCES;
		goto err1;
	}

	if (mon->clientfds_cnt + 1 > mon->clientfds_size) {
		int *clientfds;
		DEBUG("realloc space for %d clientfds",
		      mon->clientfds_size + CLIENTFDS_CHUNK);
		clientfds = realloc(mon->clientfds,
				    (mon->clientfds_size + CLIENTFDS_CHUNK) *
				     sizeof(mon->clientfds[0]));
		if (clientfds == NULL) {
			ERROR("failed to realloc memory for clientfds");
			goto err1;
		}
		mon->clientfds = clientfds;
		mon->clientfds_size += CLIENTFDS_CHUNK;
	}

	ret = lxc_mainloop_add_handler(&mon->descr, clientfd,
				       lxc_monitord_sock_handler, mon);
	if (ret) {
		ERROR("failed to add socket handler");
		goto err1;
	}

	mon->clientfds[mon->clientfds_cnt++] = clientfd;
	INFO("accepted client fd:%d clients:%d", clientfd, mon->clientfds_cnt);
	goto out;

err1:
	close(clientfd);
out:
	return ret;
}

static int lxc_monitord_sock_create(struct lxc_monitor *mon)
{
	struct sockaddr_un addr;
	int fd;

	if (lxc_monitor_sock_name(mon->lxcpath, &addr) < 0)
		return -1;

	fd = lxc_abstract_unix_open(addr.sun_path, SOCK_STREAM, O_TRUNC);
	if (fd < 0) {
		ERROR("failed to open unix socket : %s", strerror(errno));
		return -1;
	}

	mon->listenfd = fd;
	return 0;
}

static int lxc_monitord_sock_delete(struct lxc_monitor *mon)
{
	struct sockaddr_un addr;

	if (lxc_monitor_sock_name(mon->lxcpath, &addr) < 0)
		return -1;
	if (addr.sun_path[0])
		unlink(addr.sun_path);
	return 0;
}

static int lxc_monitord_create(struct lxc_monitor *mon)
{
	int ret;

	ret = lxc_monitord_fifo_create(mon);
	if (ret < 0)
		return ret;

	ret = lxc_monitord_sock_create(mon);
	return ret;
}

static void lxc_monitord_delete(struct lxc_monitor *mon)
{
	int i;

	lxc_mainloop_del_handler(&mon->descr, mon->listenfd);
	close(mon->listenfd);
	lxc_monitord_sock_delete(mon);

	lxc_mainloop_del_handler(&mon->descr, mon->fifofd);
	lxc_monitord_fifo_delete(mon);
	close(mon->fifofd);

	for (i = 0; i < mon->clientfds_cnt; i++) {
		lxc_mainloop_del_handler(&mon->descr, mon->clientfds[i]);
		close(mon->clientfds[i]);
	}
	mon->clientfds_cnt = 0;
}

static int lxc_monitord_fifo_handler(int fd, uint32_t events, void *data,
				     struct lxc_epoll_descr *descr)
{
	int ret,i;
	struct lxc_msg msglxc;
	struct lxc_monitor *mon = data;

	ret = read(fd, &msglxc, sizeof(msglxc));
	if (ret != sizeof(msglxc)) {
		SYSERROR("read fifo failed : %s", strerror(errno));
		return 1;
	}

	for (i = 0; i < mon->clientfds_cnt; i++) {
		DEBUG("writing client fd:%d", mon->clientfds[i]);
		ret = write(mon->clientfds[i], &msglxc, sizeof(msglxc));
		if (ret < 0) {
			ERROR("write failed to client sock:%d %d %s",
			      mon->clientfds[i], errno, strerror(errno));
		}
	}

	return 0;
}

static int lxc_monitord_mainloop_add(struct lxc_monitor *mon)
{
	int ret;

	ret = lxc_mainloop_add_handler(&mon->descr, mon->fifofd,
				       lxc_monitord_fifo_handler, mon);
	if (ret < 0) {
		ERROR("failed to add to mainloop monitor handler for fifo");
		return -1;
	}

	ret = lxc_mainloop_add_handler(&mon->descr, mon->listenfd,
				       lxc_monitord_sock_accept, mon);
	if (ret < 0) {
		ERROR("failed to add to mainloop monitor handler for listen socket");
		return -1;
	}

	return 0;
}

static void lxc_monitord_cleanup(void)
{
	lxc_monitord_delete(&mon);
}

static void lxc_monitord_sig_handler(int sig)
{
	INFO("caught signal %d", sig);
	lxc_monitord_cleanup();
	exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
	int ret,pipefd;
	char *lxcpath = argv[1];
	char logpath[PATH_MAX];
	sigset_t mask;

	if (argc != 3) {
		fprintf(stderr,
			"Usage: lxc-monitord lxcpath sync-pipe-fd\n\n"
			"NOTE: lxc-monitord is intended for use by lxc internally\n"
			"      and does not need to be run by hand\n\n");
		exit(EXIT_FAILURE);
	}

	ret = snprintf(logpath, sizeof(logpath), "%s/lxc-monitord.log",
		       (strcmp(LXCPATH, lxcpath) ? lxcpath : LOGPATH ) );
	if (ret < 0 || ret >= sizeof(logpath))
		return EXIT_FAILURE;

	ret = lxc_log_init(NULL, logpath, "NOTICE", "lxc-monitord", 0, lxcpath);
	if (ret)
		INFO("Failed to open log file %s, log will be lost", lxcpath);
	lxc_log_options_no_override();

	pipefd = atoi(argv[2]);

	if (sigfillset(&mask) ||
	    sigdelset(&mask, SIGILL)  ||
	    sigdelset(&mask, SIGSEGV) ||
	    sigdelset(&mask, SIGBUS)  ||
	    sigdelset(&mask, SIGTERM) ||
	    sigprocmask(SIG_BLOCK, &mask, NULL)) {
		SYSERROR("failed to set signal mask");
		return 1;
	}

	signal(SIGILL,  lxc_monitord_sig_handler);
	signal(SIGSEGV, lxc_monitord_sig_handler);
	signal(SIGBUS,  lxc_monitord_sig_handler);
	signal(SIGTERM, lxc_monitord_sig_handler);

	ret = EXIT_FAILURE;
	memset(&mon, 0, sizeof(mon));
	mon.lxcpath = lxcpath;
	if (lxc_mainloop_open(&mon.descr)) {
		ERROR("failed to create mainloop");
		goto out;
	}

	if (lxc_monitord_create(&mon)) {
		goto out;
	}

	/* sync with parent, we're ignoring the return from write
	 * because regardless if it works or not, the following
	 * close will sync us with the parent process. the
	 * if-empty-statement construct is to quiet the
	 * warn-unused-result warning.
	 */
	if (write(pipefd, "S", 1))
		;
	close(pipefd);

	if (lxc_monitord_mainloop_add(&mon)) {
		ERROR("failed to add mainloop handlers");
		goto out;
	}

	NOTICE("pid:%d monitoring lxcpath %s", getpid(), mon.lxcpath);
	for(;;) {
		ret = lxc_mainloop(&mon.descr, 1000 * 30);
		if (mon.clientfds_cnt <= 0)
		{
			NOTICE("no remaining clients, exiting");
			break;
		}
	}

	lxc_mainloop_close(&mon.descr);
	lxc_monitord_cleanup();
	ret = EXIT_SUCCESS;
	NOTICE("monitor exiting");
out:
	if (ret == 0)
		return 0;
	return 1;
}
