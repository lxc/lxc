/* SPDX-License-Identifier: LGPL-2.1+ */

#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "lxc.h"

#include "af_unix.h"
#include "log.h"
#include "mainloop.h"
#include "monitor.h"
#include "process_utils.h"
#include "utils.h"

#define CLIENTFDS_CHUNK 64

lxc_log_define(lxc_monitord, lxc);

sigjmp_buf mark;

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
	struct lxc_async_descr descr;
};

static struct lxc_monitor monitor;
static int quit;

static int lxc_monitord_fifo_create(struct lxc_monitor *mon)
{
	struct flock lk;
	char fifo_path[PATH_MAX];
	int ret;

	ret = lxc_monitor_fifo_name(mon->lxcpath, fifo_path, sizeof(fifo_path), 1);
	if (ret < 0)
		return ret;

	ret = mknod(fifo_path, S_IFIFO | S_IRUSR | S_IWUSR, 0);
	if (ret < 0 && errno != EEXIST) {
		SYSINFO("Failed to mknod monitor fifo %s", fifo_path);
		return -1;
	}

	mon->fifofd = open(fifo_path, O_RDWR);
	if (mon->fifofd < 0) {
		SYSERROR("Failed to open monitor fifo %s", fifo_path);
		unlink(fifo_path);
		return -1;
	}

	lk.l_type = F_WRLCK;
	lk.l_whence = SEEK_SET;
	lk.l_start = 0;
	lk.l_len = 0;

	if (fcntl(mon->fifofd, F_SETLK, &lk) != 0) {
		/* another lxc-monitord is already running, don't start up */
		SYSDEBUG("lxc-monitord already running on lxcpath %s", mon->lxcpath);
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

static int lxc_monitord_sockfd_remove(struct lxc_monitor *mon, int fd)
{
	int i;

	for (i = 0; i < mon->clientfds_cnt; i++)
		if (mon->clientfds[i] == fd)
			break;

	if (i >= mon->clientfds_cnt) {
		CRIT("File descriptor %d not found in clients array", fd);
		return LXC_MAINLOOP_ERROR;
	}

	memmove(&mon->clientfds[i], &mon->clientfds[i+1],
		(mon->clientfds_cnt - i - 1) * sizeof(mon->clientfds[0]));
	mon->clientfds_cnt--;
	return LXC_MAINLOOP_DISARM;
}

static int lxc_monitord_sock_handler(int fd, uint32_t events, void *data,
				     struct lxc_async_descr *descr)
{
	struct lxc_monitor *mon = data;

	if (events & EPOLLIN) {
		int rc;
		char buf[4];

		rc = lxc_read_nointr(fd, buf, sizeof(buf));
		if (rc > 0 && !strncmp(buf, "quit", 4)) {
			quit = LXC_MAINLOOP_CLOSE;
			return LXC_MAINLOOP_CLOSE;
		}
	}

	if (events & EPOLLHUP)
		return lxc_monitord_sockfd_remove(mon, fd);

	return quit;
}

static int lxc_monitord_sock_accept(int fd, uint32_t events, void *data,
				    struct lxc_async_descr *descr)
{
	int ret, clientfd;
	struct lxc_monitor *mon = data;
	struct ucred cred;
	socklen_t credsz = sizeof(cred);

	ret = LXC_MAINLOOP_ERROR;
	clientfd = accept4(fd, NULL, 0, SOCK_CLOEXEC);
	if (clientfd < 0) {
		SYSERROR("Failed to accept connection for client file descriptor %d", fd);
		goto out;
	}

	if (getsockopt(clientfd, SOL_SOCKET, SO_PEERCRED, &cred, &credsz)) {
		SYSERROR("Failed to get credentials on client socket connection %d", clientfd);
		goto err1;
	}

	if (cred.uid && cred.uid != geteuid()) {
		WARN("Monitor denied for uid %d on client socket connection %d", cred.uid, clientfd);
		goto err1;
	}

	if (mon->clientfds_cnt + 1 > mon->clientfds_size) {
		int *clientfds;

		clientfds = realloc(mon->clientfds,
				    (mon->clientfds_size + CLIENTFDS_CHUNK) * sizeof(mon->clientfds[0]));
		if (!clientfds) {
			ERROR("Failed to realloc memory for %d client file descriptors",
			      mon->clientfds_size + CLIENTFDS_CHUNK);
			goto err1;
		}

		mon->clientfds = clientfds;
		mon->clientfds_size += CLIENTFDS_CHUNK;
	}

	ret = lxc_mainloop_add_handler(&mon->descr, clientfd,
				       lxc_monitord_sock_handler,
				       default_cleanup_handler,
				       mon, "lxc_monitord_sock_handler");
	if (ret < 0) {
		ERROR("Failed to add socket handler");
		goto err1;
	}

	mon->clientfds[mon->clientfds_cnt++] = clientfd;
	INFO("Accepted client file descriptor %d. Number of accepted file descriptors is now %d",
	     clientfd, mon->clientfds_cnt);
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
		SYSERROR("Failed to open unix socket");
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

	return lxc_monitord_sock_create(mon);
}

static void lxc_monitord_delete(struct lxc_monitor *mon)
{
	lxc_abstract_unix_close(mon->listenfd);
	lxc_monitord_sock_delete(mon);

	lxc_monitord_fifo_delete(mon);
	close(mon->fifofd);

	for (int i = 0; i < mon->clientfds_cnt; i++)
		close(mon->clientfds[i]);

	mon->clientfds_cnt = 0;
}

static int lxc_monitord_fifo_handler(int fd, uint32_t events, void *data,
				     struct lxc_async_descr *descr)
{
	int ret, i;
	struct lxc_msg msglxc;
	struct lxc_monitor *mon = data;

	ret = lxc_read_nointr(fd, &msglxc, sizeof(msglxc));
	if (ret != sizeof(msglxc)) {
		SYSERROR("Reading from fifo failed");
		return LXC_MAINLOOP_CLOSE;
	}

	for (i = 0; i < mon->clientfds_cnt; i++) {
		ret = lxc_write_nointr(mon->clientfds[i], &msglxc, sizeof(msglxc));
		if (ret < 0)
			SYSERROR("Failed to send message to client file descriptor %d",
				 mon->clientfds[i]);
	}

	return LXC_MAINLOOP_CONTINUE;
}

static int lxc_monitord_mainloop_add(struct lxc_monitor *mon)
{
	int ret;

	ret = lxc_mainloop_add_handler(&mon->descr, mon->fifofd,
				       lxc_monitord_fifo_handler,
				       default_cleanup_handler,
				       mon, "lxc_monitord_fifo_handler");
	if (ret < 0) {
		ERROR("Failed to add to mainloop monitor handler for fifo");
		return -1;
	}

	ret = lxc_mainloop_add_handler(&mon->descr, mon->listenfd,
				       lxc_monitord_sock_accept,
				       default_cleanup_handler,
				       mon, "lxc_monitord_sock_accept");
	if (ret < 0) {
		ERROR("Failed to add to mainloop monitor handler for listen socket");
		return -1;
	}

	return 0;
}

static void lxc_monitord_sig_handler(int sig)
{
	siglongjmp(mark, 1);
}

int main(int argc, char *argv[])
{
	int ret, pipefd = -1;
	sigset_t mask;
	const char *lxcpath = NULL;
	bool mainloop_opened = false;
	bool monitord_created = false;
	bool persistent = false;

	if (argc > 1 && !strcmp(argv[1], "--daemon")) {
		persistent = true;
		--argc;
		++argv;
	}

	if (argc > 1) {
		lxcpath = argv[1];
		--argc;
		++argv;
	} else {
		lxcpath = lxc_global_config_value("lxc.lxcpath");
		if (!lxcpath) {
			ERROR("Failed to get default lxcpath");
			exit(EXIT_FAILURE);
		}
	}

	if (argc > 1) {
		if (lxc_safe_int(argv[1], &pipefd) < 0)
			exit(EXIT_FAILURE);
		--argc;
		++argv;
	}

	if (argc != 1 || (persistent != (pipefd == -1))) {
		fprintf(stderr,
			"Usage: lxc-monitord lxcpath sync-pipe-fd\n"
			"       lxc-monitord --daemon lxcpath\n\n"
			"NOTE: lxc-monitord is intended for use by lxc internally\n"
			"      and does not need to be run by hand\n\n");
		exit(EXIT_FAILURE);
	}

	if (sigfillset(&mask) ||
	    sigdelset(&mask, SIGILL)  ||
	    sigdelset(&mask, SIGSEGV) ||
	    sigdelset(&mask, SIGBUS)  ||
	    sigdelset(&mask, SIGTERM) ||
	    pthread_sigmask(SIG_BLOCK, &mask, NULL)) {
		SYSERROR("Failed to set signal mask");
		exit(EXIT_FAILURE);
	}

	signal(SIGILL,  lxc_monitord_sig_handler);
	signal(SIGSEGV, lxc_monitord_sig_handler);
	signal(SIGBUS,  lxc_monitord_sig_handler);
	signal(SIGTERM, lxc_monitord_sig_handler);

	if (sigsetjmp(mark, 1) != 0)
		goto on_signal;

	ret = EXIT_FAILURE;

	memset(&monitor, 0, sizeof(monitor));
	monitor.lxcpath = lxcpath;
	if (lxc_mainloop_open(&monitor.descr)) {
		ERROR("Failed to create mainloop");
		goto on_error;
	}
	mainloop_opened = true;

	if (lxc_monitord_create(&monitor))
		goto on_error;
	monitord_created = true;

	if (pipefd != -1) {
		/* sync with parent, we're ignoring the return from write
		 * because regardless if it works or not, the following
		 * close will sync us with the parent process. the
		 * if-empty-statement construct is to quiet the
		 * warn-unused-result warning.
		 */
		if (lxc_write_nointr(pipefd, "S", 1)) {
			;
		}
		close(pipefd);
	}

	if (lxc_monitord_mainloop_add(&monitor)) {
		ERROR("Failed to add mainloop handlers");
		goto on_error;
	}

	NOTICE("lxc-monitord with pid %d is now monitoring lxcpath %s",
	       lxc_raw_getpid(), monitor.lxcpath);

	for (;;) {
		ret = lxc_mainloop(&monitor.descr, persistent ? -1 : 1000 * 30);
		if (ret) {
			ERROR("mainloop returned an error");
			break;
		}

		if (monitor.clientfds_cnt <= 0) {
			NOTICE("No remaining clients. lxc-monitord is exiting");
			break;
		}

		if (quit == LXC_MAINLOOP_CLOSE) {
			NOTICE("Got quit command. lxc-monitord is exiting");
			break;
		}
	}

on_signal:
	ret = EXIT_SUCCESS;

on_error:
	if (mainloop_opened)
		lxc_mainloop_close(&monitor.descr);

	if (monitord_created)
		lxc_monitord_delete(&monitor);

	exit(ret);
}
