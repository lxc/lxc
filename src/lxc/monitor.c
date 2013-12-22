/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Daniel Lezcano <daniel.lezcano at free.fr>
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

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <net/if.h>

#include "error.h"
#include "af_unix.h"

#include <lxc/log.h>
#include <lxc/lxclock.h>
#include <lxc/state.h>
#include <lxc/monitor.h>
#include <lxc/utils.h>

lxc_log_define(lxc_monitor, lxc);

/* routines used by monitor publishers (containers) */
int lxc_monitor_fifo_name(const char *lxcpath, char *fifo_path, size_t fifo_path_sz,
			  int do_mkdirp)
{
	int ret;
	const char *rundir;

	rundir = get_rundir();
	if (do_mkdirp) {
		ret = snprintf(fifo_path, fifo_path_sz, "%s/lxc/%s", rundir, lxcpath);
		if (ret < 0 || ret >= fifo_path_sz) {
			ERROR("rundir/lxcpath (%s/%s) too long for monitor fifo", rundir, lxcpath);
			return -1;
		}
		ret = mkdir_p(fifo_path, 0755);
		if (ret < 0) {
			ERROR("unable to create monitor fifo dir %s", fifo_path);
			return ret;
		}
	}
	ret = snprintf(fifo_path, fifo_path_sz, "%s/lxc/%s/monitor-fifo", rundir, lxcpath);
	if (ret < 0 || ret >= fifo_path_sz) {
		ERROR("rundir/lxcpath (%s/%s) too long for monitor fifo", rundir, lxcpath);
		return -1;
	}
	return 0;
}

static void lxc_monitor_fifo_send(struct lxc_msg *msg, const char *lxcpath)
{
	int fd,ret;
	char fifo_path[PATH_MAX];

	BUILD_BUG_ON(sizeof(*msg) > PIPE_BUF); /* write not guaranteed atomic */

	ret = lxc_monitor_fifo_name(lxcpath, fifo_path, sizeof(fifo_path), 0);
	if (ret < 0)
		return;

	fd = open(fifo_path, O_WRONLY);
	if (fd < 0) {
		/* it is normal for this open to fail when there is no monitor
		 * running, so we don't log it
		 */
		return;
	}

	ret = write(fd, msg, sizeof(*msg));
	if (ret != sizeof(*msg)) {
		close(fd);
		SYSERROR("failed to write monitor fifo %s", fifo_path);
		return;
	}

	close(fd);
}

void lxc_monitor_send_state(const char *name, lxc_state_t state, const char *lxcpath)
{
	struct lxc_msg msg = { .type = lxc_msg_state,
			       .value = state };
	strncpy(msg.name, name, sizeof(msg.name));
	msg.name[sizeof(msg.name) - 1] = 0;

	lxc_monitor_fifo_send(&msg, lxcpath);
}


/* routines used by monitor subscribers (lxc-monitor) */
int lxc_monitor_close(int fd)
{
	return close(fd);
}

/* Note we don't use SHA-1 here as we don't want to depend on HAVE_GNUTLS.
 * FNV has good anti collision properties and we're not worried
 * about pre-image resistance or one-way-ness, we're just trying to make
 * the name unique in the 108 bytes of space we have.
 */
#define FNV1A_64_INIT ((uint64_t)0xcbf29ce484222325ULL)
static uint64_t fnv_64a_buf(void *buf, size_t len, uint64_t hval)
{
	unsigned char *bp;

	for(bp = buf; bp < (unsigned char *)buf + len; bp++)
	{
		/* xor the bottom with the current octet */
		hval ^= (uint64_t)*bp;

		/* gcc optimised:
		 * multiply by the 64 bit FNV magic prime mod 2^64
		 */
		hval += (hval << 1) + (hval << 4) + (hval << 5) +
			(hval << 7) + (hval << 8) + (hval << 40);
	}

	return hval;
}

int lxc_monitor_sock_name(const char *lxcpath, struct sockaddr_un *addr) {
	size_t len;
	int ret;
	char *sockname = &addr->sun_path[1];
	char path[PATH_MAX+18];
	uint64_t hash;

	/* addr.sun_path is only 108 bytes, so we hash the full name and
	 * then append as much of the name as we can fit.
	 */
	memset(addr, 0, sizeof(*addr));
	addr->sun_family = AF_UNIX;
	len = sizeof(addr->sun_path) - 1;
	ret = snprintf(path, sizeof(path), "lxc/%s/monitor-sock", lxcpath);
	if (ret < 0 || ret >= sizeof(path)) {
		ERROR("lxcpath %s too long for monitor unix socket", lxcpath);
		return -1;
	}

	hash = fnv_64a_buf(path, ret, FNV1A_64_INIT);
	ret = snprintf(sockname, len, "lxc/%016" PRIx64 "/%s", hash, lxcpath);
	if (ret < 0)
		return -1;
	sockname[sizeof(addr->sun_path)-2] = '\0';
	INFO("using monitor sock name %s", sockname);
	return 0;
}

int lxc_monitor_open(const char *lxcpath)
{
	struct sockaddr_un addr;
	int fd,ret;
	int retry,backoff_ms[] = {10, 50, 100};
	size_t len;

	if (lxc_monitor_sock_name(lxcpath, &addr) < 0)
		return -1;

	fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		ERROR("socket : %s", strerror(errno));
		return -1;
	}

	len = strlen(&addr.sun_path[1]) + 1;
	if (len >= sizeof(addr.sun_path) - 1) {
		ret = -1;
		errno = ENAMETOOLONG;
		goto err1;
	}

	for (retry = 0; retry < sizeof(backoff_ms)/sizeof(backoff_ms[0]); retry++) {
		ret = connect(fd, (struct sockaddr *)&addr, offsetof(struct sockaddr_un, sun_path) + len);
		if (ret == 0 || errno != ECONNREFUSED)
			break;
		ERROR("connect : backing off %d", backoff_ms[retry]);
		usleep(backoff_ms[retry] * 1000);
	}

	if (ret < 0) {
		ERROR("connect : %s", strerror(errno));
		goto err1;
	}
	return fd;
err1:
	close(fd);
	return ret;
}

int lxc_monitor_read_fdset(fd_set *rfds, int nfds, struct lxc_msg *msg,
			   int timeout)
{
	struct timeval tval,*tv = NULL;
	int ret,i;

	if (timeout != -1) {
		tv = &tval;
		tv->tv_sec = timeout;
		tv->tv_usec = 0;
	}

	ret = select(nfds, rfds, NULL, NULL, tv);
	if (ret == -1)
		return -1;
	else if (ret == 0)
		return -2;  // timed out

	/* only read from the first ready fd, the others will remain ready
	 * for when this routine is called again
	 */
	for (i = 0; i < nfds; i++) {
		if (FD_ISSET(i, rfds)) {
			ret = recv(i, msg, sizeof(*msg), 0);
			if (ret <= 0) {
				SYSERROR("client failed to recv (monitord died?) %s",
					 strerror(errno));
				return -1;
			}
			return ret;
		}
	}
	SYSERROR("no ready fd found?");
	return -1;
}

int lxc_monitor_read_timeout(int fd, struct lxc_msg *msg, int timeout)
{
	fd_set rfds;

	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);

	return lxc_monitor_read_fdset(&rfds, fd+1, msg, timeout);
}

int lxc_monitor_read(int fd, struct lxc_msg *msg)
{
	return lxc_monitor_read_timeout(fd, msg, -1);
}



/* used to spawn a monitord either on startup of a daemon container, or when
 * lxc-monitor starts
 */
int lxc_monitord_spawn(const char *lxcpath)
{
	pid_t pid1,pid2;
	int pipefd[2];
	char pipefd_str[11];

	char * const args[] = {
		"lxc-monitord",
		(char *)lxcpath,
		pipefd_str,
		NULL,
	};

	/* double fork to avoid zombies when monitord exits */
	pid1 = fork();
	if (pid1 < 0) {
		SYSERROR("failed to fork");
		return -1;
	}

	if (pid1) {
		if (waitpid(pid1, NULL, 0) != pid1)
			return -1;
		return 0;
	}

	process_unlock(); // we're no longer sharing
	if (pipe(pipefd) < 0) {
		SYSERROR("failed to create pipe");
		exit(EXIT_FAILURE);
	}

	pid2 = fork();
	if (pid2 < 0) {
		SYSERROR("failed to fork");
		exit(EXIT_FAILURE);
	}
	if (pid2) {
		char c;
		/* wait for daemon to create socket */
		close(pipefd[1]);
		/* sync with child, we're ignoring the return from read
		 * because regardless if it works or not, either way we've
		 * synced with the child process. the if-empty-statement
		 * construct is to quiet the warn-unused-result warning.
		 */
		if (read(pipefd[0], &c, 1))
			;
		close(pipefd[0]);
		exit(EXIT_SUCCESS);
	}

	umask(0);
	if (setsid() < 0) {
		SYSERROR("failed to setsid");
		exit(EXIT_FAILURE);
	}
	close(0);
	close(1);
	close(2);
	open("/dev/null", O_RDONLY);
	open("/dev/null", O_RDWR);
	open("/dev/null", O_RDWR);
	close(pipefd[0]);
	sprintf(pipefd_str, "%d", pipefd[1]);
	execvp(args[0], args);
	exit(EXIT_FAILURE);
}
