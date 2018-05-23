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
#define __STDC_FORMAT_MACROS
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libgen.h>
#include <poll.h>
#include <regex.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <lxc/lxccontainer.h>

#include "arguments.h"
#include "tool_utils.h"

static bool quit_monitord;

static int my_parser(struct lxc_arguments* args, int c, char* arg)
{
	switch (c) {
	case 'Q': quit_monitord = true; break;
	}
	return 0;
}

static const struct option my_longopts[] = {
	{"quit", no_argument, 0, 'Q'},
	LXC_COMMON_OPTIONS
};

static struct lxc_arguments my_args = {
	.progname = "lxc-monitor",
	.help     = "\
[--name=NAME]\n\
\n\
lxc-monitor monitors the state of the NAME container\n\
\n\
Options :\n\
  -n, --name=NAME   NAME of the container\n\
                    NAME may be a regular expression\n\
  -Q, --quit        tell lxc-monitord to quit\n",
	.name     = ".*",
	.options  = my_longopts,
	.parser   = my_parser,
	.checker  = NULL,
	.lxcpath_additional = -1,
};

static void close_fds(struct pollfd *fds, nfds_t nfds)
{
	nfds_t i;

	if (nfds < 1)
		return;

	for (i = 0; i < nfds; ++i) {
		close(fds[i].fd);
	}
}

typedef enum {
	lxc_msg_state,
	lxc_msg_priority,
	lxc_msg_exit_code,
} lxc_msg_type_t;

struct lxc_msg {
	lxc_msg_type_t type;
	char name[NAME_MAX+1];
	int value;
};

typedef enum {
	STOPPED,
	STARTING,
	RUNNING,
	STOPPING,
	ABORTING,
	FREEZING,
	FROZEN,
	THAWED,
	MAX_STATE,
} lxc_state_t;

static const char *const strstate[] = {
    "STOPPED",  "STARTING", "RUNNING", "STOPPING",
    "ABORTING", "FREEZING", "FROZEN",  "THAWED",
};

const char *lxc_state2str(lxc_state_t state)
{
	if (state < STOPPED || state > MAX_STATE - 1)
		return NULL;
	return strstate[state];
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

static int open_devnull(void)
{
	int fd = open("/dev/null", O_RDWR);

	if (fd < 0)
		fprintf(stderr, "%s - Failed to open \"/dev/null\"\n",
			strerror(errno));

	return fd;
}

static int set_stdfds(int fd)
{
	int ret;

	if (fd < 0)
		return -1;

	ret = dup2(fd, STDIN_FILENO);
	if (ret < 0)
		return -1;

	ret = dup2(fd, STDOUT_FILENO);
	if (ret < 0)
		return -1;

	ret = dup2(fd, STDERR_FILENO);
	if (ret < 0)
		return -1;

	return 0;
}

static int null_stdfds(void)
{
	int ret = -1;
	int fd = open_devnull();

	if (fd >= 0) {
		ret = set_stdfds(fd);
		close(fd);
	}

	return ret;
}

static int lxc_check_inherited(bool closeall, int *fds_to_ignore, size_t len_fds)
{
	struct dirent *direntp;
	int fd, fddir;
	size_t i;
	DIR *dir;

restart:
	dir = opendir("/proc/self/fd");
	if (!dir) {
		fprintf(stderr, "%s - Failed to open directory\n",
			strerror(errno));
		return -1;
	}

	fddir = dirfd(dir);

	while ((direntp = readdir(dir))) {
		if (!strcmp(direntp->d_name, "."))
			continue;

		if (!strcmp(direntp->d_name, ".."))
			continue;

		if (lxc_safe_int(direntp->d_name, &fd) < 0)
			continue;

		for (i = 0; i < len_fds; i++)
			if (fds_to_ignore[i] == fd)
				break;

		if (fd == fddir || (i < len_fds && fd == fds_to_ignore[i]))
			continue;

		if (fd == 0 || fd == 1 || fd == 2)
			continue;

		if (closeall) {
			close(fd);
			closedir(dir);
			goto restart;
		}
	}

	closedir(dir);
	return 0;
}

/* Enforces \0-termination for the abstract unix socket. This is not required
 * but allows us to print it out.
 *
 * Older version of liblxc only allowed for 105 bytes to be used for the
 * abstract unix domain socket name because the code for our abstract unix
 * socket handling performed invalid checks. Since we \0-terminate we could now
 * have a maximum of 106 chars. But to not break backwards compatibility we keep
 * the limit at 105.
 */
static int lxc_monitor_sock_name(const char *lxcpath, struct sockaddr_un *addr)
{
	size_t len;
	int ret;
	char *path;
	uint64_t hash;

	/* addr.sun_path is only 108 bytes, so we hash the full name and
	 * then append as much of the name as we can fit.
	 */
	memset(addr, 0, sizeof(*addr));
	addr->sun_family = AF_UNIX;

	/* strlen("lxc/") + strlen("/monitor-sock") + 1 = 18 */
	len = strlen(lxcpath) + 18;
	path = alloca(len);
	ret = snprintf(path, len, "lxc/%s/monitor-sock", lxcpath);
	if (ret < 0 || (size_t)ret >= len) {
		fprintf(stderr, "failed to create name for monitor socket\n");
		return -1;
	}

	/* Note: snprintf() will \0-terminate addr->sun_path on the 106th byte
	 * and so the abstract socket name has 105 "meaningful" characters. This
	 * is absolutely intentional. For further info read the comment for this
	 * function above!
	 */
	len = sizeof(addr->sun_path) - 1;
	hash = fnv_64a_buf(path, ret, FNV1A_64_INIT);
	ret = snprintf(addr->sun_path, len, "@lxc/%016" PRIx64 "/%s", hash, lxcpath);
	if (ret < 0) {
		fprintf(stderr, "failed to create hashed name for monitor socket\n");
		return -1;
	}

	/* replace @ with \0 */
	addr->sun_path[0] = '\0';

	return 0;
}

static int lxc_abstract_unix_connect(const char *path)
{
	int fd, ret;
	size_t len;
	struct sockaddr_un addr;

	fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;

	memset(&addr, 0, sizeof(addr));

	addr.sun_family = AF_UNIX;

	len = strlen(&path[1]);
	/* do not enforce \0-termination */
	if (len >= sizeof(addr.sun_path)) {
		close(fd);
		errno = ENAMETOOLONG;
		return -1;
	}
	/* addr.sun_path[0] has already been set to 0 by memset() */
	memcpy(&addr.sun_path[1], &path[1], strlen(&path[1]));

	ret = connect(fd, (struct sockaddr *)&addr,
		      offsetof(struct sockaddr_un, sun_path) + len + 1);
	if (ret < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

static int lxc_monitor_open(const char *lxcpath)
{
	struct sockaddr_un addr;
	int fd;
	size_t retry;
	size_t len;
	int backoff_ms[] = {10, 50, 100};

	if (lxc_monitor_sock_name(lxcpath, &addr) < 0)
		return -1;

	fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		fprintf(stderr, "Failed to create socket: %s\n", strerror(errno));
		return -errno;
	}

	len = strlen(&addr.sun_path[1]);
	if (len >= sizeof(addr.sun_path) - 1) {
		errno = ENAMETOOLONG;
		close(fd);
		fprintf(stderr, "name of monitor socket too long (%zu bytes): %s\n", len, strerror(errno));
		return -errno;
	}

	for (retry = 0; retry < sizeof(backoff_ms) / sizeof(backoff_ms[0]); retry++) {
		fd = lxc_abstract_unix_connect(addr.sun_path);
		if (fd != -1 || errno != ECONNREFUSED)
			break;
		fprintf(stderr, "Failed to connect to monitor socket. Retrying in %d ms: %s\n", backoff_ms[retry], strerror(errno));
		usleep(backoff_ms[retry] * 1000);
	}

	if (fd < 0) {
		fprintf(stderr, "Failed to connect to monitor socket: %s\n", strerror(errno));
		return -errno;
	}

	return fd;
}

static int lxc_monitor_read_fdset(struct pollfd *fds, nfds_t nfds,
				  struct lxc_msg *msg, int timeout)
{
	nfds_t i;
	int ret;

	ret = poll(fds, nfds, timeout * 1000);
	if (ret == -1)
		return -1;
	else if (ret == 0)
		return -2;  /* timed out */

	/* Only read from the first ready fd, the others will remain ready for
	 * when this routine is called again.
	 */
	for (i = 0; i < nfds; i++) {
		if (fds[i].revents != 0) {
			fds[i].revents = 0;
			ret = recv(fds[i].fd, msg, sizeof(*msg), 0);
			if (ret <= 0) {
				fprintf(stderr, "%s - Failed to receive message. Did monitord die?\n", strerror(errno));
				return -1;
			}
			return ret;
		}
	}

	return -1;
}

#define LXC_MONITORD_PATH LIBEXECDIR "/lxc/lxc-monitord"

/* Used to spawn a monitord either on startup of a daemon container, or when
 * lxc-monitor starts.
 */
static int lxc_monitord_spawn(const char *lxcpath)
{
	int ret;
	int pipefd[2];
	char pipefd_str[TOOL_NUMSTRLEN64];
	pid_t pid1, pid2;

	char *const args[] = {
	    LXC_MONITORD_PATH,
	    (char *)lxcpath,
	    pipefd_str,
	    NULL,
	};

	/* double fork to avoid zombies when monitord exits */
	pid1 = fork();
	if (pid1 < 0) {
		fprintf(stderr, "Failed to fork()\n");
		return -1;
	}

	if (pid1) {
		if (waitpid(pid1, NULL, 0) != pid1)
			return -1;
		return 0;
	}

	if (pipe(pipefd) < 0) {
		fprintf(stderr, "Failed to create pipe\n");
		exit(EXIT_FAILURE);
	}

	pid2 = fork();
	if (pid2 < 0) {
		fprintf(stderr, "Failed to fork()\n");
		exit(EXIT_FAILURE);
	}

	if (pid2) {
		char c;
		/* Wait for daemon to create socket. */
		close(pipefd[1]);

		/* Sync with child, we're ignoring the return from read
		 * because regardless if it works or not, either way we've
		 * synced with the child process. the if-empty-statement
		 * construct is to quiet the warn-unused-result warning.
		 */
		if (read(pipefd[0], &c, 1))
			;

		close(pipefd[0]);

		exit(EXIT_SUCCESS);
	}

	if (setsid() < 0) {
		fprintf(stderr, "Failed to setsid()\n");
		exit(EXIT_FAILURE);
	}

	lxc_check_inherited(true, &pipefd[1], 1);
	if (null_stdfds() < 0) {
		fprintf(stderr, "Failed to dup2() standard file descriptors to /dev/null\n");
		exit(EXIT_FAILURE);
	}

	close(pipefd[0]);

	ret = snprintf(pipefd_str, TOOL_NUMSTRLEN64, "%d", pipefd[1]);
	if (ret < 0 || ret >= TOOL_NUMSTRLEN64) {
		fprintf(stderr, "Failed to create pid argument to pass to monitord\n");
		exit(EXIT_FAILURE);
	}

	execvp(args[0], args);
	fprintf(stderr, "Failed to exec lxc-monitord\n");

	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	char *regexp;
	struct lxc_msg msg;
	regex_t preg;
	struct pollfd *fds;
	nfds_t nfds;
	int len, rc_main, rc_snp, i;
	struct lxc_log log;

	rc_main = EXIT_FAILURE;

	if (lxc_arguments_parse(&my_args, argc, argv))
		exit(rc_main);

	/* Only create log if explicitly instructed */
	if (my_args.log_file || my_args.log_priority) {
		log.name = my_args.name;
		log.file = my_args.log_file;
		log.level = my_args.log_priority;
		log.prefix = my_args.progname;
		log.quiet = my_args.quiet;
		log.lxcpath = my_args.lxcpath[0];

		if (lxc_log_init(&log))
			exit(rc_main);
	}

	if (quit_monitord) {
		int ret = EXIT_SUCCESS;
		for (i = 0; i < my_args.lxcpath_cnt; i++) {
			int fd;

			fd = lxc_monitor_open(my_args.lxcpath[i]);
			if (fd < 0) {
				fprintf(stderr, "Unable to open monitor on path: %s\n", my_args.lxcpath[i]);
				ret = EXIT_FAILURE;
				continue;
			}
			if (write(fd, "quit", 4) < 0) {
				fprintf(stderr, "Unable to close monitor on path: %s\n", my_args.lxcpath[i]);
				ret = EXIT_FAILURE;
				close(fd);
				continue;
			}
			close(fd);
		}
		exit(ret);
	}

	len = strlen(my_args.name) + 3;
	regexp = malloc(len + 3);
	if (!regexp) {
		fprintf(stderr, "failed to allocate memory\n");
		exit(rc_main);
	}
	rc_snp = snprintf(regexp, len, "^%s$", my_args.name);
	if (rc_snp < 0 || rc_snp >= len) {
		fprintf(stderr, "Name too long\n");
		goto error;
	}

	if (regcomp(&preg, regexp, REG_NOSUB|REG_EXTENDED)) {
		fprintf(stderr, "failed to compile the regex '%s'\n", my_args.name);
		goto error;
	}

	fds = malloc(my_args.lxcpath_cnt * sizeof(struct pollfd));
	if (!fds) {
		fprintf(stderr, "out of memory\n");
		goto cleanup;
	}

	nfds = my_args.lxcpath_cnt;
	for (i = 0; (unsigned long)i < nfds; i++) {
		int fd;

		lxc_monitord_spawn(my_args.lxcpath[i]);

		fd = lxc_monitor_open(my_args.lxcpath[i]);
		if (fd < 0) {
			close_fds(fds, i);
			goto cleanup;
		}
		fds[i].fd = fd;
		fds[i].events = POLLIN;
		fds[i].revents = 0;
	}

	setlinebuf(stdout);

	for (;;) {
		if (lxc_monitor_read_fdset(fds, nfds, &msg, -1) < 0) {
			goto close_and_clean;
		}

		msg.name[sizeof(msg.name)-1] = '\0';
		if (regexec(&preg, msg.name, 0, NULL, 0))
			continue;

		switch (msg.type) {
		case lxc_msg_state:
			printf("'%s' changed state to [%s]\n",
			       msg.name, lxc_state2str(msg.value));
			break;
		case lxc_msg_exit_code:
			printf("'%s' exited with status [%d]\n",
			       msg.name, WEXITSTATUS(msg.value));
			break;
		default:
			/* ignore garbage */
			break;
		}
	}
	rc_main = 0;

close_and_clean:
	close_fds(fds, nfds);

cleanup:
	regfree(&preg);
	free(fds);

error:
	free(regexp);

	exit(rc_main);
}
