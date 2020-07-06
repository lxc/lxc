/* SPDX-License-Identifier: LGPL-2.1+ */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

#ifdef HAVE_PTY_H
#include <pty.h>
#endif

static int pts_name(int fd, char **pts, size_t buf_len)
{
	int rv;
	char *buf = *pts;

	for (;;) {
		char *new_buf;

		if (buf_len) {
			rv = ptsname_r(fd, buf, buf_len);

			if (rv != 0 || memchr(buf, '\0', buf_len))
				/* We either got an error, or we succeeded and the
				   returned name fit in the buffer.  */
				break;

			/* Try again with a longer buffer.  */
			buf_len += buf_len; /* Double it */
		} else
			/* No initial buffer; start out by mallocing one.  */
			buf_len = 128; /* First time guess.  */

		if (buf != *pts)
			/* We've already malloced another buffer at least once.  */
			new_buf = realloc(buf, buf_len);
		else
			new_buf = malloc(buf_len);
		if (!new_buf) {
			rv = -1;
			break;
		}
		buf = new_buf;
	}

	if (rv == 0)
		*pts = buf; /* Return buffer to the user.  */
	else if (buf != *pts)
		free(buf); /* Free what we malloced when returning an error.  */

	return rv;
}

int __unlockpt(int fd)
{
#ifdef TIOCSPTLCK
	int unlock = 0;

	if (ioctl(fd, TIOCSPTLCK, &unlock)) {
		if (errno != EINVAL)
			return -1;
	}
#endif
	return 0;
}

int openpty(int *ptx, int *pty, char *name, const struct termios *termp,
	    const struct winsize *winp)
{
	char _buf[PATH_MAX];
	char *buf = _buf;
	int ptx_fd, ret = -1, pty_fd = -1;

	*buf = '\0';

	ptx_fd = open("/dev/ptmx", O_RDWR | O_NOCTTY);
	if (ptx_fd == -1)
		return -1;

	if (__unlockpt(ptx_fd))
		goto on_error;

#ifdef TIOCGPTPEER
	/* Try to allocate pty_fd solely based on ptx_fd first. */
	pty_fd = ioctl(ptx_fd, TIOCGPTPEER, O_RDWR | O_NOCTTY);
#endif
	if (pty_fd == -1) {
		/* Fallback to path-based pty_fd allocation in case kernel doesn't
		 * support TIOCGPTPEER.
		 */
		if (pts_name(ptx_fd, &buf, sizeof(_buf)))
			goto on_error;

		pty_fd = open(buf, O_RDWR | O_NOCTTY);
		if (pty_fd == -1)
			goto on_error;
	}

	if (termp)
		tcsetattr(pty_fd, TCSAFLUSH, termp);
#ifdef TIOCSWINSZ
	if (winp)
		ioctl(pty_fd, TIOCSWINSZ, winp);
#endif

	*ptx = ptx_fd;
	*pty = pty_fd;
	if (name != NULL) {
		if (*buf == '\0')
			if (pts_name(ptx_fd, &buf, sizeof(_buf)))
				goto on_error;

		strcpy(name, buf);
	}

	ret = 0;

on_error:
	if (ret == -1) {
		close(ptx_fd);

		if (pty_fd != -1)
			close(pty_fd);
	}

	if (buf != _buf)
		free(buf);

	return ret;
}
