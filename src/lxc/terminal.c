/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <errno.h>
#include <fcntl.h>
#include <lxc/lxccontainer.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

#include "af_unix.h"
#include "caps.h"
#include "commands.h"
#include "conf.h"
#include "config.h"
#include "log.h"
#include "lxclock.h"
#include "mainloop.h"
#include "memory_utils.h"
#include "start.h"
#include "syscall_wrappers.h"
#include "terminal.h"
#include "utils.h"

#if HAVE_OPENPTY
#include <pty.h>
#else
#include <../include/openpty.h>
#endif

#define LXC_TERMINAL_BUFFER_SIZE 1024

lxc_log_define(terminal, lxc);

void lxc_terminal_winsz(int srcfd, int dstfd)
{
	int ret;
	struct winsize wsz;

	if (!isatty(srcfd))
		return;

	ret = ioctl(srcfd, TIOCGWINSZ, &wsz);
	if (ret < 0) {
		WARN("Failed to get window size");
		return;
	}

	ret = ioctl(dstfd, TIOCSWINSZ, &wsz);
	if (ret < 0)
		WARN("Failed to set window size");
	else
		DEBUG("Set window size to %d columns and %d rows", wsz.ws_col,
		      wsz.ws_row);

	return;
}

static void lxc_terminal_winch(struct lxc_terminal_state *ts)
{
	lxc_terminal_winsz(ts->stdinfd, ts->ptxfd);
}

int lxc_terminal_signalfd_cb(int fd, uint32_t events, void *cbdata,
			     struct lxc_epoll_descr *descr)
{
	ssize_t ret;
	struct signalfd_siginfo siginfo;
	struct lxc_terminal_state *ts = cbdata;

	ret = lxc_read_nointr(fd, &siginfo, sizeof(siginfo));
	if (ret < 0 || (size_t)ret < sizeof(siginfo)) {
		ERROR("Failed to read signal info");
		return LXC_MAINLOOP_ERROR;
	}

	if (siginfo.ssi_signo == SIGTERM) {
		DEBUG("Received SIGTERM. Detaching from the terminal");
		return LXC_MAINLOOP_CLOSE;
	}

	if (siginfo.ssi_signo == SIGWINCH)
		lxc_terminal_winch(ts);

	return LXC_MAINLOOP_CONTINUE;
}

struct lxc_terminal_state *lxc_terminal_signal_init(int srcfd, int dstfd)
{
	__do_close int signal_fd = -EBADF;
	__do_free struct lxc_terminal_state *ts = NULL;
	int ret;
	sigset_t mask;

	ts = malloc(sizeof(*ts));
	if (!ts)
		return NULL;

	memset(ts, 0, sizeof(*ts));
	ts->stdinfd = srcfd;
	ts->ptxfd = dstfd;
	ts->sigfd = -1;

	ret = sigemptyset(&mask);
	if (ret < 0) {
		SYSERROR("Failed to initialize an empty signal set");
		return NULL;
	}

	if (isatty(srcfd)) {
		ret = sigaddset(&mask, SIGWINCH);
		if (ret < 0)
			SYSNOTICE("Failed to add SIGWINCH to signal set");
	} else {
		INFO("fd %d does not refer to a tty device", srcfd);
	}

	/* Exit the mainloop cleanly on SIGTERM. */
	ret = sigaddset(&mask, SIGTERM);
	if (ret < 0) {
		SYSERROR("Failed to add SIGWINCH to signal set");
		return NULL;
	}

	ret = pthread_sigmask(SIG_BLOCK, &mask, &ts->oldmask);
	if (ret < 0) {
		WARN("Failed to block signals");
		return NULL;
	}

	signal_fd = signalfd(-1, &mask, SFD_CLOEXEC);
	if (signal_fd < 0) {
		WARN("Failed to create signal fd");
		(void)pthread_sigmask(SIG_SETMASK, &ts->oldmask, NULL);
		return NULL;
	}
	ts->sigfd = move_fd(signal_fd);
	TRACE("Created signal fd %d", ts->sigfd);

	return move_ptr(ts);
}

int lxc_terminal_signal_sigmask_safe_blocked(struct lxc_terminal *terminal)
{
	struct lxc_terminal_state *state = terminal->tty_state;

	if (!state)
		return 0;

	return pthread_sigmask(SIG_SETMASK, &state->oldmask, NULL);
}

/**
 * lxc_terminal_signal_fini: uninstall signal handler
 *
 * @terminal: terminal instance
 *
 * Restore the saved signal handler that was in effect at the time
 * lxc_terminal_signal_init() was called.
 */
static void lxc_terminal_signal_fini(struct lxc_terminal *terminal)
{
	struct lxc_terminal_state *state = terminal->tty_state;

	if (!terminal->tty_state)
		return;

	state = terminal->tty_state;
	if (state->sigfd >= 0) {
		close(state->sigfd);

		if (pthread_sigmask(SIG_SETMASK, &state->oldmask, NULL) < 0)
			SYSWARN("Failed to restore signal mask");
	}

	free(terminal->tty_state);
	terminal->tty_state = NULL;
}

static int lxc_terminal_truncate_log_file(struct lxc_terminal *terminal)
{
	/* be very certain things are kosher */
	if (!terminal->log_path || terminal->log_fd < 0)
		return -EBADF;

	return lxc_unpriv(ftruncate(terminal->log_fd, 0));
}

static int lxc_terminal_rotate_log_file(struct lxc_terminal *terminal)
{
	__do_free char *tmp = NULL;
	int ret;
	size_t len;

	if (!terminal->log_path || terminal->log_rotate == 0)
		return -EOPNOTSUPP;

	/* be very certain things are kosher */
	if (terminal->log_fd < 0)
		return -EBADF;

	len = strlen(terminal->log_path) + sizeof(".1");
	tmp = must_realloc(NULL, len);

	ret = strnprintf(tmp, len, "%s.1", terminal->log_path);
	if (ret < 0)
		return -EFBIG;

	close(terminal->log_fd);
	terminal->log_fd = -1;
	ret = lxc_unpriv(rename(terminal->log_path, tmp));
	if (ret < 0)
		return ret;

	return lxc_terminal_create_log_file(terminal);
}

static int lxc_terminal_write_log_file(struct lxc_terminal *terminal, char *buf,
				       int bytes_read)
{
	int ret;
	struct stat st;
	int64_t space_left = -1;

	if (terminal->log_fd < 0)
		return 0;

	/* A log size <= 0 means that there's no limit on the size of the log
         * file at which point we simply ignore whether the log is supposed to
	 * be rotated or not.
	 */
	if (terminal->log_size <= 0)
		return lxc_write_nointr(terminal->log_fd, buf, bytes_read);

	/* Get current size of the log file. */
	ret = fstat(terminal->log_fd, &st);
	if (ret < 0) {
		SYSERROR("Failed to stat the terminal log file descriptor");
		return -1;
	}

	/* handle non-regular files */
	if ((st.st_mode & S_IFMT) != S_IFREG) {
		/* This isn't a regular file. so rotating the file seems a
		 * dangerous thing to do, size limits are also very
		 * questionable. Let's not risk anything and tell the user that
		 * they're requesting us to do weird stuff.
		 */
		if (terminal->log_rotate > 0 || terminal->log_size > 0)
			return -EINVAL;

		/* I mean, sure log wherever you want to. */
		return lxc_write_nointr(terminal->log_fd, buf, bytes_read);
	}

	space_left = terminal->log_size - st.st_size;

	/* User doesn't want to rotate the log file and there's no more space
	 * left so simply truncate it.
	 */
	if (space_left <= 0 && terminal->log_rotate <= 0) {
		ret = lxc_terminal_truncate_log_file(terminal);
		if (ret < 0)
			return ret;

		if (bytes_read <= terminal->log_size)
			return lxc_write_nointr(terminal->log_fd, buf, bytes_read);

		/* Write as much as we can into the buffer and loose the rest. */
		return lxc_write_nointr(terminal->log_fd, buf, terminal->log_size);
	}

	/* There's enough space left. */
	if (bytes_read <= space_left)
		return lxc_write_nointr(terminal->log_fd, buf, bytes_read);

	/* There's not enough space left but at least write as much as we can
	 * into the old log file.
	 */
	ret = lxc_write_nointr(terminal->log_fd, buf, space_left);
	if (ret < 0)
		return -1;

	/* Calculate how many bytes we still need to write. */
	bytes_read -= space_left;

	/* There'd be more to write but we aren't instructed to rotate the log
	 * file so simply return. There's no error on our side here.
	 */
	if (terminal->log_rotate > 0)
		ret = lxc_terminal_rotate_log_file(terminal);
	else
		ret = lxc_terminal_truncate_log_file(terminal);
	if (ret < 0)
		return ret;

	if (terminal->log_size < bytes_read) {
		/* Well, this is unfortunate because it means that there is more
		 * to write than the user has granted us space. There are
		 * multiple ways to handle this but let's use the simplest one:
		 * write as much as we can, tell the user that there was more
		 * stuff to write and move on.
		 * Note that this scenario shouldn't actually happen with the
		 * standard pty-based terminal that LXC allocates since it will
		 * be switched into raw mode. In raw mode only 1 byte at a time
		 * should be read and written.
		 */
		WARN("Size of terminal log file is smaller than the bytes to write");
		ret = lxc_write_nointr(terminal->log_fd, buf, terminal->log_size);
		if (ret < 0)
			return -1;
		bytes_read -= ret;
		return bytes_read;
	}

	/* Yay, we made it. */
	ret = lxc_write_nointr(terminal->log_fd, buf, bytes_read);
	if (ret < 0)
		return -1;
	bytes_read -= ret;
	return bytes_read;
}

int lxc_terminal_io_cb(int fd, uint32_t events, void *data,
		       struct lxc_epoll_descr *descr)
{
	struct lxc_terminal *terminal = data;
	char buf[LXC_TERMINAL_BUFFER_SIZE];
	int r, w, w_log, w_rbuf;

	w = r = lxc_read_nointr(fd, buf, sizeof(buf));
	if (r <= 0) {
		INFO("Terminal client on fd %d has exited", fd);
		lxc_mainloop_del_handler(descr, fd);

		if (fd == terminal->ptx) {
			terminal->ptx = -EBADF;
		} else if (fd == terminal->peer) {
			lxc_terminal_signal_fini(terminal);
			terminal->peer = -EBADF;
		} else {
			ERROR("Handler received unexpected file descriptor");
		}
		close(fd);

		return LXC_MAINLOOP_CLOSE;
	}

	if (fd == terminal->peer)
		w = lxc_write_nointr(terminal->ptx, buf, r);

	w_rbuf = w_log = 0;
	if (fd == terminal->ptx) {
		/* write to peer first */
		if (terminal->peer >= 0)
			w = lxc_write_nointr(terminal->peer, buf, r);

		/* write to terminal ringbuffer */
		if (terminal->buffer_size > 0)
			w_rbuf = lxc_ringbuf_write(&terminal->ringbuf, buf, r);

		/* write to terminal log */
		if (terminal->log_fd >= 0)
			w_log = lxc_terminal_write_log_file(terminal, buf, r);
	}

	if (w != r)
		WARN("Short write on terminal r:%d != w:%d", r, w);

	if (w_rbuf < 0) {
		errno = -w_rbuf;
		SYSTRACE("Failed to write %d bytes to terminal ringbuffer", r);
	}

	if (w_log < 0)
		TRACE("Failed to write %d bytes to terminal log", r);

	return LXC_MAINLOOP_CONTINUE;
}

static int lxc_terminal_mainloop_add_peer(struct lxc_terminal *terminal)
{
	int ret;

	if (terminal->peer >= 0) {
		ret = lxc_mainloop_add_handler(terminal->descr, terminal->peer,
					       lxc_terminal_io_cb, terminal);
		if (ret < 0) {
			WARN("Failed to add terminal peer handler to mainloop");
			return -1;
		}
	}

	if (!terminal->tty_state || terminal->tty_state->sigfd < 0)
		return 0;

	ret = lxc_mainloop_add_handler(terminal->descr, terminal->tty_state->sigfd,
				       lxc_terminal_signalfd_cb, terminal->tty_state);
	if (ret < 0) {
		WARN("Failed to add signal handler to mainloop");
		return -1;
	}

	return 0;
}

int lxc_terminal_mainloop_add(struct lxc_epoll_descr *descr,
			      struct lxc_terminal *terminal)
{
	int ret;

	if (terminal->ptx < 0) {
		INFO("Terminal is not initialized");
		return 0;
	}

	ret = lxc_mainloop_add_handler(descr, terminal->ptx,
				       lxc_terminal_io_cb, terminal);
	if (ret < 0) {
		ERROR("Failed to add handler for terminal ptx fd %d to "
		      "mainloop", terminal->ptx);
		return -1;
	}

	/* We cache the descr so that we can add an fd to it when someone
	 * does attach to it in lxc_terminal_allocate().
	 */
	terminal->descr = descr;

	return lxc_terminal_mainloop_add_peer(terminal);
}

int lxc_setup_tios(int fd, struct termios *oldtios)
{
	int ret;
	struct termios newtios;

	if (!isatty(fd)) {
		ERROR("File descriptor %d does not refer to a terminal", fd);
		return -1;
	}

	/* Get current termios. */
	ret = tcgetattr(fd, oldtios);
	if (ret < 0) {
		SYSERROR("Failed to get current terminal settings");
		return -1;
	}

	/* ensure we don't end up in an endless loop:
	 * The kernel might fire SIGTTOU while an
	 * ioctl() in tcsetattr() is executed. When the ioctl()
	 * is resumed and retries, the signal handler interrupts it again.
	 */
	signal (SIGTTIN, SIG_IGN);
	signal (SIGTTOU, SIG_IGN);

	newtios = *oldtios;

	/* We use the same settings that ssh does. */
	newtios.c_iflag |= IGNPAR;
	newtios.c_iflag &= ~(ISTRIP | INLCR | IGNCR | ICRNL | IXON | IXANY | IXOFF);
#ifdef IUCLC
	newtios.c_iflag &= ~IUCLC;
#endif
	newtios.c_lflag &= ~(TOSTOP | ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHONL);
#ifdef IEXTEN
	newtios.c_lflag &= ~IEXTEN;
#endif
	newtios.c_oflag |= ONLCR;
	newtios.c_oflag |= OPOST;
	newtios.c_cc[VMIN] = 1;
	newtios.c_cc[VTIME] = 0;

	/* Set new attributes. */
	ret = tcsetattr(fd, TCSAFLUSH, &newtios);
	if (ret < 0) {
		ERROR("Failed to set new terminal settings");
		return -1;
	}

	return 0;
}

static void lxc_terminal_peer_proxy_free(struct lxc_terminal *terminal)
{
	lxc_terminal_signal_fini(terminal);

	close(terminal->proxy.ptx);
	terminal->proxy.ptx = -1;

	close(terminal->proxy.pty);
	terminal->proxy.pty = -1;

	terminal->proxy.busy = -1;

	terminal->proxy.name[0] = '\0';

	terminal->peer = -1;
}

static int lxc_terminal_peer_proxy_alloc(struct lxc_terminal *terminal,
					 int sockfd)
{
	int ret;
	struct termios oldtermio;
	struct lxc_terminal_state *ts;

	if (terminal->ptx < 0) {
		ERROR("Terminal not set up");
		return -1;
	}

	if (terminal->proxy.busy != -1 || terminal->peer != -1) {
		NOTICE("Terminal already in use");
		return -1;
	}

	if (terminal->tty_state) {
		ERROR("Terminal has already been initialized");
		return -1;
	}

	/* This is the proxy terminal that will be given to the client, and
	 * that the real terminal ptx will send to / recv from.
	 */
	ret = openpty(&terminal->proxy.ptx, &terminal->proxy.pty, NULL,
		      NULL, NULL);
	if (ret < 0) {
		SYSERROR("Failed to open proxy terminal");
		return -1;
	}

	ret = ttyname_r(terminal->proxy.pty, terminal->proxy.name,
			sizeof(terminal->proxy.name));
	if (ret < 0) {
		SYSERROR("Failed to retrieve name of proxy terminal pty");
		goto on_error;
	}

	ret = fd_cloexec(terminal->proxy.ptx, true);
	if (ret < 0) {
		SYSERROR("Failed to set FD_CLOEXEC flag on proxy terminal ptx");
		goto on_error;
	}

	ret = fd_cloexec(terminal->proxy.pty, true);
	if (ret < 0) {
		SYSERROR("Failed to set FD_CLOEXEC flag on proxy terminal pty");
		goto on_error;
	}

	ret = lxc_setup_tios(terminal->proxy.pty, &oldtermio);
	if (ret < 0)
		goto on_error;

	ts = lxc_terminal_signal_init(terminal->proxy.ptx, terminal->ptx);
	if (!ts)
		goto on_error;

	terminal->tty_state = ts;
	terminal->peer = terminal->proxy.pty;
	terminal->proxy.busy = sockfd;
	ret = lxc_terminal_mainloop_add_peer(terminal);
	if (ret < 0)
		goto on_error;

	NOTICE("Opened proxy terminal with ptx fd %d and pty fd %d",
	       terminal->proxy.ptx, terminal->proxy.pty);
	return 0;

on_error:
	lxc_terminal_peer_proxy_free(terminal);
	return -1;
}

int lxc_terminal_allocate(struct lxc_conf *conf, int sockfd, int *ttyreq)
{
	int ttynum;
	int ptxfd = -1;
	struct lxc_tty_info *ttys = &conf->ttys;
	struct lxc_terminal *terminal = &conf->console;

	if (*ttyreq == 0) {
		int ret;

		ret = lxc_terminal_peer_proxy_alloc(terminal, sockfd);
		if (ret < 0)
			goto out;

		ptxfd = terminal->proxy.ptx;
		goto out;
	}

	if (*ttyreq > 0) {
		if (*ttyreq > ttys->max)
			goto out;

		if (ttys->tty[*ttyreq - 1].busy >= 0)
			goto out;

		/* The requested tty is available. */
		ttynum = *ttyreq;
		goto out_tty;
	}

	/* Search for next available tty, fixup index tty1 => [0]. */
	for (ttynum = 1; ttynum <= ttys->max && ttys->tty[ttynum - 1].busy >= 0; ttynum++) {
		;
	}

	/* We didn't find any available slot for tty. */
	if (ttynum > ttys->max)
		goto out;

	*ttyreq = ttynum;

out_tty:
	ttys->tty[ttynum - 1].busy = sockfd;
	ptxfd = ttys->tty[ttynum - 1].ptx;

out:
	return ptxfd;
}

void lxc_terminal_free(struct lxc_conf *conf, int fd)
{
	int i;
	struct lxc_tty_info *ttys = &conf->ttys;
	struct lxc_terminal *terminal = &conf->console;

	for (i = 0; i < ttys->max; i++)
		if (ttys->tty[i].busy == fd)
			ttys->tty[i].busy = -1;

	if (terminal->proxy.busy != fd)
		return;

	lxc_mainloop_del_handler(terminal->descr, terminal->proxy.pty);
	lxc_terminal_peer_proxy_free(terminal);
}

static int lxc_terminal_peer_default(struct lxc_terminal *terminal)
{
	struct lxc_terminal_state *ts;
	const char *path;
	int ret = 0;

	if (terminal->path)
		path = terminal->path;
	else
		path = "/dev/tty";

	terminal->peer = lxc_unpriv(open(path, O_RDWR | O_CLOEXEC));
	if (terminal->peer < 0) {
		if (!terminal->path) {
			errno = ENODEV;
			SYSDEBUG("The process does not have a controlling terminal");
			goto on_succes;
		}

		SYSERROR("Failed to open proxy terminal \"%s\"", path);
		return -ENOTTY;
	}
	DEBUG("Using terminal \"%s\" as proxy", path);

	if (!isatty(terminal->peer)) {
		ERROR("File descriptor for \"%s\" does not refer to a terminal", path);
		goto on_error_free_tios;
	}

	ts = lxc_terminal_signal_init(terminal->peer, terminal->ptx);
	terminal->tty_state = ts;
	if (!ts) {
		WARN("Failed to install signal handler");
		goto on_error_free_tios;
	}

	lxc_terminal_winsz(terminal->peer, terminal->ptx);

	terminal->tios = malloc(sizeof(*terminal->tios));
	if (!terminal->tios)
		goto on_error_free_tios;

	ret = lxc_setup_tios(terminal->peer, terminal->tios);
	if (ret < 0)
		goto on_error_close_peer;
	else
		goto on_succes;

on_error_free_tios:
	free(terminal->tios);
	terminal->tios = NULL;

on_error_close_peer:
	close(terminal->peer);
	terminal->peer = -1;
	ret = -ENOTTY;

on_succes:
	return ret;
}

int lxc_terminal_write_ringbuffer(struct lxc_terminal *terminal)
{
	char *r_addr;
	ssize_t ret;
	uint64_t used;
	struct lxc_ringbuf *buf = &terminal->ringbuf;

	/* There's not log file where we can dump the ringbuffer to. */
	if (terminal->log_fd < 0)
		return 0;

	used = lxc_ringbuf_used(buf);
	if (used == 0)
		return 0;

	ret = lxc_terminal_truncate_log_file(terminal);
	if (ret < 0)
		return ret;

	/* Write as much as we can without exceeding the limit. */
	if (terminal->log_size < used)
		used = terminal->log_size;

	r_addr = lxc_ringbuf_get_read_addr(buf);
	ret = lxc_write_nointr(terminal->log_fd, r_addr, used);
	if (ret < 0)
		return -EIO;

	return 0;
}

void lxc_terminal_delete(struct lxc_terminal *terminal)
{
	int ret;

	ret = lxc_terminal_write_ringbuffer(terminal);
	if (ret < 0)
		WARN("Failed to write terminal log to disk");

	if (terminal->tios && terminal->peer >= 0) {
		ret = tcsetattr(terminal->peer, TCSAFLUSH, terminal->tios);
		if (ret < 0)
			SYSWARN("Failed to set old terminal settings");
	}
	free(terminal->tios);
	terminal->tios = NULL;

	if (terminal->peer >= 0)
		close(terminal->peer);
	terminal->peer = -1;

	if (terminal->ptx >= 0)
		close(terminal->ptx);
	terminal->ptx = -1;

	if (terminal->pty >= 0)
		close(terminal->pty);
	terminal->pty = -1;

	if (terminal->log_fd >= 0)
		close(terminal->log_fd);
	terminal->log_fd = -1;
}

/**
 * Note that this function needs to run before the mainloop starts. Since we
 * register a handler for the terminal's ptxfd when we create the mainloop
 * the terminal handler needs to see an allocated ringbuffer.
 */
static int lxc_terminal_create_ringbuf(struct lxc_terminal *terminal)
{
	int ret;
	struct lxc_ringbuf *buf = &terminal->ringbuf;
	uint64_t size = terminal->buffer_size;

	/* no ringbuffer previously allocated and no ringbuffer requested */
	if (!buf->addr && size <= 0)
		return 0;

	/* ringbuffer allocated but no new ringbuffer requested */
	if (buf->addr && size <= 0) {
		lxc_ringbuf_release(buf);
		buf->addr = NULL;
		buf->r_off = 0;
		buf->w_off = 0;
		buf->size = 0;
		TRACE("Deallocated terminal ringbuffer");
		return 0;
	}

	if (size <= 0)
		return 0;

	/* check wether the requested size for the ringbuffer has changed */
	if (buf->addr && buf->size != size) {
		TRACE("Terminal ringbuffer size changed from %" PRIu64
		      " to %" PRIu64 " bytes. Deallocating terminal ringbuffer",
		      buf->size, size);
		lxc_ringbuf_release(buf);
	}

	ret = lxc_ringbuf_create(buf, size);
	if (ret < 0) {
		ERROR("Failed to setup %" PRIu64 " byte terminal ringbuffer", size);
		return -1;
	}

	TRACE("Allocated %" PRIu64 " byte terminal ringbuffer", size);
	return 0;
}

/**
 * This is the terminal log file. Please note that the terminal log file is
 * (implementation wise not content wise) independent of the terminal ringbuffer.
 */
int lxc_terminal_create_log_file(struct lxc_terminal *terminal)
{
	if (!terminal->log_path)
		return 0;

	terminal->log_fd = lxc_unpriv(open(terminal->log_path, O_CLOEXEC | O_RDWR | O_CREAT | O_APPEND, 0600));
	if (terminal->log_fd < 0) {
		SYSERROR("Failed to open terminal log file \"%s\"", terminal->log_path);
		return -1;
	}

	DEBUG("Using \"%s\" as terminal log file", terminal->log_path);
	return 0;
}

static int lxc_terminal_map_ids(struct lxc_conf *c, struct lxc_terminal *terminal)
{
	int ret;

	if (lxc_list_empty(&c->id_map))
		return 0;

	if (is_empty_string(terminal->name) && terminal->pty < 0)
		return 0;

	if (terminal->pty >= 0)
		ret = userns_exec_mapped_root(NULL, terminal->pty, c);
	else
		ret = userns_exec_mapped_root(terminal->name, -EBADF, c);
	if (ret < 0)
		return log_error(-1, "Failed to chown terminal %d(%s)", terminal->pty,
				 !is_empty_string(terminal->name) ? terminal->name : "(null)");

	TRACE("Chowned terminal %d(%s)", terminal->pty,
	      !is_empty_string(terminal->name) ? terminal->name : "(null)");

	return 0;
}

static int lxc_terminal_create_foreign(struct lxc_conf *conf, struct lxc_terminal *terminal)
{
	int ret;

	ret = openpty(&terminal->ptx, &terminal->pty, NULL, NULL, NULL);
	if (ret < 0) {
		SYSERROR("Failed to open terminal");
		return -1;
	}

	ret = lxc_terminal_map_ids(conf, terminal);
	if (ret < 0) {
		SYSERROR("Failed to change ownership of terminal multiplexer device");
		goto err;
	}

	ret = ttyname_r(terminal->pty, terminal->name, sizeof(terminal->name));
	if (ret < 0) {
		SYSERROR("Failed to retrieve name of terminal pty");
		goto err;
	}

	ret = fd_cloexec(terminal->ptx, true);
	if (ret < 0) {
		SYSERROR("Failed to set FD_CLOEXEC flag on terminal ptx");
		goto err;
	}

	ret = fd_cloexec(terminal->pty, true);
	if (ret < 0) {
		SYSERROR("Failed to set FD_CLOEXEC flag on terminal pty");
		goto err;
	}

	ret = lxc_terminal_peer_default(terminal);
	if (ret < 0) {
		ERROR("Failed to allocate proxy terminal");
		goto err;
	}

	return 0;

err:
	lxc_terminal_delete(terminal);
	return -ENODEV;
}

static int lxc_terminal_create_native(const char *name, const char *lxcpath, struct lxc_conf *conf,
				      struct lxc_terminal *terminal)
{
	__do_close int devpts_fd = -EBADF;
	int ret;

	devpts_fd = lxc_cmd_get_devpts_fd(name, lxcpath);
	if (devpts_fd < 0)
		return log_error_errno(-1, errno, "Failed to receive devpts fd");

	terminal->ptx = open_beneath(devpts_fd, "ptmx", O_RDWR | O_NOCTTY | O_CLOEXEC);
	if (terminal->ptx < 0) {
		if (errno == ENOSPC)
			return systrace("Exceeded number of allocatable terminals");

		return syserror("Failed to open terminal multiplexer device");
	}

	ret = unlockpt(terminal->ptx);
	if (ret < 0) {
		SYSWARN("Failed to unlock multiplexer device device");
		goto err;
	}

	terminal->pty = ioctl(terminal->ptx, TIOCGPTPEER, O_RDWR | O_NOCTTY | O_CLOEXEC);
	if (terminal->pty < 0) {
		switch (errno) {
		case ENOTTY:
			SYSTRACE("Pure fd-based terminal allocation not possible");
			break;
		case ENOSPC:
			SYSTRACE("Exceeded number of allocatable terminals");
			break;
		default:
			SYSWARN("Failed to allocate new pty device");
			break;
		}
		goto err;
	}

	ret = ttyname_r(terminal->pty, terminal->name, sizeof(terminal->name));
	if (ret < 0) {
		SYSWARN("Failed to retrieve name of terminal pty");
		goto err;
	}

	ret = lxc_terminal_peer_default(terminal);
	if (ret < 0) {
		SYSWARN("Failed to allocate proxy terminal");
		goto err;
	}

	return 0;

err:
	lxc_terminal_delete(terminal);
	return -ENODEV;
}

int lxc_terminal_create(const char *name, const char *lxcpath,
			struct lxc_conf *conf, struct lxc_terminal *terminal)
{
	if (!lxc_terminal_create_native(name, lxcpath, conf, terminal))
		return 0;

	return lxc_terminal_create_foreign(conf, terminal);
}

int lxc_terminal_setup(struct lxc_conf *conf)
{
	int ret;
	struct lxc_terminal *terminal = &conf->console;

	if (terminal->path && strequal(terminal->path, "none"))
		return log_info(0, "No terminal requested");

	ret = lxc_terminal_create_foreign(conf, terminal);
	if (ret < 0)
		return -1;

	ret = lxc_terminal_create_log_file(terminal);
	if (ret < 0)
		goto err;

	ret = lxc_terminal_create_ringbuf(terminal);
	if (ret < 0)
		goto err;

	return 0;

err:
	lxc_terminal_delete(terminal);
	return -ENODEV;
}

static bool __terminal_dup2(int duplicate, int original)
{
	int ret;

	if (!isatty(original))
		return true;

	ret = dup2(duplicate, original);
	if (ret < 0) {
		SYSERROR("Failed to dup2(%d, %d)", duplicate, original);
		return false;
	}

	return true;
}

int lxc_terminal_set_stdfds(int fd)
{
	int i;

	if (fd < 0)
		return 0;

	for (i = 0; i < 3; i++)
		if (!__terminal_dup2(fd, (int[]){STDIN_FILENO, STDOUT_FILENO,
						 STDERR_FILENO}[i]))
			return -1;

	return 0;
}

int lxc_terminal_stdin_cb(int fd, uint32_t events, void *cbdata,
			  struct lxc_epoll_descr *descr)
{
	int ret;
	char c;
	struct lxc_terminal_state *ts = cbdata;

	if (fd != ts->stdinfd)
		return LXC_MAINLOOP_CLOSE;

	ret = lxc_read_nointr(ts->stdinfd, &c, 1);
	if (ret <= 0)
		return LXC_MAINLOOP_CLOSE;

	if (ts->escape >= 1) {
		/* we want to exit the terminal with Ctrl+a q */
		if (c == ts->escape && !ts->saw_escape) {
			ts->saw_escape = 1;
			return LXC_MAINLOOP_CONTINUE;
		}

		if (c == 'q' && ts->saw_escape)
			return LXC_MAINLOOP_CLOSE;

		ts->saw_escape = 0;
	}

	ret = lxc_write_nointr(ts->ptxfd, &c, 1);
	if (ret <= 0)
		return LXC_MAINLOOP_CLOSE;

	return LXC_MAINLOOP_CONTINUE;
}

int lxc_terminal_ptx_cb(int fd, uint32_t events, void *cbdata,
			   struct lxc_epoll_descr *descr)
{
	int r, w;
	char buf[LXC_TERMINAL_BUFFER_SIZE];
	struct lxc_terminal_state *ts = cbdata;

	if (fd != ts->ptxfd)
		return LXC_MAINLOOP_CLOSE;

	r = lxc_read_nointr(fd, buf, sizeof(buf));
	if (r <= 0)
		return LXC_MAINLOOP_CLOSE;

	w = lxc_write_nointr(ts->stdoutfd, buf, r);
	if (w <= 0 || w != r)
		return LXC_MAINLOOP_CLOSE;

	return LXC_MAINLOOP_CONTINUE;
}

int lxc_terminal_getfd(struct lxc_container *c, int *ttynum, int *ptxfd)
{
	return lxc_cmd_get_tty_fd(c->name, ttynum, ptxfd, c->config_path);
}

int lxc_console(struct lxc_container *c, int ttynum,
		int stdinfd, int stdoutfd, int stderrfd,
		int escape)
{
	int ptxfd, ret, ttyfd;
	struct lxc_epoll_descr descr;
	struct termios oldtios;
	struct lxc_terminal_state *ts;
	struct lxc_terminal terminal = {
		.tty_state = NULL,
	};
	int istty = 0;

	ttyfd = lxc_cmd_get_tty_fd(c->name, &ttynum, &ptxfd, c->config_path);
	if (ttyfd < 0)
		return -1;

	ret = setsid();
	if (ret < 0)
		TRACE("Process is already group leader");

	ts = lxc_terminal_signal_init(stdinfd, ptxfd);
	if (!ts) {
		ret = -1;
		goto close_fds;
	}
	terminal.tty_state = ts;
	ts->escape = escape;
	ts->stdoutfd = stdoutfd;

	istty = isatty(stdinfd);
	if (istty) {
		lxc_terminal_winsz(stdinfd, ptxfd);
		lxc_terminal_winsz(ts->stdinfd, ts->ptxfd);
	} else {
		INFO("File descriptor %d does not refer to a terminal", stdinfd);
	}

	ret = lxc_mainloop_open(&descr);
	if (ret) {
		ERROR("Failed to create mainloop");
		goto sigwinch_fini;
	}

	if (ts->sigfd != -1) {
		ret = lxc_mainloop_add_handler(&descr, ts->sigfd,
					       lxc_terminal_signalfd_cb, ts);
		if (ret < 0) {
			ERROR("Failed to add signal handler to mainloop");
			goto close_mainloop;
		}
	}

	ret = lxc_mainloop_add_handler(&descr, ts->stdinfd,
				       lxc_terminal_stdin_cb, ts);
	if (ret < 0) {
		ERROR("Failed to add stdin handler");
		goto close_mainloop;
	}

	ret = lxc_mainloop_add_handler(&descr, ts->ptxfd,
				       lxc_terminal_ptx_cb, ts);
	if (ret < 0) {
		ERROR("Failed to add ptx handler");
		goto close_mainloop;
	}

	if (ts->escape >= 1) {
		fprintf(stderr,
			"\n"
			"Connected to tty %1$d\n"
			"Type <Ctrl+%2$c q> to exit the console, "
			"<Ctrl+%2$c Ctrl+%2$c> to enter Ctrl+%2$c itself\n",
			ttynum, 'a' + escape - 1);
	}

	if (istty) {
		ret = lxc_setup_tios(stdinfd, &oldtios);
		if (ret < 0)
			goto close_mainloop;
	}

	ret = lxc_mainloop(&descr, -1);
	if (ret < 0) {
		ERROR("The mainloop returned an error");
		goto restore_tios;
	}

	ret = 0;

restore_tios:
	if (istty) {
		istty = tcsetattr(stdinfd, TCSAFLUSH, &oldtios);
		if (istty < 0)
			SYSWARN("Failed to restore terminal properties");
	}

close_mainloop:
	lxc_mainloop_close(&descr);

sigwinch_fini:
	lxc_terminal_signal_fini(&terminal);

close_fds:
	close(ptxfd);
	close(ttyfd);

	return ret;
}

int lxc_make_controlling_terminal(int fd)
{
	int ret;

	setsid();

	ret = ioctl(fd, TIOCSCTTY, (char *)NULL);
	if (ret < 0)
		return -1;

	return 0;
}

int lxc_terminal_prepare_login(int fd)
{
	int ret;

	ret = lxc_make_controlling_terminal(fd);
	if (ret < 0)
		return -1;

	ret = lxc_terminal_set_stdfds(fd);
	if (ret < 0)
		return -1;

	if (fd > STDERR_FILENO)
		close(fd);

	return 0;
}

void lxc_terminal_info_init(struct lxc_terminal_info *terminal)
{
	terminal->name[0] = '\0';
	terminal->ptx = -EBADF;
	terminal->pty = -EBADF;
	terminal->busy = -1;
}

void lxc_terminal_init(struct lxc_terminal *terminal)
{
	memset(terminal, 0, sizeof(*terminal));
	terminal->pty = -EBADF;
	terminal->ptx = -EBADF;
	terminal->peer = -EBADF;
	terminal->log_fd = -EBADF;
	lxc_terminal_info_init(&terminal->proxy);
}

void lxc_terminal_conf_free(struct lxc_terminal *terminal)
{
	free(terminal->log_path);
	free(terminal->path);
	if (terminal->buffer_size > 0 && terminal->ringbuf.addr)
		lxc_ringbuf_release(&terminal->ringbuf);
	lxc_terminal_signal_fini(terminal);
}
