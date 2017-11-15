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

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/types.h>

#include <lxc/lxccontainer.h>

#include "af_unix.h"
#include "caps.h"
#include "commands.h"
#include "conf.h"
#include "config.h"
#include "console.h"
#include "log.h"
#include "lxclock.h"
#include "mainloop.h"
#include "start.h" 	/* for struct lxc_handler */
#include "utils.h"

#if HAVE_PTY_H
#include <pty.h>
#else
#include <../include/openpty.h>
#endif

#define LXC_CONSOLE_BUFFER_SIZE 1024

lxc_log_define(console, lxc);

static struct lxc_list lxc_ttys;

typedef void (*sighandler_t)(int);

__attribute__((constructor)) void lxc_console_init(void)
{
	lxc_list_init(&lxc_ttys);
}

void lxc_console_winsz(int srcfd, int dstfd)
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

static void lxc_console_winch(struct lxc_tty_state *ts)
{
	lxc_console_winsz(ts->stdinfd, ts->masterfd);

	if (ts->winch_proxy)
		lxc_cmd_console_winch(ts->winch_proxy, ts->winch_proxy_lxcpath);
}

void lxc_console_sigwinch(int sig)
{
	struct lxc_list *it;
	struct lxc_tty_state *ts;

	lxc_list_for_each(it, &lxc_ttys) {
		ts = it->elem;
		lxc_console_winch(ts);
	}
}

int lxc_console_cb_signal_fd(int fd, uint32_t events, void *cbdata,
			       struct lxc_epoll_descr *descr)
{
	ssize_t ret;
	struct signalfd_siginfo siginfo;
	struct lxc_tty_state *ts = cbdata;

	ret = read(fd, &siginfo, sizeof(siginfo));
	if (ret < 0 || (size_t)ret < sizeof(siginfo)) {
		ERROR("Failed to read signal info");
		return -1;
	}

	if (siginfo.ssi_signo == SIGTERM) {
		DEBUG("Received SIGTERM. Detaching from the console");
		return 1;
	}

	if (siginfo.ssi_signo == SIGWINCH)
		lxc_console_winch(ts);

	return 0;
}

struct lxc_tty_state *lxc_console_signal_init(int srcfd, int dstfd)
{
	int ret;
	bool istty;
	sigset_t mask;
	struct lxc_tty_state *ts;

	ts = malloc(sizeof(*ts));
	if (!ts)
		return NULL;

	memset(ts, 0, sizeof(*ts));
	ts->stdinfd = srcfd;
	ts->masterfd = dstfd;
	ts->sigfd = -1;

	sigemptyset(&mask);

	istty = isatty(srcfd) == 1;
	if (!istty) {
		INFO("fd %d does not refer to a tty device", srcfd);
	} else {
		/* Add tty to list to be scanned at SIGWINCH time. */
		lxc_list_add_elem(&ts->node, ts);
		lxc_list_add_tail(&lxc_ttys, &ts->node);
		sigaddset(&mask, SIGWINCH);
	}

	/* Exit the mainloop cleanly on SIGTERM. */
	sigaddset(&mask, SIGTERM);

	ret = sigprocmask(SIG_BLOCK, &mask, &ts->oldmask);
	if (ret < 0) {
		WARN("Failed to block signals");
		goto on_error;
	}

	ts->sigfd = signalfd(-1, &mask, 0);
	if (ts->sigfd < 0) {
		WARN("Failed to create signal fd");
		sigprocmask(SIG_SETMASK, &ts->oldmask, NULL);
		goto on_error;
	}

	DEBUG("Created signal fd %d", ts->sigfd);
	return ts;

on_error:
	ERROR("Failed to create signal fd");
	if (ts->sigfd >= 0) {
		close(ts->sigfd);
		ts->sigfd = -1;
	}
	if (istty)
		lxc_list_del(&ts->node);
	return ts;
}

void lxc_console_signal_fini(struct lxc_tty_state *ts)
{
	if (ts->sigfd >= 0) {
		close(ts->sigfd);

		if (sigprocmask(SIG_SETMASK, &ts->oldmask, NULL) < 0)
			WARN("%s - Failed to restore signal mask", strerror(errno));
	}

	if (isatty(ts->stdinfd))
		lxc_list_del(&ts->node);

	free(ts);
}

static int lxc_console_cb_con(int fd, uint32_t events, void *data,
			      struct lxc_epoll_descr *descr)
{
	struct lxc_console *console = (struct lxc_console *)data;
	char buf[LXC_CONSOLE_BUFFER_SIZE];
	int r, w, w_log, w_rbuf;

	w = r = lxc_read_nointr(fd, buf, sizeof(buf));
	if (r <= 0) {
		INFO("Console client on fd %d has exited", fd);
		lxc_mainloop_del_handler(descr, fd);
		if (fd == console->peer) {
			if (console->tty_state) {
				lxc_console_signal_fini(console->tty_state);
				console->tty_state = NULL;
			}
			console->peer = -1;
			close(fd);
			return 0;
		}
		close(fd);
		return 1;
	}

	if (fd == console->peer)
		w = lxc_write_nointr(console->master, buf, r);

	w_rbuf = w_log = 0;
	if (fd == console->master) {
		/* write to peer first */
		if (console->peer >= 0)
			w = lxc_write_nointr(console->peer, buf, r);

		/* write to console ringbuffer */
		if (console->buffer_size > 0)
			w_rbuf = lxc_ringbuf_write(&console->ringbuf, buf, r);

		/* write to console log */
		if (console->log_fd >= 0)
			w_log = lxc_write_nointr(console->log_fd, buf, r);
	}

	if (w != r)
		WARN("Console short write r:%d != w:%d", r, w);

	if (w_rbuf < 0)
		TRACE("%s - Failed to write %d bytes to console ringbuffer",
		      strerror(-w_rbuf), r);

	if (w_log < 0)
		TRACE("Failed to write %d bytes to console log", r);

	return 0;
}

static void lxc_console_mainloop_add_peer(struct lxc_console *console)
{
	if (console->peer >= 0) {
		if (lxc_mainloop_add_handler(console->descr, console->peer,
					     lxc_console_cb_con, console))
			WARN("Failed to add console peer handler to mainloop");
	}

	if (console->tty_state && console->tty_state->sigfd != -1) {
		if (lxc_mainloop_add_handler(console->descr,
					     console->tty_state->sigfd,
					     lxc_console_cb_signal_fd,
					     console->tty_state)) {
			WARN("Failed to add signal handler to mainloop");
		}
	}
}

extern int lxc_console_mainloop_add(struct lxc_epoll_descr *descr,
				    struct lxc_conf *conf)
{
	struct lxc_console *console = &conf->console;

	if (!conf->rootfs.path) {
		INFO("no rootfs, no console.");
		return 0;
	}

	if (console->master < 0) {
		INFO("no console");
		return 0;
	}

	if (lxc_mainloop_add_handler(descr, console->master,
				     lxc_console_cb_con, console)) {
		ERROR("failed to add to mainloop console handler for '%d'",
		      console->master);
		return -1;
	}

	/* we cache the descr so that we can add an fd to it when someone
	 * does attach to it in lxc_console_allocate()
	 */
	console->descr = descr;
	lxc_console_mainloop_add_peer(console);

	return 0;
}

int lxc_setup_tios(int fd, struct termios *oldtios)
{
	struct termios newtios;

	if (!isatty(fd)) {
		ERROR("'%d' is not a tty", fd);
		return -1;
	}

	/* Get current termios */
	if (tcgetattr(fd, oldtios)) {
		SYSERROR("failed to get current terminal settings");
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
	newtios.c_oflag &= ~OPOST;
	newtios.c_cc[VMIN] = 1;
	newtios.c_cc[VTIME] = 0;

	/* Set new attributes. */
	if (tcsetattr(fd, TCSAFLUSH, &newtios)) {
		ERROR("failed to set new terminal settings");
		return -1;
	}

	return 0;
}

static void lxc_console_peer_proxy_free(struct lxc_console *console)
{
	if (console->tty_state) {
		lxc_console_signal_fini(console->tty_state);
		console->tty_state = NULL;
	}
	close(console->peerpty.master);
	close(console->peerpty.slave);
	console->peerpty.master = -1;
	console->peerpty.slave = -1;
	console->peerpty.busy = -1;
	console->peerpty.name[0] = '\0';
	console->peer = -1;
}

static int lxc_console_peer_proxy_alloc(struct lxc_console *console, int sockfd)
{
	struct termios oldtermio;
	struct lxc_tty_state *ts;
	int ret;

	if (console->master < 0) {
		ERROR("console not set up");
		return -1;
	}
	if (console->peerpty.busy != -1 || console->peer != -1) {
		NOTICE("console already in use");
		return -1;
	}
	if (console->tty_state) {
		ERROR("console already has tty_state");
		return -1;
	}

	/* this is the proxy pty that will be given to the client, and that
	 * the real pty master will send to / recv from
	 */
	process_lock();
	ret = openpty(&console->peerpty.master, &console->peerpty.slave,
		    console->peerpty.name, NULL, NULL);
	process_unlock();
	if (ret) {
		SYSERROR("failed to create proxy pty");
		return -1;
	}

	if (lxc_setup_tios(console->peerpty.slave, &oldtermio) < 0)
		goto err1;

	ts = lxc_console_signal_init(console->peerpty.master, console->master);
	if (!ts)
		goto err1;

	console->tty_state = ts;
	console->peer = console->peerpty.slave;
	console->peerpty.busy = sockfd;
	lxc_console_mainloop_add_peer(console);

	DEBUG("%d %s peermaster:%d sockfd:%d", getpid(), __FUNCTION__, console->peerpty.master, sockfd);
	return 0;

err1:
	lxc_console_peer_proxy_free(console);
	return -1;
}

int lxc_console_allocate(struct lxc_conf *conf, int sockfd, int *ttyreq)
{
	int masterfd = -1, ttynum;
	struct lxc_tty_info *tty_info = &conf->tty_info;
	struct lxc_console *console = &conf->console;

	if (*ttyreq == 0) {
		if (lxc_console_peer_proxy_alloc(console, sockfd) < 0)
			goto out;
		masterfd = console->peerpty.master;
		goto out;
	}

	if (*ttyreq > 0) {
		if (*ttyreq > tty_info->nbtty)
			goto out;

		if (tty_info->pty_info[*ttyreq - 1].busy)
			goto out;

		/* the requested tty is available */
		ttynum = *ttyreq;
		goto out_tty;
	}

	/* search for next available tty, fixup index tty1 => [0] */
	for (ttynum = 1; ttynum <= tty_info->nbtty && tty_info->pty_info[ttynum - 1].busy; ttynum++)
		;

	/* we didn't find any available slot for tty */
	if (ttynum > tty_info->nbtty)
		goto out;

	*ttyreq = ttynum;

out_tty:
	tty_info->pty_info[ttynum - 1].busy = sockfd;
	masterfd = tty_info->pty_info[ttynum - 1].master;
out:
	return masterfd;
}

void lxc_console_free(struct lxc_conf *conf, int fd)
{
	int i;
	struct lxc_tty_info *tty_info = &conf->tty_info;
	struct lxc_console *console = &conf->console;

	for (i = 0; i < tty_info->nbtty; i++) {
		if (tty_info->pty_info[i].busy == fd)
			tty_info->pty_info[i].busy = 0;
	}

	if (console->peerpty.busy == fd) {
		lxc_mainloop_del_handler(console->descr, console->peerpty.slave);
		lxc_console_peer_proxy_free(console);
	}
}

static int lxc_console_peer_default(struct lxc_console *console)
{
	struct lxc_tty_state *ts;
	const char *path = console->path;
	int fd;
	int ret = 0;

	/* If no console was given, try current controlling terminal, there
	 * won't be one if we were started as a daemon (-d).
	 */
	if (!path && !access("/dev/tty", F_OK)) {
		fd = open("/dev/tty", O_RDWR);
		if (fd >= 0) {
			close(fd);
			path = "/dev/tty";
		}
	}

	if (!path) {
		errno = ENOTTY;
		DEBUG("process does not have a controlling terminal");
		goto out;
	}

	console->peer = lxc_unpriv(open(path, O_CLOEXEC | O_RDWR | O_CREAT | O_APPEND, 0600));
	if (console->peer < 0) {
		ERROR("failed to open \"%s\": %s", path, strerror(errno));
		return -ENOTTY;
	}
	DEBUG("using \"%s\" as peer tty device", path);

	if (!isatty(console->peer)) {
		ERROR("file descriptor for file \"%s\" does not refer to a tty device", path);
		goto on_error1;
	}

	ts = lxc_console_signal_init(console->peer, console->master);
	console->tty_state = ts;
	if (!ts) {
		WARN("Failed to install signal handler");
		goto on_error1;
	}

	lxc_console_winsz(console->peer, console->master);

	console->tios = malloc(sizeof(*console->tios));
	if (!console->tios) {
		SYSERROR("failed to allocate memory");
		goto on_error1;
	}

	if (lxc_setup_tios(console->peer, console->tios) < 0)
		goto on_error2;
	else
		goto out;

on_error2:
	free(console->tios);
	console->tios = NULL;

on_error1:
	close(console->peer);
	console->peer = -1;
	ret = -ENOTTY;

out:
	return ret;
}

int lxc_console_write_ringbuffer(struct lxc_console *console)
{
	char *r_addr;
	ssize_t ret;
	uint64_t used;
	struct lxc_ringbuf *buf = &console->ringbuf;

	if (!console->buffer_log_file)
		return 0;

	used = lxc_ringbuf_used(buf);
	if (used == 0)
		return 0;

	r_addr = lxc_ringbuf_get_read_addr(buf);
	ret = lxc_write_nointr(console->buffer_log_file_fd, r_addr, used);
	if (ret < 0)
		return -EIO;

	return 0;
}

void lxc_console_delete(struct lxc_console *console)
{
	int ret;

	ret = lxc_console_write_ringbuffer(console);
	if (ret < 0)
		WARN("Failed to write console log to disk");

	if (console->tios && console->peer >= 0) {
		ret = tcsetattr(console->peer, TCSAFLUSH, console->tios);
		if (ret < 0)
			WARN("%s - Failed to set old terminal settings", strerror(errno));
	}
	free(console->tios);
	console->tios = NULL;

	close(console->peer);
	close(console->master);
	close(console->slave);
	if (console->log_fd >= 0)
		close(console->log_fd);
	console->peer = -1;
	console->master = -1;
	console->slave = -1;
	console->log_fd = -1;
	if (console->buffer_log_file_fd >= 0)
		close(console->buffer_log_file_fd);
	console->buffer_log_file_fd = -1;
}

/* This is the console ringbuffer log file. Please note that the console
 * ringbuffer log file is (implementation wise not content wise) independent of
 * the console log file.
 */
static int lxc_console_create_ringbuf_log_file(struct lxc_console *console)
{
	if (!console->buffer_log_file)
		return 0;

	console->buffer_log_file_fd = lxc_unpriv(open(console->buffer_log_file,
			    O_CLOEXEC | O_RDWR | O_CREAT | O_TRUNC, 0600));
	if (console->buffer_log_file_fd < 0) {
		SYSERROR("Failed to open console ringbuffer log file \"%s\"",
			 console->buffer_log_file);
		return -EIO;
	}

	DEBUG("Using \"%s\" as console ringbuffer log file", console->buffer_log_file);
	return 0;
}

/**
 * Note that this function needs to run before the mainloop starts. Since we
 * register a handler for the console's masterfd when we create the mainloop
 * the console handler needs to see an allocated ringbuffer.
 */
static int lxc_console_create_ringbuf(struct lxc_console *console)
{
	int ret;
	struct lxc_ringbuf *buf = &console->ringbuf;
	uint64_t size = console->buffer_size;

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
		TRACE("Deallocated console ringbuffer");
		return 0;
	}

	if (size <= 0)
		return 0;

	/* check wether the requested size for the ringbuffer has changed */
	if (buf->addr && buf->size != size) {
		TRACE("Console ringbuffer size changed from %" PRIu64
		      " to %" PRIu64 " bytes. Deallocating console ringbuffer",
		      buf->size, size);
		lxc_ringbuf_release(buf);
	}

	ret = lxc_ringbuf_create(buf, size);
	if (ret < 0) {
		ERROR("Failed to setup %" PRIu64 " byte console ringbuffer", size);
		return -1;
	}

	TRACE("Allocated %" PRIu64 " byte console ringbuffer", size);
	return 0;
}

/**
 * This is the console log file. Please note that the console log file is
 * (implementation wise not content wise) independent of the console ringbuffer.
 */
int lxc_console_create_log_file(struct lxc_console *console)
{
	if (!console->log_path)
		return 0;

	console->log_fd = lxc_unpriv(open(console->log_path, O_CLOEXEC | O_RDWR | O_CREAT | O_APPEND, 0600));
	if (console->log_fd < 0) {
		SYSERROR("Failed to open console log file \"%s\"", console->log_path);
		return -1;
	}

	DEBUG("Using \"%s\" as console log file", console->log_path);
	return 0;
}

int lxc_console_create(struct lxc_conf *conf)
{
	int ret, saved_errno;
	struct lxc_console *console = &conf->console;

	if (!conf->rootfs.path) {
		INFO("Container does not have a rootfs. The console will be "
		     "shared with the host");
		return 0;
	}

	if (console->path && !strcmp(console->path, "none")) {
		INFO("No console was requested");
		return 0;
	}

	process_lock();
	ret = openpty(&console->master, &console->slave, console->name, NULL, NULL);
	saved_errno = errno;
	process_unlock();
	if (ret < 0) {
		ERROR("%s - Failed to allocate a pty", strerror(saved_errno));
		return -1;
	}

	ret = fcntl(console->master, F_SETFD, FD_CLOEXEC);
	if (ret < 0) {
		SYSERROR("Failed to set FD_CLOEXEC flag on console master");
		goto err;
	}

	ret = fcntl(console->slave, F_SETFD, FD_CLOEXEC);
	if (ret < 0) {
		SYSERROR("Failed to set FD_CLOEXEC flag on console slave");
		goto err;
	}

	ret = lxc_console_peer_default(console);
	if (ret < 0) {
		ERROR("Failed to allocate a peer pty device");
		goto err;
	}

	/* create console log file */
	ret = lxc_console_create_log_file(console);
	if (ret < 0)
		goto err;

	/* create console ringbuffer */
	ret = lxc_console_create_ringbuf(console);
	if (ret < 0)
		goto err;

	/* create console ringbuffer log file */
	ret = lxc_console_create_ringbuf_log_file(console);
	if (ret < 0)
		goto err;

	return 0;

err:
	lxc_console_delete(console);
	return -ENODEV;
}

int lxc_console_set_stdfds(int fd)
{
	if (fd < 0)
		return 0;

	if (isatty(STDIN_FILENO))
		if (dup2(fd, STDIN_FILENO) < 0) {
			SYSERROR("failed to duplicate stdin.");
			return -1;
		}

	if (isatty(STDOUT_FILENO))
		if (dup2(fd, STDOUT_FILENO) < 0) {
			SYSERROR("failed to duplicate stdout.");
			return -1;
		}

	if (isatty(STDERR_FILENO))
		if (dup2(fd, STDERR_FILENO) < 0) {
			SYSERROR("failed to duplicate stderr.");
			return -1;
		}

	return 0;
}

int lxc_console_cb_tty_stdin(int fd, uint32_t events, void *cbdata,
		struct lxc_epoll_descr *descr)
{
	struct lxc_tty_state *ts = cbdata;
	char c;

	if (fd != ts->stdinfd)
		return 1;

	if (lxc_read_nointr(ts->stdinfd, &c, 1) <= 0)
		return 1;

	if (ts->escape >= 1) {
		/* we want to exit the console with Ctrl+a q */
		if (c == ts->escape && !ts->saw_escape) {
			ts->saw_escape = 1;
			return 0;
		}

		if (c == 'q' && ts->saw_escape)
			return 1;

		ts->saw_escape = 0;
	}

	if (lxc_write_nointr(ts->masterfd, &c, 1) <= 0)
		return 1;

	return 0;
}

int lxc_console_cb_tty_master(int fd, uint32_t events, void *cbdata,
		struct lxc_epoll_descr *descr)
{
	struct lxc_tty_state *ts = cbdata;
	char buf[LXC_CONSOLE_BUFFER_SIZE];
	int r, w;

	if (fd != ts->masterfd)
		return 1;

	r = lxc_read_nointr(fd, buf, sizeof(buf));
	if (r <= 0)
		return 1;

	w = lxc_write_nointr(ts->stdoutfd, buf, r);
	if (w <= 0) {
		return 1;
	} else if (w != r) {
		SYSERROR("failed to write");
		return 1;
	}

	return 0;
}

int lxc_console_getfd(struct lxc_container *c, int *ttynum, int *masterfd)
{
	return lxc_cmd_console(c->name, ttynum, masterfd, c->config_path);
}

int lxc_console(struct lxc_container *c, int ttynum,
		int stdinfd, int stdoutfd, int stderrfd,
		int escape)
{
	int ret, ttyfd, masterfd;
	struct lxc_epoll_descr descr;
	struct termios oldtios;
	struct lxc_tty_state *ts;
	int istty = 0;

	ttyfd = lxc_cmd_console(c->name, &ttynum, &masterfd, c->config_path);
	if (ttyfd < 0)
		return -1;

	ret = setsid();
	if (ret < 0)
		TRACE("Process is already group leader");

	ts = lxc_console_signal_init(stdinfd, masterfd);
	if (!ts) {
		ret = -1;
		goto close_fds;
	}
	ts->escape = escape;
	ts->winch_proxy = c->name;
	ts->winch_proxy_lxcpath = c->config_path;
	ts->stdoutfd = stdoutfd;

	istty = isatty(stdinfd);
	if (istty) {
		lxc_console_winsz(stdinfd, masterfd);
		lxc_cmd_console_winch(ts->winch_proxy, ts->winch_proxy_lxcpath);
	} else {
		INFO("File descriptor %d does not refer to a tty device", stdinfd);
	}

	ret = lxc_mainloop_open(&descr);
	if (ret) {
		ERROR("Failed to create mainloop");
		goto sigwinch_fini;
	}

	if (ts->sigfd != -1) {
		ret = lxc_mainloop_add_handler(&descr, ts->sigfd,
					       lxc_console_cb_signal_fd, ts);
		if (ret < 0) {
			ERROR("Failed to add signal handler to mainloop");
			goto close_mainloop;
		}
	}

	ret = lxc_mainloop_add_handler(&descr, ts->stdinfd,
				       lxc_console_cb_tty_stdin, ts);
	if (ret < 0) {
		ERROR("Failed to add stdin handler");
		goto close_mainloop;
	}

	ret = lxc_mainloop_add_handler(&descr, ts->masterfd,
				       lxc_console_cb_tty_master, ts);
	if (ret < 0) {
		ERROR("Failed to add master handler");
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
			WARN("%s - Failed to restore terminal properties",
			     strerror(errno));
	}

close_mainloop:
	lxc_mainloop_close(&descr);

sigwinch_fini:
	lxc_console_signal_fini(ts);

close_fds:
	close(masterfd);
	close(ttyfd);

	return ret;
}
