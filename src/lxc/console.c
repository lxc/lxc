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

#include <assert.h>
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

lxc_log_define(lxc_console, lxc);

static struct lxc_list lxc_ttys;

typedef void (*sighandler_t)(int);

__attribute__((constructor))
void lxc_console_init(void)
{
	lxc_list_init(&lxc_ttys);
}

void lxc_console_winsz(int srcfd, int dstfd)
{
	struct winsize wsz;
	if (isatty(srcfd) && ioctl(srcfd, TIOCGWINSZ, &wsz) == 0) {
		DEBUG("set winsz dstfd:%d cols:%d rows:%d", dstfd,
		      wsz.ws_col, wsz.ws_row);
		ioctl(dstfd, TIOCSWINSZ, &wsz);
	}
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

int lxc_console_cb_sigwinch_fd(int fd, uint32_t events, void *cbdata,
		struct lxc_epoll_descr *descr)
{
	struct signalfd_siginfo siginfo;
	struct lxc_tty_state *ts = cbdata;

	ssize_t ret = read(fd, &siginfo, sizeof(siginfo));
	if (ret < 0 || (size_t)ret < sizeof(siginfo)) {
		ERROR("failed to read signal info");
		return -1;
	}

	lxc_console_winch(ts);
	return 0;
}

struct lxc_tty_state *lxc_console_sigwinch_init(int srcfd, int dstfd)
{
	sigset_t mask;
	struct lxc_tty_state *ts;

	ts = malloc(sizeof(*ts));
	if (!ts)
		return NULL;

	memset(ts, 0, sizeof(*ts));
	ts->stdinfd = srcfd;
	ts->masterfd = dstfd;
	ts->sigfd = -1;

	/* add tty to list to be scanned at SIGWINCH time */
	lxc_list_add_elem(&ts->node, ts);
	lxc_list_add_tail(&lxc_ttys, &ts->node);

	sigemptyset(&mask);
	sigaddset(&mask, SIGWINCH);
	if (sigprocmask(SIG_BLOCK, &mask, &ts->oldmask)) {
		SYSERROR("failed to block SIGWINCH.");
		ts->sigfd = -1;
		return ts;
	}

	ts->sigfd = signalfd(-1, &mask, 0);
	if (ts->sigfd < 0) {
		SYSERROR("failed to get signalfd.");
		sigprocmask(SIG_SETMASK, &ts->oldmask, NULL);
		ts->sigfd = -1;
		return ts;
	}

	DEBUG("%d got SIGWINCH fd %d", getpid(), ts->sigfd);
	return ts;
}

void lxc_console_sigwinch_fini(struct lxc_tty_state *ts)
{
	if (ts->sigfd >= 0)
		close(ts->sigfd);

	lxc_list_del(&ts->node);
	sigprocmask(SIG_SETMASK, &ts->oldmask, NULL);
	free(ts);
}

static int lxc_console_cb_con(int fd, uint32_t events, void *data,
			      struct lxc_epoll_descr *descr)
{
	struct lxc_console *console = (struct lxc_console *)data;
	char buf[1024];
	int r, w;

	w = r = lxc_read_nointr(fd, buf, sizeof(buf));
	if (r <= 0) {
		INFO("console client on fd %d has exited", fd);
		lxc_mainloop_del_handler(descr, fd);
		close(fd);
		return 1;
	}

	if (fd == console->peer)
		w = lxc_write_nointr(console->master, buf, r);

	if (fd == console->master) {
		if (console->log_fd >= 0)
			w = lxc_write_nointr(console->log_fd, buf, r);

		if (console->peer >= 0)
			w = lxc_write_nointr(console->peer, buf, r);
	}

	if (w != r)
		WARN("console short write r:%d w:%d", r, w);

	return 0;
}

static void lxc_console_mainloop_add_peer(struct lxc_console *console)
{
	if (console->peer >= 0) {
		if (lxc_mainloop_add_handler(console->descr, console->peer,
					     lxc_console_cb_con, console))
			WARN("console peer not added to mainloop");
	}

	if (console->tty_state && console->tty_state->sigfd != -1) {
		if (lxc_mainloop_add_handler(console->descr,
					     console->tty_state->sigfd,
					     lxc_console_cb_sigwinch_fd,
					     console->tty_state)) {
			WARN("failed to add to mainloop SIGWINCH handler for '%d'",
			     console->tty_state->sigfd);
		}
	}
}

extern int lxc_console_mainloop_add(struct lxc_epoll_descr *descr,
				    struct lxc_conf *conf)
{
	struct lxc_console *console = &conf->console;

	if (conf->is_execute) {
		INFO("no console for lxc-execute.");
		return 0;
	}

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

	newtios = *oldtios;

	/* We use the same settings that ssh does. */
	newtios.c_iflag |= IGNPAR;
	newtios.c_iflag &= ~(ISTRIP | INLCR | IGNCR | ICRNL | IXON | IXANY | IXOFF);
#ifdef IUCLC
	newtios.c_iflag &= ~IUCLC;
#endif
	newtios.c_lflag &= ~(ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHONL);
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
	if (console->tty_state && console->tty_state->sigfd != -1) {
		lxc_console_sigwinch_fini(console->tty_state);
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

	ts = lxc_console_sigwinch_init(console->peerpty.master, console->master);
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

static void lxc_console_peer_default(struct lxc_console *console)
{
	struct lxc_tty_state *ts;
	const char *path = console->path;

	/* if no console was given, try current controlling terminal, there
	 * won't be one if we were started as a daemon (-d)
	 */
	if (!path && !access("/dev/tty", F_OK)) {
		int fd;
		fd = open("/dev/tty", O_RDWR);
		if (fd >= 0) {
			close(fd);
			path = "/dev/tty";
		}
	}

	if (!path)
		goto out;

	DEBUG("opening %s for console peer", path);
	console->peer = lxc_unpriv(open(path, O_CLOEXEC | O_RDWR | O_CREAT |
					O_APPEND, 0600));
	if (console->peer < 0)
		goto out;

	DEBUG("using '%s' as console", path);

	if (!isatty(console->peer))
		goto err1;

	ts = lxc_console_sigwinch_init(console->peer, console->master);
	console->tty_state = ts;
	if (!ts) {
		WARN("Unable to install SIGWINCH");
		goto err1;
	}

	lxc_console_winsz(console->peer, console->master);

	console->tios = malloc(sizeof(*console->tios));
	if (!console->tios) {
		SYSERROR("failed to allocate memory");
		goto err1;
	}

	if (lxc_setup_tios(console->peer, console->tios) < 0)
		goto err2;

	return;

err2:
	free(console->tios);
	console->tios = NULL;
err1:
	close(console->peer);
	console->peer = -1;
out:
	DEBUG("no console peer");
	return;
}

void lxc_console_delete(struct lxc_console *console)
{
	if (console->tios && console->peer >= 0 &&
	    tcsetattr(console->peer, TCSAFLUSH, console->tios))
		WARN("failed to set old terminal settings");
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
}

int lxc_console_create(struct lxc_conf *conf)
{
	struct lxc_console *console = &conf->console;
	int ret;

	if (conf->is_execute) {
		INFO("no console for lxc-execute.");
		return 0;
	}

	if (!conf->rootfs.path)
		return 0;

	if (console->path && !strcmp(console->path, "none"))
		return 0;

	process_lock();
	ret = openpty(&console->master, &console->slave,
		    console->name, NULL, NULL);
	process_unlock();
	if (ret) {
		SYSERROR("failed to allocate a pty");
		return -1;
	}

	if (fcntl(console->master, F_SETFD, FD_CLOEXEC)) {
		SYSERROR("failed to set console master to close-on-exec");
		goto err;
	}

	if (fcntl(console->slave, F_SETFD, FD_CLOEXEC)) {
		SYSERROR("failed to set console slave to close-on-exec");
		goto err;
	}

	lxc_console_peer_default(console);

	if (console->log_path) {
		console->log_fd = lxc_unpriv(open(console->log_path,
						  O_CLOEXEC | O_RDWR |
						  O_CREAT | O_APPEND, 0600));
		if (console->log_fd < 0) {
			SYSERROR("failed to open '%s'", console->log_path);
			goto err;
		}
		DEBUG("using '%s' as console log", console->log_path);
	}

	return 0;

err:
	lxc_console_delete(console);
	return -1;
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

	assert(fd == ts->stdinfd);
	if (lxc_read_nointr(ts->stdinfd, &c, 1) <= 0)
		return 1;

	if (ts->escape != -1) {
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
	char buf[1024];
	int r, w;

	assert(fd == ts->masterfd);
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

	if (!isatty(stdinfd)) {
		ERROR("stdin is not a tty");
		return -1;
	}

	ret = lxc_setup_tios(stdinfd, &oldtios);
	if (ret) {
		ERROR("failed to setup tios");
		return -1;
	}

	ttyfd = lxc_cmd_console(c->name, &ttynum, &masterfd, c->config_path);
	if (ttyfd < 0) {
		ret = ttyfd;
		goto err1;
	}

	fprintf(stderr, "\n"
			"Connected to tty %1$d\n"
			"Type <Ctrl+%2$c q> to exit the console, "
			"<Ctrl+%2$c Ctrl+%2$c> to enter Ctrl+%2$c itself\n",
			ttynum, 'a' + escape - 1);

	ret = setsid();
	if (ret)
		INFO("already group leader");

	ts = lxc_console_sigwinch_init(stdinfd, masterfd);
	if (!ts) {
		ret = -1;
		goto err2;
	}
	ts->escape = escape;
	ts->winch_proxy = c->name;
	ts->winch_proxy_lxcpath = c->config_path;

	lxc_console_winsz(stdinfd, masterfd);
	lxc_cmd_console_winch(ts->winch_proxy, ts->winch_proxy_lxcpath);

	ret = lxc_mainloop_open(&descr);
	if (ret) {
		ERROR("failed to create mainloop");
		goto err3;
	}

	if (ts->sigfd != -1) {
		ret = lxc_mainloop_add_handler(&descr, ts->sigfd,
				lxc_console_cb_sigwinch_fd, ts);
		if (ret) {
			ERROR("failed to add handler for SIGWINCH fd");
			goto err4;
		}
	}

	ret = lxc_mainloop_add_handler(&descr, ts->stdinfd,
				       lxc_console_cb_tty_stdin, ts);
	if (ret) {
		ERROR("failed to add handler for stdinfd");
		goto err4;
	}

	ret = lxc_mainloop_add_handler(&descr, ts->masterfd,
				       lxc_console_cb_tty_master, ts);
	if (ret) {
		ERROR("failed to add handler for masterfd");
		goto err4;
	}

	ret = lxc_mainloop(&descr, -1);
	if (ret) {
		ERROR("mainloop returned an error");
		goto err4;
	}

	ret = 0;

err4:
	lxc_mainloop_close(&descr);
err3:
	if (ts->sigfd != -1)
		lxc_console_sigwinch_fini(ts);
err2:
	close(masterfd);
	close(ttyfd);
err1:
	tcsetattr(stdinfd, TCSAFLUSH, &oldtios);

	return ret;
}

