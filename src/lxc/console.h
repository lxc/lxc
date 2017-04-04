/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2010
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

#ifndef __LXC_CONSOLE_H
#define __LXC_CONSOLE_H

#include "conf.h"
#include "list.h"

struct lxc_epoll_descr; /* defined in mainloop.h */
struct lxc_container; /* defined in lxccontainer.h */
struct lxc_tty_state
{
	struct lxc_list node;
	int stdinfd;
	int stdoutfd;
	int masterfd;
	/* Escape sequence to use for exiting the pty. A single char can be
	 * specified. The pty can then exited by doing: Ctrl + specified_char + q.
	 * This field is checked by lxc_console_cb_tty_stdin(). Set to -1 to
	 * disable exiting the pty via a escape sequence. */
	int escape;
	/* Used internally by lxc_console_cb_tty_stdin() to check whether an
	 * escape sequence has been received. */
	int saw_escape;
	/* Name of the container to forward the SIGWINCH event to. */
	const char *winch_proxy;
	/* Path of the container to forward the SIGWINCH event to. */
	const char *winch_proxy_lxcpath;
	/* File descriptor that accepts SIGWINCH signals. If set to -1 no
	 * SIGWINCH handler could be installed. This also means that
	 * the sigset_t oldmask member is meaningless. */
	int sigfd;
	sigset_t oldmask;
};

/*
 * lxc_console_allocate: allocate the console or a tty
 *
 * @conf    : the configuration of the container to allocate from
 * @sockfd  : the socket fd whose remote side when closed, will be an
 *            indication that the console or tty is no longer in use
 * @ttyreq  : the tty requested to be opened, -1 for any, 0 for the console
 */
extern int  lxc_console_allocate(struct lxc_conf *conf, int sockfd, int *ttynum);

/*
 * Create a new pty:
 * - calls openpty() to allocate a master/slave pty pair
 * - sets the FD_CLOEXEC flag on the master/slave fds
 * - allocates either the current controlling pty (default) or a user specified
 *   pty as peer pty for the newly created master/slave pair
 * - sets up SIGWINCH handler, winsz, and new terminal settings
 *   (Handlers for SIGWINCH and I/O are not registered in a mainloop.)
 * (For an unprivileged container the created pty on the host is not
 * automatically chowned to the uid/gid of the unprivileged user. For this
 * ttys_shift_ids() can be called.)
 */
extern int  lxc_console_create(struct lxc_conf *);

/*
 * Delete a pty created via lxc_console_create():
 * - set old terminal settings
 * - memory allocated via lxc_console_create() is free()ed.
 * - close master/slave pty pair and allocated fd for the peer (usually
 *   /dev/tty)
 * Registered handlers in a mainloop are not automatically deleted.
 */
extern void lxc_console_delete(struct lxc_console *);

/*
 * lxc_console_free: mark the console or a tty as unallocated, free any
 * resources allocated by lxc_console_allocate().
 *
 * @conf : the configuration of the container whose tty was closed
 * @fd   : the socket fd whose remote side was closed, which indicated
 *         the console or tty is no longer in use. this is used to match
 *         which console/tty is being freed.
 */
extern void lxc_console_free(struct lxc_conf *conf, int fd);

/*
 * Register pty event handlers in an open mainloop
 */
extern int  lxc_console_mainloop_add(struct lxc_epoll_descr *, struct lxc_conf *);

/*
 * Handle SIGWINCH events on the allocated ptys.
 */
extern void lxc_console_sigwinch(int sig);

/*
 * Connect to one of the ptys given to the container via lxc.tty.
 * - allocates either the current controlling pty (default) or a user specified
 *   pty as peer pty for the containers tty
 * - sets up SIGWINCH handler, winsz, and new terminal settings
 * - opens mainloop
 * - registers SIGWINCH, I/O handlers in the mainloop
 * - performs all necessary cleanup operations
 */
extern int  lxc_console(struct lxc_container *c, int ttynum,
		        int stdinfd, int stdoutfd, int stderrfd,
		        int escape);

/*
 * Allocate one of the ptys given to the container via lxc.tty. Returns an open
 * fd to the allocated pty.
 * Set ttynum to -1 to allocate the first available pty, or to a value within
 * the range specified by lxc.tty to allocate a specific pty.
 */
extern int  lxc_console_getfd(struct lxc_container *c, int *ttynum,
			      int *masterfd);

/*
 * Make fd a duplicate of the standard file descriptors:
 * fd is made a duplicate of a specific standard file descriptor iff the
 * standard file descriptor refers to a pty.
 */
extern int lxc_console_set_stdfds(int fd);

/*
 * Handler for events on the stdin fd of the pty. To be registered via the
 * corresponding functions declared and defined in mainloop.{c,h} or
 * lxc_console_mainloop_add().
 * This function exits the loop cleanly when an EPOLLHUP event is received.
 */
extern int lxc_console_cb_tty_stdin(int fd, uint32_t events, void *cbdata,
		struct lxc_epoll_descr *descr);

/*
 * Handler for events on the master fd of the pty. To be registered via the
 * corresponding functions declared and defined in mainloop.{c,h} or
 * lxc_console_mainloop_add().
 * This function exits the loop cleanly when an EPOLLHUP event is received.
 */
extern int lxc_console_cb_tty_master(int fd, uint32_t events, void *cbdata,
		struct lxc_epoll_descr *descr);

/*
 * Setup new terminal properties. The old terminal settings are stored in
 * oldtios.
 */
extern int lxc_setup_tios(int fd, struct termios *oldtios);


/*
 * lxc_console_winsz: propagte winsz from one terminal to another
 *
 * @srcfd : terminal to get size from (typically a slave pty)
 * @dstfd : terminal to set size on (typically a master pty)
 */
extern void lxc_console_winsz(int srcfd, int dstfd);

/*
 * lxc_console_sigwinch_init: install SIGWINCH handler
 *
 * @srcfd  : src for winsz in SIGWINCH handler
 * @dstfd  : dst for winsz in SIGWINCH handler
 *
 * Returns lxc_tty_state structure on success or NULL on failure. The sigfd
 * member of the returned lxc_tty_state can be select()/poll()ed/epoll()ed
 * on (ie added to a mainloop) for SIGWINCH.
 *
 * Must be called with process_lock held to protect the lxc_ttys list, or
 * from a non-threaded context.
 *
 * Note that SIGWINCH isn't installed as a classic asychronous handler,
 * rather signalfd(2) is used so that we can handle the signal when we're
 * ready for it. This avoids deadlocks since a signal handler
 * (ie lxc_console_sigwinch()) would need to take the thread mutex to
 * prevent lxc_ttys list corruption, but using the fd we can provide the
 * tty_state needed to the callback (lxc_console_cb_sigwinch_fd()).
 *
 * This function allocates memory. It is up to the caller to free it.
 */
extern struct lxc_tty_state *lxc_console_sigwinch_init(int srcfd, int dstfd);

/*
 * Handler for SIGWINCH events. To be registered via the corresponding functions
 * declared and defined in mainloop.{c,h} or lxc_console_mainloop_add().
 */
extern int lxc_console_cb_sigwinch_fd(int fd, uint32_t events, void *cbdata,
		struct lxc_epoll_descr *descr);

/*
 * lxc_console_sigwinch_fini: uninstall SIGWINCH handler
 *
 * @ts  : the lxc_tty_state returned by lxc_console_sigwinch_init
 *
 * Restore the saved signal handler that was in effect at the time
 * lxc_console_sigwinch_init() was called.
 *
 * Must be called with process_lock held to protect the lxc_ttys list, or
 * from a non-threaded context.
 */
extern void lxc_console_sigwinch_fini(struct lxc_tty_state *ts);

#endif
