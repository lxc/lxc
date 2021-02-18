/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_TERMINAL_H
#define __LXC_TERMINAL_H

#include <signal.h>
#include <stdio.h>

#include "compiler.h"
#include "list.h"
#include "macro.h"
#include "ringbuf.h"

struct lxc_container;
struct lxc_conf;
struct lxc_epoll_descr;

struct lxc_terminal_info {
	/* the path name of the pty side */
	char name[PATH_MAX];

	/* the file descriptor of the ptx */
	int ptx;

	/* the file descriptor of the pty */
	int pty;

	/* whether the terminal is currently used */
	int busy;
};

struct lxc_terminal_state {
	struct lxc_list node;
	int stdinfd;
	int stdoutfd;
	int ptxfd;

	/* Escape sequence to use for exiting the terminal. A single char can
	 * be specified. The terminal can then exited by doing: Ctrl +
	 * specified_char + q. This field is checked by
	 * lxc_terminal_stdin_cb(). Set to -1 to disable exiting the terminal
	 * via a escape sequence.
	 */
	int escape;

	/* Used internally by lxc_terminal_stdin_cb() to check whether an
	 * escape sequence has been received.
	 */
	int saw_escape;

	/* File descriptor that accepts signals. If set to -1 no signal handler
	 * could be installed. This also means that the sigset_t oldmask member
	 * is meaningless.
	 */
	int sigfd;

	sigset_t oldmask;
};

struct lxc_terminal {
	int pty;
	int ptx;
	int peer;
	struct lxc_terminal_info proxy;
	struct lxc_epoll_descr *descr;
	char *path;
	char name[PATH_MAX];
	struct termios *tios;
	struct lxc_terminal_state *tty_state;

	struct /* lxc_terminal_log */ {
		/* size of the log file */
		uint64_t log_size;

		/* path to the log file */
		char *log_path;

		/* fd to the log file */
		int log_fd;

		/* whether the log file will be rotated */
		unsigned int log_rotate;
	};

	struct /* lxc_terminal_ringbuf */ {
		/* size of the ringbuffer */
		uint64_t buffer_size;

		/* the in-memory ringbuffer */
		struct lxc_ringbuf ringbuf;
	};
};

/**
 * lxc_terminal_allocate: allocate the console or a tty
 *
 * @conf    : the configuration of the container to allocate from
 * @sockfd  : the socket fd whose remote side when closed, will be an
 *            indication that the console or tty is no longer in use
 * @ttyreq  : the tty requested to be opened, -1 for any, 0 for the console
 */
__hidden extern int  lxc_terminal_allocate(struct lxc_conf *conf, int sockfd, int *ttynum);

/**
 * Create a new terminal:
 * - calls openpty() to allocate a ptx/pty pair
 * - sets the FD_CLOEXEC flag on the ptx/pty fds
 * - allocates either the current controlling terminal (default) or a user
 *   specified terminal as proxy for the newly created ptx/pty pair
 * - sets up SIGWINCH handler, winsz, and new terminal settings
 *   (Handlers for SIGWINCH and I/O are not registered in a mainloop.)
 */
__hidden extern int lxc_terminal_create(const char *name, const char *lxcpath,
					struct lxc_conf *conf,
					struct lxc_terminal *console);

/**
 * lxc_terminal_setup: Create a new terminal.
 * - In addition to lxc_terminal_create() also sets up logging.
 */
__hidden extern int lxc_terminal_setup(struct lxc_conf *);

/**
 * Delete a terminal created via lxc_terminal_create() or lxc_terminal_setup():
 * Note, registered handlers are not automatically deleted.
 */
__hidden extern void lxc_terminal_delete(struct lxc_terminal *);

/**
 * lxc_terminal_free: mark the terminal as unallocated and free any resources
 * allocated by lxc_terminal_allocate().
 *
 * @conf : the configuration of the container whose tty was closed
 * @fd   : the socket fd whose remote side was closed, which indicated
 *         the terminal is no longer in use. this is used to match
 *         which terminal is being freed.
 */
__hidden extern void lxc_terminal_free(struct lxc_conf *conf, int fd);

/**
 * Register terminal event handlers in an open mainloop.
 */
__hidden extern int lxc_terminal_mainloop_add(struct lxc_epoll_descr *, struct lxc_terminal *);

/**
 * Handle SIGWINCH events on the allocated terminals.
 */
__hidden extern void lxc_terminal_sigwinch(int sig);

/**
 * Connect to one of the ttys given to the container via lxc.tty.max.
 * - allocates either the current controlling terminal (default) or a user specified
 *   terminal as proxy terminal for the containers tty
 * - sets up SIGWINCH handler, winsz, and new terminal settings
 * - opens mainloop
 * - registers SIGWINCH, I/O handlers in the mainloop
 * - performs all necessary cleanup operations
 */
__hidden extern int lxc_console(struct lxc_container *c, int ttynum, int stdinfd, int stdoutfd,
				int stderrfd, int escape);

/**
 * Allocate one of the tty given to the container via lxc.tty.max. Returns an
 * open fd to the allocated tty.
 * Set ttynum to -1 to allocate the first available tty, or to a value within
 * the range specified by lxc.tty.max to allocate a specific tty.
 */
__hidden extern int lxc_terminal_getfd(struct lxc_container *c, int *ttynum, int *ptxfd);

/**
 * Make fd a duplicate of the standard file descriptors. The fd is made a
 * duplicate of a specific standard file descriptor iff the standard file
 * descriptor refers to a terminal.
 */
__hidden extern int lxc_terminal_set_stdfds(int fd);

/**
 * Handler for events on the stdin fd of the terminal. To be registered via the
 * corresponding functions declared and defined in mainloop.{c,h} or
 * lxc_terminal_mainloop_add().
 * This function exits the loop cleanly when an EPOLLHUP event is received.
 */
__hidden extern int lxc_terminal_stdin_cb(int fd, uint32_t events, void *cbdata,
					  struct lxc_epoll_descr *descr);

/**
 * Handler for events on the ptx fd of the terminal. To be registered via
 * the corresponding functions declared and defined in mainloop.{c,h} or
 * lxc_terminal_mainloop_add().
 * This function exits the loop cleanly when an EPOLLHUP event is received.
 */
__hidden extern int lxc_terminal_ptx_cb(int fd, uint32_t events, void *cbdata,
					struct lxc_epoll_descr *descr);

/**
 * Setup new terminal properties. The old terminal settings are stored in
 * oldtios.
 */
__hidden extern int lxc_setup_tios(int fd, struct termios *oldtios);

/**
 * lxc_terminal_winsz: propagate winsz from one terminal to another
 *
 * @srcfd
 * - terminal to get size from (typically a pty pty)
 * @dstfd
 * - terminal to set size on (typically a ptx pty)
 */
__hidden extern void lxc_terminal_winsz(int srcfd, int dstfd);

/*
 * lxc_terminal_signal_init: install signal handler
 *
 * @srcfd
 * - src for winsz in SIGWINCH handler
 * @dstfd
 * - dst for winsz in SIGWINCH handler
 *
 * Returns lxc_terminal_state structure on success or NULL on failure. The
 * sigfd member of the returned lxc_terminal_state can be
 * select()/poll()ed/epoll()ed on (i.e. added to a mainloop) for signals.
 *
 * Must be called with process_lock held to protect the lxc_ttys list, or from
 * a non-threaded context.
 *
 * Note that the signal handler isn't installed as a classic asynchronous
 * handler, rather signalfd(2) is used so that we can handle the signal when
 * we're ready for it. This avoids deadlocks since a signal handler (ie
 * lxc_terminal_sigwinch()) would need to take the thread mutex to prevent
 * lxc_ttys list corruption, but using the fd we can provide the tty_state
 * needed to the callback (lxc_terminal_signalfd_cb()).
 *
 * This function allocates memory. It is up to the caller to free it.
 */
__hidden extern struct lxc_terminal_state *lxc_terminal_signal_init(int srcfd, int dstfd);

/**
 * Handler for signal events. To be registered via the corresponding functions
 * declared and defined in mainloop.{c,h} or lxc_terminal_mainloop_add().
 */
__hidden extern int lxc_terminal_signalfd_cb(int fd, uint32_t events, void *cbdata,
					     struct lxc_epoll_descr *descr);

__hidden extern int lxc_terminal_write_ringbuffer(struct lxc_terminal *terminal);
__hidden extern int lxc_terminal_create_log_file(struct lxc_terminal *terminal);
__hidden extern int lxc_terminal_io_cb(int fd, uint32_t events, void *data,
				       struct lxc_epoll_descr *descr);

__hidden extern int lxc_make_controlling_terminal(int fd);
__hidden extern int lxc_terminal_prepare_login(int fd);
__hidden extern void lxc_terminal_conf_free(struct lxc_terminal *terminal);
__hidden extern void lxc_terminal_info_init(struct lxc_terminal_info *terminal);
__hidden extern void lxc_terminal_init(struct lxc_terminal *terminal);
__hidden extern int lxc_terminal_signal_sigmask_safe_blocked(struct lxc_terminal *terminal);

#endif /* __LXC_TERMINAL_H */
