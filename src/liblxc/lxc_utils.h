/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Daniel Lezcano <dlezcano at fr.ibm.com>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
#ifndef _utils_h
#define _utils_h

#define LXC_TTY_HANDLER(s) \
	static struct sigaction lxc_tty_sa_##s;				\
	static void tty_##s##_handler(int sig, siginfo_t *info, void *ctx) \
	{								\
		if (lxc_tty_sa_##s.sa_handler == SIG_DFL ||		\
		    lxc_tty_sa_##s.sa_handler == SIG_IGN)		\
			return;						\
		(*lxc_tty_sa_##s.sa_sigaction)(sig, info, ctx);	\
	}

#define LXC_TTY_ADD_HANDLER(s) \
	do { \
		struct sigaction sa; \
		sa.sa_sigaction = tty_##s##_handler; \
		sa.sa_flags = SA_SIGINFO; \
		sigfillset(&sa.sa_mask); \
		/* No error expected with sigaction. */ \
		sigaction(s, &sa, &lxc_tty_sa_##s); \
	} while (0)

#define LXC_TTY_DEL_HANDLER(s) \
	do { \
		sigaction(s, &lxc_tty_sa_##s, NULL); \
	} while (0)

#endif
