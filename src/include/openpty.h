/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef _OPENPTY_H
#define _OPENPTY_H

#include <termios.h>
#include <sys/ioctl.h>

#include "../lxc/memory_utils.h"

/*
 * Create pseudo tty ptx pty pair with @__name and set terminal
 * attributes according to @__termp and @__winp and return handles for both
 * ends in @__aptx and @__apts.
 */
__hidden extern int openpty(int *ptx, int *pty, char *name,
			    const struct termios *termp,
			    const struct winsize *winp);

#endif
