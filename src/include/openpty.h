/*
 * openpty: glibc implementation
 *
 * Copyright (C) 1998, 1999, 2004 Free Software Foundation, Inc.
 *
 * Authors:
 * Zack Weinberg <zack@rabi.phys.columbia.edu>, 1998.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.

 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.

 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _openpty_h
#define _openpty_h

#include <termios.h>
#include <sys/ioctl.h>

/* Create pseudo tty master slave pair with NAME and set terminal
   attributes according to TERMP and WINP and return handles for both
   ends in AMASTER and ASLAVE.  */
extern int openpty (int *__amaster, int *__aslave, char *__name,
		    const struct termios *__termp,
		    const struct winsize *__winp);

#endif
