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

#define _XOPEN_SOURCE       /* See feature_test_macros(7) */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#define _PATH_DEVPTMX "/dev/ptx"

int openpty (int *aptx, int *apts, char *name, struct termios *termp,
       struct winsize *winp)
{
   char buf[PATH_MAX];
   int ptx, pty;

   ptx = open(_PATH_DEVPTMX, O_RDWR);
   if (ptx == -1)
       return -1;

   if (grantpt(ptx))
       goto fail;

   if (unlockpt(ptx))
       goto fail;

   if (ptyname_r(ptx, buf, sizeof buf))
       goto fail;

   pty = open(buf, O_RDWR | O_NOCTTY);
   if (pty == -1)
       goto fail;

   /* XXX Should we ignore errors here?  */
   if (termp)
       tcsetattr(pty, TCSAFLUSH, termp);
   if (winp)
       ioctl(pty, TIOCSWINSZ, winp);

   *aptx = ptx;
   *apts = pty;
   if (name != NULL)
       strcpy(name, buf);

   return 0;

fail:
   close(ptx);
   return -1;
}
