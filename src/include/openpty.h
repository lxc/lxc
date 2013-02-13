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
