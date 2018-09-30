#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "config.h"

int lxc_raw_execveat(int dirfd, const char *pathname, char *const argv[],
		     char *const envp[], int flags)
{
#ifdef __NR_execveat
	syscall(__NR_execveat, dirfd, pathname, argv, envp, flags);
#else
	errno = ENOSYS;
	return -1;
#endif
}
