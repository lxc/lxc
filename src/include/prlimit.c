/*
 * Copyright (C) 2008 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <unistd.h>
#include <linux/types.h> /* __le64, __l32 ... */
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/vfs.h>

#if defined(__LP64__)
#error This code is only needed on 32-bit systems!
#endif

#define RLIM64_INFINITY (~0ULL)

typedef uint64_t u64;

// There is no prlimit system call, so we need to use prlimit64.
int prlimit(pid_t pid, int resource, const struct rlimit *n32, struct rlimit *o32)
{
	struct rlimit64 n64;
	if (n32 != NULL) {
		n64.rlim_cur = (n32->rlim_cur == RLIM_INFINITY)
				   ? RLIM64_INFINITY
				   : n32->rlim_cur;
		n64.rlim_max = (n32->rlim_max == RLIM_INFINITY)
				   ? RLIM64_INFINITY
				   : n32->rlim_max;
	}

	struct rlimit64 o64;
	int result = prlimit64(
	    pid, resource, (n32 != NULL) ? (const struct rlimit64 *)&n64 : NULL,
	    (o32 != NULL) ? &o64 : NULL);

	if (result != -1 && o32 != NULL) {
		o32->rlim_cur = (o64.rlim_cur == RLIM64_INFINITY)
				    ? RLIM_INFINITY
				    : o64.rlim_cur;
		o32->rlim_max = (o64.rlim_max == RLIM64_INFINITY)
				    ? RLIM_INFINITY
				    : o64.rlim_max;
	}

	return result;
}
