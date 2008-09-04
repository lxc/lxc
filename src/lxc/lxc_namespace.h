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
#ifndef __namespace_h
#define __namespace_h

#include <syscall.h>
#ifndef CLONE_FS
#  define CLONE_FS                0x00000200
#endif
#ifndef CLONE_NEWNS
#  define CLONE_NEWNS             0x00020000
#endif
#ifndef CLONE_NEWUTS
#  define CLONE_NEWUTS            0x04000000
#endif
#ifndef CLONE_NEWIPC
#  define CLONE_NEWIPC            0x08000000
#endif
#ifndef CLONE_NEWUSER
#  define CLONE_NEWUSER           0x10000000
#endif
#ifndef CLONE_NEWPID
#  define CLONE_NEWPID            0x20000000
#endif
#ifndef CLONE_NEWNET
#  define CLONE_NEWNET            0x40000000
#endif
#ifndef __NR_unshare
#  ifdef __i386__
#    define __NR_unshare 310
#  elif __x86_64__
#    define __NR_unshare 272
#  elif __ia64__
#    define __NR_unshare 1296
#  elif __s390__
#    define __NR_unshare 303
#  elif __powerpc__
#    define __NR_unshare 282
#else
#    error "unsupported architecture"
#  endif
#endif
#if __i386__ || __x86_64__ || __s390__ || __powerpc__
#   define fork_ns(flags) syscall(SYS_clone, flags|SIGCHLD, NULL);
#elif __ia64__
#   define fork_ns(flags) syscall(SYS_clone2, flags|SIGCHLD, NULL);
#else
#   error "unsupported architecture"
#endif
#define unshare_ns(flags) syscall(__NR_unshare, flags, NULL);
#endif
