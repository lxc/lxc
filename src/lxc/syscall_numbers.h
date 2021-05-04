/* SPDX-License-Identifier: LGPL-2.1+ */
#ifndef __LXC_SYSCALL_NUMBERS_H
#define __LXC_SYSCALL_NUMBERS_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <asm/unistd.h>
#include <errno.h>
#include <linux/keyctl.h>
#include <sched.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef HAVE_LINUX_MEMFD_H
#include <linux/memfd.h>
#endif

#ifdef HAVE_SYS_SIGNALFD_H
#include <sys/signalfd.h>
#endif

#ifndef __NR_keyctl
	#if defined __i386__
		#define __NR_keyctl 288
	#elif defined __x86_64__
		#define __NR_keyctl 250
	#elif defined __arm__
		#define __NR_keyctl 311
	#elif defined __aarch64__
		#define __NR_keyctl 311
	#elif defined __s390__
		#define __NR_keyctl 280
	#elif defined __powerpc__
		#define __NR_keyctl 271
	#elif defined __riscv
		#define __NR_keyctl 219
	#elif defined __sparc__
		#define __NR_keyctl 283
	#elif defined __ia64__
		#define __NR_keyctl (249 + 1024)
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32	/* o32 */
			#define __NR_keyctl 4282
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32	/* n32 */
			#define __NR_keyctl 6245
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64	/* n64 */
			#define __NR_keyctl 5241
		#endif
	#else
		#define -1
		#warning "__NR_keyctl not defined for your architecture"
	#endif
#endif

#ifndef __NR_memfd_create
	#if defined __i386__
		#define __NR_memfd_create 356
	#elif defined __x86_64__
		#define __NR_memfd_create 319
	#elif defined __arm__
		#define __NR_memfd_create 385
	#elif defined __aarch64__
		#define __NR_memfd_create 279
	#elif defined __s390__
		#define __NR_memfd_create 350
	#elif defined __powerpc__
		#define __NR_memfd_create 360
	#elif defined __riscv
		#define __NR_memfd_create 279
	#elif defined __sparc__
		#define __NR_memfd_create 348
	#elif defined __blackfin__
		#define __NR_memfd_create 390
	#elif defined __ia64__
		#define __NR_memfd_create 1340
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32
			#define __NR_memfd_create 4354
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32
			#define __NR_memfd_create 6318
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64
			#define __NR_memfd_create 5314
		#endif
	#else
		#define -1
		#warning "__NR_memfd_create not defined for your architecture"
	#endif
#endif

#ifndef __NR_pivot_root
	#if defined __i386__
		#define __NR_pivot_root 217
	#elif defined __x86_64__
		#define __NR_pivot_root	155
	#elif defined __arm__
		#define __NR_pivot_root 218
	#elif defined __aarch64__
		#define __NR_pivot_root 218
	#elif defined __s390__
		#define __NR_pivot_root 217
	#elif defined __powerpc__
		#define __NR_pivot_root 203
	#elif defined __riscv
		#define __NR_pivot_root 41
	#elif defined __sparc__
		#define __NR_pivot_root 146
	#elif defined __ia64__
		#define __NR_pivot_root (183 + 1024)
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32	/* o32 */
			#define __NR_pivot_root 4216
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32	/* n32 */
			#define __NR_pivot_root 6151
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64	/* n64 */
			#define __NR_pivot_root 5151
		#endif
	#else
		#define -1
		#warning "__NR_pivot_root not defined for your architecture"
	#endif
#endif

#ifndef __NR_setns
	#if defined __i386__
		#define __NR_setns 346
	#elif defined __x86_64__
		#define __NR_setns 308
	#elif defined __arm__
		#define __NR_setns 375
	#elif defined __aarch64__
		#define __NR_setns 375
	#elif defined __s390__
		#define __NR_setns 339
	#elif defined __powerpc__
		#define __NR_setns 350
	#elif defined __riscv
		#define __NR_setns 268
	#elif defined __sparc__
		#define __NR_setns 337
	#elif defined __ia64__
		#define __NR_setns (306 + 1024)
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32	/* o32 */
			#define __NR_setns 4344
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32	/* n32 */
			#define __NR_setns 6308
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64	/* n64 */
			#define __NR_setns 5303
		#endif
	#else
		#define -1
		#warning "__NR_setns not defined for your architecture"
	#endif
#endif

#ifndef __NR_sethostname
	#if defined __i386__
		#define __NR_sethostname 74
	#elif defined __x86_64__
		#define __NR_sethostname 170
	#elif defined __arm__
		#define __NR_sethostname 74
	#elif defined __aarch64__
		#define __NR_sethostname 74
	#elif defined __s390__
		#define __NR_sethostname 74
	#elif defined __powerpc__
		#define __NR_sethostname 74
	#elif defined __riscv
		#define __NR_sethostname 161
	#elif defined __sparc__
		#define __NR_sethostname 88
	#elif defined __ia64__
		#define __NR_sethostname (59 + 1024)
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32	/* o32 */
			#define __NR_sethostname 474
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32	/* n32 */
			#define __NR_sethostname 6165
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64	/* n64 */
			#define __NR_sethostname 5165
		#endif
	#else
		#define -1
		#warning "__NR_sethostname not defined for your architecture"
	#endif
#endif

#ifndef __NR_signalfd
	#if defined __i386__
		#define __NR_signalfd 321
	#elif defined __x86_64__
		#define __NR_signalfd 282
	#elif defined __arm__
		#define __NR_signalfd 349
	#elif defined __aarch64__
		#define __NR_signalfd 349
	#elif defined __s390__
		#define __NR_signalfd 316
	#elif defined __powerpc__
		#define __NR_signalfd 305
	#elif defined __riscv
		#define __NR_signalfd 74
	#elif defined __sparc__
		#define __NR_signalfd 311
	#elif defined __ia64__
		#define __NR_signalfd (283 + 1024)
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32	/* o32 */
			#define __NR_signalfd 4317
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32	/* n32 */
			#define __NR_signalfd 6280
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64	/* n64 */
			#define __NR_signalfd 5276
		#endif
	#endif
#endif

#ifndef __NR_signalfd4
	#if defined __i386__
		#define __NR_signalfd4 327
	#elif defined __x86_64__
		#define __NR_signalfd4 289
	#elif defined __arm__
		#define __NR_signalfd4 355
	#elif defined __aarch64__
		#define __NR_signalfd4 355
	#elif defined __s390__
		#define __NR_signalfd4 322
	#elif defined __powerpc__
		#define __NR_signalfd4 313
	#elif defined __riscv
		#define __NR_signalfd4 74
	#elif defined __sparc__
		#define __NR_signalfd4 317
	#elif defined __ia64__
		#define __NR_signalfd4 (289 + 1024)
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32	/* o32 */
			#define __NR_signalfd4 4324
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32	/* n32 */
			#define __NR_signalfd4 6287
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64	/* n64 */
			#define __NR_signalfd4 5283
		#endif
	#else
		#define -1
		#warning "__NR_signalfd4 not defined for your architecture"
	#endif
#endif

#ifndef __NR_unshare
	#if defined __i386__
		#define __NR_unshare 310
	#elif defined __x86_64__
		#define __NR_unshare 272
	#elif defined __arm__
		#define __NR_unshare 337
	#elif defined __aarch64__
		#define __NR_unshare 337
	#elif defined __s390__
		#define __NR_unshare 303
	#elif defined __powerpc__
		#define __NR_unshare 282
	#elif defined __riscv
		#define __NR_unshare 97
	#elif defined __sparc__
		#define __NR_unshare 299
	#elif defined __ia64__
		#define __NR_unshare (272 + 1024)
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32	/* o32 */
			#define __NR_unshare 4303
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32	/* n32 */
			#define __NR_unshare 6266
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64	/* n64 */
			#define __NR_unshare 5262
		#endif
	#else
		#define -1
		#warning "__NR_unshare not defined for your architecture"
	#endif
#endif

#ifndef __NR_bpf
	#if defined __i386__
		#define __NR_bpf 357
	#elif defined __x86_64__
		#define __NR_bpf 321
	#elif defined __arm__
		#define __NR_bpf 386
	#elif defined __aarch64__
		#define __NR_bpf 386
	#elif defined __s390__
		#define __NR_bpf 351
	#elif defined __powerpc__
		#define __NR_bpf 361
	#elif defined __riscv
		#define __NR_bpf 280
	#elif defined __sparc__
		#define __NR_bpf 349
	#elif defined __ia64__
		#define __NR_bpf (317 + 1024)
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32	/* o32 */
			#define __NR_bpf 4355
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32	/* n32 */
			#define __NR_bpf 6319
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64	/* n64 */
			#define __NR_bpf 5315
		#endif
	#else
		#define -1
		#warning "__NR_bpf not defined for your architecture"
	#endif
#endif

#ifndef __NR_faccessat
	#if defined __i386__
		#define __NR_faccessat 307
	#elif defined __x86_64__
		#define __NR_faccessat 269
	#elif defined __arm__
		#define __NR_faccessat 334
	#elif defined __aarch64__
		#define __NR_faccessat 334
	#elif defined __s390__
		#define __NR_faccessat 300
	#elif defined __powerpc__
		#define __NR_faccessat 298
	#elif defined __riscv
		#define __NR_faccessat 48
	#elif defined __sparc__
		#define __NR_faccessat 296
	#elif defined __ia64__
		#define __NR_faccessat (269 + 1024)
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32	/* o32 */
			#define __NR_faccessat 4300
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32	/* n32 */
			#define __NR_faccessat 6263
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64	/* n64 */
			#define __NR_faccessat 5259
		#endif
	#else
		#define -1
		#warning "__NR_faccessat not defined for your architecture"
	#endif
#endif

#ifndef __NR_pidfd_send_signal
	#if defined __alpha__
		#define __NR_pidfd_send_signal 534
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32	/* o32 */
			#define __NR_pidfd_send_signal 4424
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32	/* n32 */
			#define __NR_pidfd_send_signal 6424
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64	/* n64 */
			#define __NR_pidfd_send_signal 5424
		#endif
	#elif defined __ia64__
		#define __NR_pidfd_send_signal (424 + 1024)
	#else
		#define __NR_pidfd_send_signal 424
	#endif
#endif

#ifndef __NR_seccomp
	#if defined __i386__
		#define __NR_seccomp 354
	#elif defined __x86_64__
		#define __NR_seccomp 317
	#elif defined __arm__
		#define __NR_seccomp 383
	#elif defined __aarch64__
		#define __NR_seccomp 383
	#elif defined __s390__
		#define __NR_seccomp 348
	#elif defined __powerpc__
		#define __NR_seccomp 358
	#elif defined __riscv
		#define __NR_seccomp 277
	#elif defined __sparc__
		#define __NR_seccomp 346
	#elif defined __ia64__
		#define __NR_seccomp (329 + 1024)
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32	/* o32 */
			#define __NR_seccomp 4352
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32	/* n32 */
			#define __NR_seccomp 6316
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64	/* n64 */
			#define __NR_seccomp 5312
		#endif
	#else
		#define -1
		#warning "__NR_seccomp not defined for your architecture"
	#endif
#endif

#ifndef __NR_gettid
	#if defined __i386__
		#define __NR_gettid 224
	#elif defined __x86_64__
		#define __NR_gettid 186
	#elif defined __arm__
		#define __NR_gettid 224
	#elif defined __aarch64__
		#define __NR_gettid 224
	#elif defined __s390__
		#define __NR_gettid 236
	#elif defined __powerpc__
		#define __NR_gettid 207
	#elif defined __riscv
		#define __NR_gettid 178
	#elif defined __sparc__
		#define __NR_gettid 143
	#elif defined __ia64__
		#define __NR_gettid (81 + 1024)
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32	/* o32 */
			#define __NR_gettid 4222
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32	/* n32 */
			#define __NR_gettid 6178
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64	/* n64 */
			#define __NR_gettid 5178
		#endif
	#else
		#define -1
		#warning "__NR_gettid not defined for your architecture"
	#endif
#endif

#ifndef __NR_execveat
	#if defined __i386__
		#define __NR_execveat 358
	#elif defined __x86_64__
		#ifdef __ILP32__	/* x32 */
			#define __NR_execveat 545
		#else
			#define __NR_execveat 322
		#endif
	#elif defined __arm__
		#define __NR_execveat 387
	#elif defined __aarch64__
		#define __NR_execveat 387
	#elif defined __s390__
		#define __NR_execveat 354
	#elif defined __powerpc__
		#define __NR_execveat 362
	#elif defined __riscv
		#define __NR_execveat 281
	#elif defined __sparc__
		#define __NR_execveat 350
	#elif defined __ia64__
		#define __NR_execveat (318 + 1024)
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32	/* o32 */
			#define __NR_execveat 4356
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32	/* n32 */
			#define __NR_execveat 6320
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64	/* n64 */
			#define __NR_execveat 5316
		#endif
	#else
		#define -1
		#warning "__NR_execveat not defined for your architecture"
	#endif
#endif

#ifndef __NR_move_mount
	#if defined __alpha__
		#define __NR_move_mount 539
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32	/* o32 */
			#define __NR_move_mount 4429
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32	/* n32 */
			#define __NR_move_mount 6429
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64	/* n64 */
			#define __NR_move_mount 5429
		#endif
	#elif defined __ia64__
		#define __NR_move_mount (428 + 1024)
	#else
		#define __NR_move_mount 429
	#endif
#endif

#ifndef __NR_open_tree
	#if defined __alpha__
		#define __NR_open_tree 538
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32	/* o32 */
			#define __NR_open_tree 4428
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32	/* n32 */
			#define __NR_open_tree 6428
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64	/* n64 */
			#define __NR_open_tree 5428
		#endif
	#elif defined __ia64__
		#define __NR_open_tree (428 + 1024)
	#else
		#define __NR_open_tree 428
	#endif
#endif

#ifndef __NR_clone3
	#if defined __alpha__
		#define __NR_clone3 545
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32	/* o32 */
			#define __NR_clone3 4435
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32	/* n32 */
			#define __NR_clone3 6435
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64	/* n64 */
			#define __NR_clone3 5435
		#endif
	#elif defined __ia64__
		#define __NR_clone3 (435 + 1024)
	#else
		#define __NR_clone3 435
	#endif
#endif

#ifndef __NR_fsopen
	#if defined __alpha__
		#define __NR_fsopen 540
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32	/* o32 */
			#define __NR_fsopen 4430
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32	/* n32 */
			#define __NR_fsopen 6430
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64	/* n64 */
			#define __NR_fsopen 5430
		#endif
	#elif defined __ia64__
		#define __NR_fsopen (430 + 1024)
	#else
		#define __NR_fsopen 430
	#endif
#endif

#ifndef __NR_fspick
	#if defined __alpha__
		#define __NR_fspick 543
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32	/* o32 */
			#define __NR_fspick 4433
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32	/* n32 */
			#define __NR_fspick 6433
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64	/* n64 */
			#define __NR_fspick 5433
		#endif
	#elif defined __ia64__
		#define __NR_fspick (433 + 1024)
	#else
		#define __NR_fspick 433
	#endif
#endif

#ifndef __NR_fsconfig
	#if defined __alpha__
		#define __NR_fsconfig 541
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32	/* o32 */
			#define __NR_fsconfig 4431
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32	/* n32 */
			#define __NR_fsconfig 6431
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64	/* n64 */
			#define __NR_fsconfig 5431
		#endif
	#elif defined __ia64__
		#define __NR_fsconfig (431 + 1024)
	#else
		#define __NR_fsconfig 431
	#endif
#endif

#ifndef __NR_fsmount
	#if defined __alpha__
		#define __NR_fsmount 542
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32	/* o32 */
			#define __NR_fsmount 4432
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32	/* n32 */
			#define __NR_fsmount 6432
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64	/* n64 */
			#define __NR_fsmount 5432
		#endif
	#elif defined __ia64__
		#define __NR_fsmount (432 + 1024)
	#else
		#define __NR_fsmount 432
	#endif
#endif

#ifndef __NR_openat2
	#if defined __alpha__
		#define __NR_openat2 547
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32	/* o32 */
			#define __NR_openat2 4437
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32	/* n32 */
			#define __NR_openat2 6437
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64	/* n64 */
			#define __NR_openat2 5437
		#endif
	#elif defined __ia64__
		#define __NR_openat2 (437 + 1024)
	#else
		#define __NR_openat2 437
	#endif
#endif

#ifndef __NR_close_range
	#if defined __alpha__
		#define __NR_close_range 546
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32	/* o32 */
			#define __NR_close_range (436 + 4000)
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32	/* n32 */
			#define __NR_close_range (436 + 6000)
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64	/* n64 */
			#define __NR_close_range (436 + 5000)
		#endif
	#elif defined __ia64__
		#define __NR_close_range (436 + 1024)
	#else
		#define __NR_close_range 436
	#endif
#endif

#ifndef __NR_mount_setattr
	#if defined __alpha__
		#define __NR_mount_setattr 552
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32	/* o32 */
			#define __NR_mount_setattr (442 + 4000)
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32	/* n32 */
			#define __NR_mount_setattr (442 + 6000)
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64	/* n64 */
			#define __NR_mount_setattr (442 + 5000)
		#endif
	#elif defined __ia64__
		#define __NR_mount_setattr (442 + 1024)
	#else
		#define __NR_mount_setattr 442
	#endif
#endif

#ifndef __NR_personality
	#if defined __alpha__
		#define __NR_personality 324
	#elif defined __m68k__
		#define __NR_personality 136
	#elif defined __i386__
		#define __NR_personality 136
	#elif defined __x86_64__
		#define __NR_personality 135
	#elif defined __arm__
		#define __NR_personality 136
	#elif defined __aarch64__
		#define __NR_personality 92
	#elif defined __s390__
		#define __NR_personality 136
	#elif defined __powerpc__
		#define __NR_personality 136
	#elif defined __riscv
		#define __NR_personality -1
	#elif defined __sparc__
		#define __NR_personality 191
	#elif defined __ia64__
		#define __NR_personality (116 + 1024)
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32	/* o32 */
			#define __NR_personality (136 + 4000)
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32	/* n32 */
			#define __NR_personality (132 + 6000)
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64	/* n64 */
			#define __NR_personality (132 + 5000)
		#endif
	#else
		#define -1
		#warning "__NR_personality not defined for your architecture"
	#endif
#endif

#endif /* __LXC_SYSCALL_NUMBERS_H */
