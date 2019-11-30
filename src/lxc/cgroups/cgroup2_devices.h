/* SPDX-License-Identifier: LGPL-2.1+ */

/* Parts of this taken from systemd's implementation. */

#ifndef __LXC_CGROUP2_DEVICES_H
#define __LXC_CGROUP2_DEVICES_H

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "conf.h"
#include "config.h"

#ifdef HAVE_STRUCT_BPF_CGROUP_DEV_CTX
#include <linux/bpf.h>
#include <linux/filter.h>
#endif

#if !HAVE_BPF
#if !(defined __NR_bpf && __NR_bpf > 0)
#if defined __NR_bpf
#undef __NR_bpf
#endif
#if defined __i386__
#define __NR_bpf 357
#elif defined __x86_64__
#define __NR_bpf 321
#elif defined __aarch64__
#define __NR_bpf 280
#elif defined __arm__
#define __NR_bpf 386
#elif defined __sparc__
#define __NR_bpf 349
#elif defined __s390__
#define __NR_bpf 351
#elif defined __tilegx__
#define __NR_bpf 280
#else
#warning "__NR_bpf not defined for your architecture"
#endif
#endif

union bpf_attr;

static inline int missing_bpf(int cmd, union bpf_attr *attr, size_t size)
{
#ifdef __NR_bpf
	return (int)syscall(__NR_bpf, cmd, attr, size);
#else
	errno = ENOSYS;
	return -1;
#endif
}

#define bpf missing_bpf
#endif

struct bpf_program {
	bool blacklist;
	int kernel_fd;
	uint32_t prog_type;

	size_t n_instructions;
#ifdef HAVE_STRUCT_BPF_CGROUP_DEV_CTX
	struct bpf_insn *instructions;
#endif

	char *attached_path;
	int attached_type;
	uint32_t attached_flags;
};

#ifdef HAVE_STRUCT_BPF_CGROUP_DEV_CTX
struct bpf_program *bpf_program_new(uint32_t prog_type);
int bpf_program_init(struct bpf_program *prog);
int bpf_program_append_device(struct bpf_program *prog,
			      struct device_item *device);
int bpf_program_finalize(struct bpf_program *prog);
int bpf_program_cgroup_attach(struct bpf_program *prog, int type,
			      const char *path, uint32_t flags);
int bpf_program_cgroup_detach(struct bpf_program *prog);
void bpf_program_free(struct bpf_program *prog);
void lxc_clear_cgroup2_devices(struct lxc_conf *conf);
bool bpf_devices_cgroup_supported(void);
static inline void __auto_bpf_program_free__(struct bpf_program **prog)
{
	if (*prog) {
		bpf_program_free(*prog);
		*prog = NULL;
	}
}
int bpf_list_add_device(struct lxc_conf *conf, struct device_item *device);
#else
static inline struct bpf_program *bpf_program_new(uint32_t prog_type)
{
	errno = ENOSYS;
	return NULL;
}

static inline int bpf_program_init(struct bpf_program *prog)
{
	errno = ENOSYS;
	return -1;
}

static inline int bpf_program_append_device(struct bpf_program *prog, char type,
					    int major, int minor,
					    const char *access, int allow)
{
	errno = ENOSYS;
	return -1;
}

static inline int bpf_program_finalize(struct bpf_program *prog)
{
	errno = ENOSYS;
	return -1;
}

static inline int bpf_program_cgroup_attach(struct bpf_program *prog, int type,
					    const char *path, uint32_t flags)
{
	errno = ENOSYS;
	return -1;
}

static inline int bpf_program_cgroup_detach(struct bpf_program *prog)
{
	errno = ENOSYS;
	return -1;
}

static inline void bpf_program_free(struct bpf_program *prog)
{
}

static inline void lxc_clear_cgroup2_devices(struct lxc_conf *conf)
{
}

static inline bool bpf_devices_cgroup_supported(void)
{
	return false;
}

static inline void __auto_bpf_program_free__(struct bpf_program **prog)
{
}

static inline int bpf_list_add_device(struct lxc_conf *conf,
				      struct device_item *device)
{
	errno = ENOSYS;
	return -1;
}
#endif

#define __do_bpf_program_free \
	__attribute__((__cleanup__(__auto_bpf_program_free__)))

#endif /* __LXC_CGROUP2_DEVICES_H */
