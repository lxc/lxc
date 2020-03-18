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
#include "syscall_numbers.h"

#ifdef HAVE_STRUCT_BPF_CGROUP_DEV_CTX
#include <linux/bpf.h>
#include <linux/filter.h>
#endif

#ifndef HAVE_BPF

union bpf_attr;

static inline int missing_bpf(int cmd, union bpf_attr *attr, size_t size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}

#define bpf missing_bpf
#endif /* HAVE_BPF */

struct bpf_program {
	int device_list_type;
	int kernel_fd;
	uint32_t prog_type;

	size_t n_instructions;
#ifdef HAVE_STRUCT_BPF_CGROUP_DEV_CTX
	struct bpf_insn *instructions;
#endif /* HAVE_STRUCT_BPF_CGROUP_DEV_CTX */

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
#else /* !HAVE_STRUCT_BPF_CGROUP_DEV_CTX */
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
#endif /* !HAVE_STRUCT_BPF_CGROUP_DEV_CTX */

#define __do_bpf_program_free \
	__attribute__((__cleanup__(__auto_bpf_program_free__)))

#endif /* __LXC_CGROUP2_DEVICES_H */
