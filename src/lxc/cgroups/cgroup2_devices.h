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

#include "cgroup.h"
#include "compiler.h"
#include "conf.h"
#include "config.h"
#include "list.h"
#include "macro.h"
#include "memory_utils.h"
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

	int fd_cgroup;
	int attached_type;
	uint32_t attached_flags;
};

static inline bool bpf_device_block_all(const struct bpf_program *prog)
{
	/* LXC_BPF_DEVICE_CGROUP_ALLOWLIST  -> allowlist (deny all) */
	return prog->device_list_type == LXC_BPF_DEVICE_CGROUP_ALLOWLIST;
}

static inline bool bpf_device_add(const struct bpf_program *prog,
				  struct device_item *device)
{
#ifdef HAVE_STRUCT_BPF_CGROUP_DEV_CTX
	if (device->global_rule > LXC_BPF_DEVICE_CGROUP_LOCAL_RULE)
		return false;

	/* We're blocking all devices so skip individual deny rules. */
	if (bpf_device_block_all(prog) && !device->allow)
		return false;

	/* We're allowing all devices so skip individual allow rules. */
	if (!bpf_device_block_all(prog) && device->allow)
		return false;
#endif
	return true;
}

static inline void bpf_device_set_type(struct bpf_program *prog,
				       struct lxc_list *devices)
{
#ifdef HAVE_STRUCT_BPF_CGROUP_DEV_CTX
	struct lxc_list *it;

	lxc_list_for_each (it, devices) {
		struct device_item *cur = it->elem;

		if (cur->global_rule > LXC_BPF_DEVICE_CGROUP_LOCAL_RULE)
			prog->device_list_type = cur->global_rule;
	}
#endif
}

#ifdef HAVE_STRUCT_BPF_CGROUP_DEV_CTX
__hidden extern struct bpf_program *bpf_program_new(uint32_t prog_type);
__hidden extern int bpf_program_init(struct bpf_program *prog);
__hidden extern int bpf_program_append_device(struct bpf_program *prog, struct device_item *device);
__hidden extern int bpf_program_finalize(struct bpf_program *prog);
__hidden extern int bpf_program_cgroup_attach(struct bpf_program *prog, int type,
					      int fd_cgroup, int replace_bpf_fd,
					      uint32_t flags);
__hidden extern int bpf_program_cgroup_detach(struct bpf_program *prog);
__hidden extern void bpf_program_free(struct bpf_program *prog);
__hidden extern void bpf_device_program_free(struct cgroup_ops *ops);
__hidden extern bool bpf_devices_cgroup_supported(void);

__hidden extern int bpf_list_add_device(struct lxc_conf *conf, struct device_item *device);

#else /* !HAVE_STRUCT_BPF_CGROUP_DEV_CTX */

static inline struct bpf_program *bpf_program_new(uint32_t prog_type)
{
	return ret_set_errno(NULL, ENOSYS);
}

static inline int bpf_program_init(struct bpf_program *prog)
{
	return ret_errno(ENOSYS);
}

static inline int bpf_program_append_device(struct bpf_program *prog, char type,
					    int major, int minor,
					    const char *access, int allow)
{
	return ret_errno(ENOSYS);
}

static inline int bpf_program_finalize(struct bpf_program *prog)
{
	return ret_errno(ENOSYS);
}

static inline int bpf_program_cgroup_attach(struct bpf_program *prog, int type,
					    int fd_cgroup, int replace_bpf_fd,
					    uint32_t flags)
{
	return ret_errno(ENOSYS);
}

static inline int bpf_program_cgroup_detach(struct bpf_program *prog)
{
	return ret_errno(ENOSYS);
}

static inline void bpf_program_free(struct bpf_program *prog)
{
}

static inline void bpf_device_program_free(struct cgroup_ops *ops)
{
}

static inline bool bpf_devices_cgroup_supported(void)
{
	return ret_set_errno(false, ENOSYS);
}

static inline int bpf_list_add_device(struct lxc_conf *conf,
				      struct device_item *device)
{
	return ret_errno(ENOSYS);
}
#endif /* !HAVE_STRUCT_BPF_CGROUP_DEV_CTX */

define_cleanup_function(struct bpf_program *, bpf_program_free);
#define __do_bpf_program_free call_cleaner(bpf_program_free)

#endif /* __LXC_CGROUP2_DEVICES_H */
