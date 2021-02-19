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

#include "include/bpf.h"
#include "include/bpf_common.h"

#ifndef HAVE_BPF
static inline int bpf_lxc(int cmd, union bpf_attr *attr, size_t size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}
#define bpf bpf_lxc
#endif /* HAVE_BPF */

struct bpf_program {
	int device_list_type;
	int kernel_fd;
	__u32 prog_type;

	size_t n_instructions;
	struct bpf_insn *instructions;

	int fd_cgroup;
	int attached_type;
	__u32 attached_flags;
};

__hidden extern struct bpf_program *bpf_program_new(__u32 prog_type);
__hidden extern int bpf_program_init(struct bpf_program *prog);
__hidden extern int bpf_program_append_device(struct bpf_program *prog, struct device_item *device);
__hidden extern int bpf_program_finalize(struct bpf_program *prog);
__hidden extern int bpf_program_cgroup_detach(struct bpf_program *prog);
__hidden extern void bpf_device_program_free(struct cgroup_ops *ops);
__hidden extern bool bpf_devices_cgroup_supported(void);

/*
 * Note that bpf_list_add_device() returns 1 if it altered the device list and
 * 0 if it didn't; both return values indicate success. Only a negative return
 * value indicates an error.
 */
__hidden extern int bpf_list_add_device(struct bpf_devices *bpf_devices,
					struct device_item *device);
__hidden extern bool bpf_cgroup_devices_attach(struct cgroup_ops *ops,
					       struct bpf_devices *bpf_devices);
__hidden extern bool bpf_cgroup_devices_update(struct cgroup_ops *ops,
					       struct bpf_devices *bpf_devices,
					       struct device_item *device);

static inline void bpf_program_free(struct bpf_program *prog)
{
	if (prog) {
		(void)bpf_program_cgroup_detach(prog);
		free(prog->instructions);
		free(prog);
	}
}
define_cleanup_function(struct bpf_program *, bpf_program_free);
#define __do_bpf_program_free call_cleaner(bpf_program_free)

#endif /* __LXC_CGROUP2_DEVICES_H */
