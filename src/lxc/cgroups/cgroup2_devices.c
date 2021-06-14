/* SPDX-License-Identifier: LGPL-2.1+ */

/* Parts of this taken from systemd's implementation. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "cgroup2_devices.h"
#include "config.h"
#include "file_utils.h"
#include "log.h"
#include "macro.h"
#include "memory_utils.h"

lxc_log_define(cgroup2_devices, cgroup);

#define BPF_LOG_BUF_SIZE (1 << 23) /* 8MB */
#ifndef BPF_LOG_LEVEL1
#define BPF_LOG_LEVEL1 1
#endif

#ifndef BPF_LOG_LEVEL2
#define BPF_LOG_LEVEL2 2
#endif

#ifndef BPF_LOG_LEVEL
#define BPF_LOG_LEVEL (BPF_LOG_LEVEL1 | BPF_LOG_LEVEL2)
#endif

static int bpf_program_add_instructions(struct bpf_program *prog,
					const struct bpf_insn *instructions,
					size_t count)
{

	struct bpf_insn *new_insn;

	if (prog->kernel_fd >= 0)
		return log_error_errno(-1, EBUSY, "Refusing to update bpf cgroup program that's already loaded");

	new_insn = realloc(prog->instructions, sizeof(struct bpf_insn) * (count + prog->n_instructions));
	if (!new_insn)
		return log_error_errno(-1, ENOMEM, "Failed to reallocate bpf cgroup program");
	prog->instructions = new_insn;
	memset(prog->instructions + prog->n_instructions, 0,
	       sizeof(struct bpf_insn) * count);
	memcpy(prog->instructions + prog->n_instructions, instructions,
	       sizeof(struct bpf_insn) * count);
	prog->n_instructions += count;

	return 0;
}

/* Memory load, dst_reg = *(uint *) (src_reg + off16) */
#define BPF_LDX_MEM(SIZE, DST, SRC, OFF)                               \
	((struct bpf_insn){.code = BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM, \
			   .dst_reg = DST,                             \
			   .src_reg = SRC,                             \
			   .off = OFF,                                 \
			   .imm = 0})

/* ALU ops on immediates, bpf_add|sub|...: dst_reg += imm32 */
#define BPF_ALU32_IMM(OP, DST, IMM)                              \
	((struct bpf_insn){.code = BPF_ALU | BPF_OP(OP) | BPF_K, \
			   .dst_reg = DST,                       \
			   .src_reg = 0,                         \
			   .off = 0,                             \
			   .imm = IMM})

/* Short form of mov, dst_reg = src_reg */
#define BPF_MOV64_IMM(DST, IMM)                                 \
	((struct bpf_insn){.code = BPF_ALU64 | BPF_MOV | BPF_K, \
			   .dst_reg = DST,                      \
			   .src_reg = 0,                        \
			   .off = 0,                            \
			   .imm = IMM})

#define BPF_MOV32_REG(DST, SRC)                               \
	((struct bpf_insn){.code = BPF_ALU | BPF_MOV | BPF_X, \
			   .dst_reg = DST,                    \
			   .src_reg = SRC,                    \
			   .off = 0,                          \
			   .imm = 0})

/* Conditional jumps against registers, if (dst_reg 'op' src_reg) goto pc + off16 */
#define BPF_JMP_REG(OP, DST, SRC, OFF)                           \
	((struct bpf_insn){.code = BPF_JMP | BPF_OP(OP) | BPF_X, \
			   .dst_reg = DST,                       \
			   .src_reg = SRC,                       \
			   .off = OFF,                           \
			   .imm = 0})

/* Conditional jumps against immediates, if (dst_reg 'op' imm32) goto pc + off16 */
#define BPF_JMP_IMM(OP, DST, IMM, OFF)                           \
	((struct bpf_insn){.code = BPF_JMP | BPF_OP(OP) | BPF_K, \
			   .dst_reg = DST,                       \
			   .src_reg = 0,                         \
			   .off = OFF,                           \
			   .imm = IMM})

/* Program exit */
#define BPF_EXIT_INSN()                                \
	((struct bpf_insn){.code = BPF_JMP | BPF_EXIT, \
			   .dst_reg = 0,               \
			   .src_reg = 0,               \
			   .off = 0,                   \
			   .imm = 0})

static int bpf_access_mask(const char *acc, __u32 *mask)
{
	if (!acc)
		return 0;

	for (; *acc; acc++) {
		switch (*acc) {
		case 'r':
			*mask |= BPF_DEVCG_ACC_READ;
			break;
		case 'w':
			*mask |= BPF_DEVCG_ACC_WRITE;
			break;
		case 'm':
			*mask |= BPF_DEVCG_ACC_MKNOD;
			break;
		default:
			return -EINVAL;
		}
	}

	return 0;
}

static int bpf_device_type(char type)
{
	switch (type) {
	case 'a':
		return 0;
	case 'b':
		return BPF_DEVCG_DEV_BLOCK;
	case 'c':
		return BPF_DEVCG_DEV_CHAR;
	}

	return -1;
}

static inline bool bpf_device_all_access(__u32 access_mask)
{
	return access_mask == (BPF_DEVCG_ACC_READ | BPF_DEVCG_ACC_WRITE | BPF_DEVCG_ACC_MKNOD);
}

struct bpf_program *bpf_program_new(uint32_t prog_type)
{
	__do_free struct bpf_program *prog = NULL;

	prog = zalloc(sizeof(struct bpf_program));
	if (!prog)
		return ret_set_errno(NULL, ENOMEM);

	prog->prog_type = prog_type;
	prog->kernel_fd = -EBADF;
	prog->fd_cgroup = -EBADF;
	/*
	 * By default a allowlist is used unless the user tells us otherwise.
	 */
	prog->device_list_type = LXC_BPF_DEVICE_CGROUP_ALLOWLIST;

	return move_ptr(prog);
}

int bpf_program_init(struct bpf_program *prog)
{
	const struct bpf_insn pre_insn[] = {
		/* load device type to r2 */
		BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1, offsetof(struct bpf_cgroup_dev_ctx, access_type)),
		BPF_ALU32_IMM(BPF_AND, BPF_REG_2, 0xFFFF),

		/* load access type to r3 */
		BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1, offsetof(struct bpf_cgroup_dev_ctx, access_type)),
		BPF_ALU32_IMM(BPF_RSH, BPF_REG_3, 16),

		/* load major number to r4 */
		BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_1, offsetof(struct bpf_cgroup_dev_ctx, major)),

		/* load minor number to r5 */
		BPF_LDX_MEM(BPF_W, BPF_REG_5, BPF_REG_1, offsetof(struct bpf_cgroup_dev_ctx, minor)),
	};

	if (!prog)
		return ret_set_errno(-1, EINVAL);

	return bpf_program_add_instructions(prog, pre_insn, ARRAY_SIZE(pre_insn));
}

int bpf_program_append_device(struct bpf_program *prog, struct device_item *device)
{
	int jump_nr = 1;
	__u32 access_mask = 0;
	int device_type, ret;
	struct bpf_insn bpf_access_decision[2];

	if (!prog || !device)
		return ret_set_errno(-1, EINVAL);

	ret = bpf_access_mask(device->access, &access_mask);
	if (ret < 0)
		return log_error_errno(ret, -ret, "Invalid access mask specified %s", device->access);

	if (!bpf_device_all_access(access_mask))
		jump_nr++;

	device_type = bpf_device_type(device->type);
	if (device_type < 0)
		return log_error_errno(-1, EINVAL, "Invalid bpf cgroup device type %c", device->type);

	if (device_type > 0)
		jump_nr++;

	if (device->major >= 0)
		jump_nr++;

	if (device->minor >= 0)
		jump_nr++;

	if (!bpf_device_all_access(access_mask)) {
		struct bpf_insn ins[] = {
			BPF_MOV32_REG(BPF_REG_1, BPF_REG_3),
			BPF_ALU32_IMM(BPF_AND, BPF_REG_1, access_mask),
			BPF_JMP_REG(BPF_JNE, BPF_REG_1, BPF_REG_3, jump_nr--),
		};

		ret = bpf_program_add_instructions(prog, ins, ARRAY_SIZE(ins));
		if (ret)
			return log_error_errno(-1, errno, "Failed to add instructions to bpf cgroup program");
	}

	if (device_type > 0) {
		struct bpf_insn ins[] = {
			BPF_JMP_IMM(BPF_JNE, BPF_REG_2, device_type, jump_nr--),
		};

		ret = bpf_program_add_instructions(prog, ins, ARRAY_SIZE(ins));
		if (ret)
			return log_error_errno(-1, errno, "Failed to add instructions to bpf cgroup program");
	}

	if (device->major >= 0) {
		struct bpf_insn ins[] = {
			BPF_JMP_IMM(BPF_JNE, BPF_REG_4, device->major, jump_nr--),
		};

		ret = bpf_program_add_instructions(prog, ins, ARRAY_SIZE(ins));
		if (ret)
			return log_error_errno(-1, errno, "Failed to add instructions to bpf cgroup program");
	}

	if (device->minor >= 0) {
		struct bpf_insn ins[] = {
			BPF_JMP_IMM(BPF_JNE, BPF_REG_5, device->minor, jump_nr--),
		};

		ret = bpf_program_add_instructions(prog, ins, ARRAY_SIZE(ins));
		if (ret)
			return log_error_errno(-1, errno, "Failed to add instructions to bpf cgroup program");
	}

	bpf_access_decision[0] = BPF_MOV64_IMM(BPF_REG_0, device->allow);
	bpf_access_decision[1] = BPF_EXIT_INSN();
	ret = bpf_program_add_instructions(prog, bpf_access_decision,
					   ARRAY_SIZE(bpf_access_decision));
	if (ret)
		return log_error_errno(-1, errno, "Failed to add instructions to bpf cgroup program");

	return 0;
}

int bpf_program_finalize(struct bpf_program *prog)
{
	struct bpf_insn ins[2];

	if (!prog)
		return ret_set_errno(-1, EINVAL);

	TRACE("Device bpf program %s all devices by default",
	      prog->device_list_type == LXC_BPF_DEVICE_CGROUP_ALLOWLIST
		  ? "blocks"
		  : "allows");

	ins[0] = BPF_MOV64_IMM(BPF_REG_0, prog->device_list_type);
	ins[1] = BPF_EXIT_INSN();
	return bpf_program_add_instructions(prog, ins, ARRAY_SIZE(ins));
}

static int bpf_program_load_kernel(struct bpf_program *prog)
{
	__do_free char *log_buf = NULL;
	__u32 log_level = 0, log_size = 0;
	union bpf_attr *attr;

	if (prog->kernel_fd >= 0)
		return 0;

	if (lxc_log_trace()) {
		log_buf = zalloc(BPF_LOG_BUF_SIZE);
		if (!log_buf) {
			WARN("Failed to allocate bpf log buffer");
		} else {
			log_level = BPF_LOG_LEVEL;
			log_size = BPF_LOG_BUF_SIZE;
		}
	}

	attr = &(union bpf_attr){
		.prog_type	= prog->prog_type,
		.insns		= PTR_TO_U64(prog->instructions),
		.insn_cnt	= prog->n_instructions,
		.license	= PTR_TO_U64("GPL"),
		.log_buf	= PTR_TO_U64(log_buf),
		.log_level	= log_level,
		.log_size	= log_size,
	};

	prog->kernel_fd = bpf(BPF_PROG_LOAD, attr, sizeof(*attr));
	if (prog->kernel_fd < 0)
		return log_error_errno(-1, errno, "Failed to load bpf program: %s",
				       log_buf ?: "(null)");

	TRACE("Loaded bpf program: %s", log_buf ?: "(null)");
	return 0;
}

static int bpf_program_cgroup_attach(struct bpf_program *prog, int type,
				     int fd_cgroup, __u32 flags)
{
	__do_close int fd_attach = -EBADF;
	int ret;
	union bpf_attr *attr;

	if (prog->fd_cgroup >= 0 || prog->kernel_fd >= 0)
		return ret_errno(EBUSY);

	if (fd_cgroup < 0)
		return ret_errno(EBADF);

	if (flags & ~(BPF_F_ALLOW_OVERRIDE | BPF_F_ALLOW_MULTI | BPF_F_REPLACE))
		return syserror_set(-EINVAL, "Invalid flags for bpf program");

	/*
	 * Don't allow the bpf program to be overwritten for now. If we ever
	 * allow this we need to verify that the attach_flags of the current
	 * bpf program and the attach_flags of the new program match.
	 */
	if (flags & BPF_F_ALLOW_OVERRIDE)
		INFO("Allowing to override bpf program");

	/* Leave the caller's fd alone. */
	fd_attach = dup_cloexec(fd_cgroup);
	if (fd_attach < 0)
		return -errno;

	ret = bpf_program_load_kernel(prog);
	if (ret < 0)
		return syserror("Failed to load bpf program");

	attr = &(union bpf_attr){
		.attach_type	= type,
		.target_fd	= fd_attach,
		.attach_bpf_fd	= prog->kernel_fd,
		.attach_flags	= flags,
	};

	ret = bpf(BPF_PROG_ATTACH, attr, sizeof(*attr));
	if (ret < 0)
		return syserror("Failed to attach bpf program");

	prog->fd_cgroup		= move_fd(fd_attach);
	prog->attached_type	= type;
	prog->attached_flags	= flags;

	TRACE("Attached bpf program to cgroup %d", prog->fd_cgroup);
	return 0;
}

int bpf_program_cgroup_detach(struct bpf_program *prog)
{
	__do_close int fd_cgroup = -EBADF, fd_kernel = -EBADF;
	int ret;
	union bpf_attr *attr;

	if (!prog)
		return 0;

	/* Ensure that these fds are wiped. */
	fd_cgroup = move_fd(prog->fd_cgroup);
	fd_kernel = move_fd(prog->kernel_fd);

	if (fd_cgroup < 0 || fd_kernel < 0)
		return 0;

	attr = &(union bpf_attr){
		.attach_type	= prog->attached_type,
		.target_fd	= fd_cgroup,
		.attach_bpf_fd	= fd_kernel,
	};

	ret = bpf(BPF_PROG_DETACH, attr, sizeof(*attr));
	if (ret < 0)
		return syserror("Failed to detach bpf program from cgroup %d", fd_cgroup);

	TRACE("Detached bpf program from cgroup %d", fd_cgroup);

	return 0;
}

void bpf_device_program_free(struct cgroup_ops *ops)
{
	if (ops->cgroup2_devices) {
		(void)bpf_program_cgroup_detach(ops->cgroup2_devices);
		bpf_program_free(ops->cgroup2_devices);
		ops->cgroup2_devices = NULL;
	}
}

static inline bool bpf_device_list_block_all(const struct bpf_devices *bpf_devices)
{
	/* LXC_BPF_DEVICE_CGROUP_ALLOWLIST  -> block ("allowlist") all devices. */
	return bpf_devices->list_type == LXC_BPF_DEVICE_CGROUP_ALLOWLIST;
}

static inline bool bpf_device_add(const struct bpf_devices *bpf_devices,
				  struct device_item *device)
{
	/* We're blocking all devices so skip individual deny rules. */
	if (bpf_device_list_block_all(bpf_devices) && !device->allow)
		return log_trace(false, "Device cgroup blocks all devices; skipping specific deny rules");

	/* We're allowing all devices so skip individual allow rules. */
	if (!bpf_device_list_block_all(bpf_devices) && device->allow)
		return log_trace(false, "Device cgroup allows all devices; skipping specific allow rules");

	return true;
}

int bpf_list_add_device(struct bpf_devices *bpf_devices,
			struct device_item *device)
{
	__do_free struct lxc_list *list_elem = NULL;
	__do_free struct device_item *new_device = NULL;
	struct lxc_list *it;

	if (!bpf_devices || !device)
		return ret_errno(EINVAL);

	/* Check whether this determines the list type. */
	if (device->type == 'a' &&
	    device->major < 0 &&
	    device->minor < 0 &&
	    is_empty_string(device->access)) {
		if (device->allow) {
			bpf_devices->list_type = LXC_BPF_DEVICE_CGROUP_DENYLIST;
			TRACE("Device cgroup will allow (\"denylist\") all devices by default");
		} else {
			bpf_devices->list_type = LXC_BPF_DEVICE_CGROUP_ALLOWLIST;
			TRACE("Device cgroup will block (\"allowlist\") all devices by default");
		}

		/* Reset the device list. */
		lxc_clear_cgroup2_devices(bpf_devices);
		TRACE("Resetting cgroup device list");
		return 1; /* The device list was altered. */
	}

	TRACE("Processing new device rule: type %c, major %d, minor %d, access %s, allow %d",
	      device->type, device->major, device->minor, device->access, device->allow);

	lxc_list_for_each(it, &bpf_devices->device_item) {
		struct device_item *cur = it->elem;

		if (cur->type != device->type)
			continue;
		if (cur->major != device->major)
			continue;
		if (cur->minor != device->minor)
			continue;
		if (!strequal(cur->access, device->access))
			continue;

		if (!bpf_device_add(bpf_devices, cur))
			continue;

		/*
		 * The rule is switched from allow to deny or vica versa so
		 * don't bother allocating just flip the existing one.
		 */
		if (cur->allow != device->allow) {
			cur->allow = device->allow;

			return log_trace(1, "Switched existing device rule"); /* The device list was altered. */
		}


		return log_trace(0, "Reused existing device rule"); /* The device list wasn't altered. */
	}

	list_elem = malloc(sizeof(*list_elem));
	if (!list_elem)
		return syserror_set(ENOMEM, "Failed to allocate new device list");

	new_device = memdup(device, sizeof(struct device_item));
	if (!new_device)
		return syserror_set(ENOMEM, "Failed to allocate new device item");

	lxc_list_add_elem(list_elem, move_ptr(new_device));
	lxc_list_add_tail(&bpf_devices->device_item, move_ptr(list_elem));

	return log_trace(1, "Added new device rule"); /* The device list was altered. */
}

bool bpf_devices_cgroup_supported(void)
{
	__do_bpf_program_free struct bpf_program *prog = NULL;
	const struct bpf_insn insn[] = {
		BPF_MOV64_IMM(BPF_REG_0, 1),
		BPF_EXIT_INSN(),
	};
	int ret;

	if (geteuid() != 0)
		return log_trace(false,
				 "The bpf device cgroup requires real root");

	prog = bpf_program_new(BPF_PROG_TYPE_CGROUP_DEVICE);
	if (!prog)
		return log_trace(false, "Failed to allocate new bpf device cgroup program");

	ret = bpf_program_init(prog);
	if (ret)
		return log_error_errno(false, ENOMEM, "Failed to initialize bpf program");

	ret = bpf_program_add_instructions(prog, insn, ARRAY_SIZE(insn));
	if (ret < 0)
		return log_trace(false, "Failed to add new instructions to bpf device cgroup program");

	ret = bpf_program_load_kernel(prog);
	if (ret < 0)
		return log_trace(false, "Failed to load new bpf device cgroup program");

	return log_trace(true, "The bpf device cgroup is supported");
}

static struct bpf_program *__bpf_cgroup_devices(struct bpf_devices *bpf_devices)
{
	__do_bpf_program_free struct bpf_program *prog = NULL;
	int ret;
	struct lxc_list *it;

	prog = bpf_program_new(BPF_PROG_TYPE_CGROUP_DEVICE);
	if (!prog)
		return syserror_ret(NULL, "Failed to create new bpf program");

	ret = bpf_program_init(prog);
	if (ret)
		return syserror_ret(NULL, "Failed to initialize bpf program");

	prog->device_list_type = bpf_devices->list_type;
	TRACE("Device cgroup %s all devices by default",
	      bpf_device_list_block_all(bpf_devices) ? "blocks" : "allows");

	lxc_list_for_each(it, &bpf_devices->device_item) {
		struct device_item *cur = it->elem;

		TRACE("Processing device rule: type %c, major %d, minor %d, access %s, allow %d",
		      cur->type, cur->major, cur->minor, cur->access, cur->allow);

		if (!bpf_device_add(bpf_devices, cur))
			continue;

		ret = bpf_program_append_device(prog, cur);
		if (ret)
			return syserror_ret(NULL, "Failed adding new device rule");

		TRACE("Added new device rule");
	}

	ret = bpf_program_finalize(prog);
	if (ret)
		return syserror_ret(NULL, "Failed to finalize device program");

	return move_ptr(prog);
}

bool bpf_cgroup_devices_attach(struct cgroup_ops *ops,
			       struct bpf_devices *bpf_devices)
{
	__do_bpf_program_free struct bpf_program *prog = NULL;
	int ret;

	prog = __bpf_cgroup_devices(bpf_devices);
	if (!prog)
		return syserror_ret(false, "Failed to create bpf program");

	ret = bpf_program_cgroup_attach(prog, BPF_CGROUP_DEVICE,
					ops->unified->dfd_lim,
					BPF_F_ALLOW_MULTI);
	if (ret)
		return syserror_ret(false, "Failed to attach bpf program");

	/* Replace old bpf program. */
	swap(prog, ops->cgroup2_devices);
	return log_trace(true, "Attached bpf program");
}

bool bpf_cgroup_devices_update(struct cgroup_ops *ops,
			       struct bpf_devices *bpf_devices,
			       struct device_item *new)
{
	__do_bpf_program_free struct bpf_program *prog = NULL;
	static int can_use_bpf_replace = -1;
	struct bpf_program *prog_old;
	union bpf_attr *attr;
	int ret;

	if (!ops)
		return ret_set_errno(false, EINVAL);

	if (!pure_unified_layout(ops))
		return ret_set_errno(false, EINVAL);

	if (ops->unified->dfd_lim < 0)
		return ret_set_errno(false, EBADF);

	/*
	 * Note that bpf_list_add_device() returns 1 if it altered the device
	 * list and 0 if it didn't; both return values indicate success.
	 * Only a negative return value indicates an error.
	 */
	ret = bpf_list_add_device(bpf_devices, new);
	if (ret < 0)
		return false;

	if (ret == 0)
		return log_trace(true, "Device bpf program unaltered");

	/* No previous device program attached. */
	prog_old = ops->cgroup2_devices;
	if (!prog_old)
		return bpf_cgroup_devices_attach(ops, bpf_devices);

	prog = __bpf_cgroup_devices(bpf_devices);
	if (!prog)
		return syserror_ret(false, "Failed to create bpf program");

	ret = bpf_program_load_kernel(prog);
	if (ret < 0)
		return syserror_ret(false, "Failed to load bpf program");

	attr = &(union bpf_attr){
		.attach_type	= prog_old->attached_type,
		.target_fd	= prog_old->fd_cgroup,
		.attach_bpf_fd	= prog->kernel_fd,
	};

	switch (can_use_bpf_replace) {
	case 1:
		attr->replace_bpf_fd = prog_old->kernel_fd;
		attr->attach_flags = BPF_F_REPLACE | BPF_F_ALLOW_MULTI;

		ret = bpf(BPF_PROG_ATTACH, attr, sizeof(*attr));
		break;
	case -1:
		attr->replace_bpf_fd = prog_old->kernel_fd;
		attr->attach_flags = BPF_F_REPLACE | BPF_F_ALLOW_MULTI;

		can_use_bpf_replace = !bpf(BPF_PROG_ATTACH, attr, sizeof(*attr));
		if (can_use_bpf_replace > 0)
			break;

		__fallthrough;
	case 0:
		attr->attach_flags = BPF_F_ALLOW_MULTI;
		attr->replace_bpf_fd = 0;

		ret = bpf(BPF_PROG_ATTACH, attr, sizeof(*attr));
		break;
	}
	if (ret < 0)
		return syserror_ret(false, "Failed to update bpf program");

	if (can_use_bpf_replace > 0) {
		/* The old program was automatically detached by the kernel. */
		close_prot_errno_disarm(prog_old->kernel_fd);
		/* The new bpf program now owns the cgroup fd. */
		prog->fd_cgroup = move_fd(prog_old->fd_cgroup);
		TRACE("Replaced existing bpf program");
	} else {
		TRACE("Appended bpf program");
	}
	prog->attached_type  = prog_old->attached_type;
	prog->attached_flags = attr->attach_flags;
	swap(prog, ops->cgroup2_devices);

	return true;
}
