/* SPDX-License-Identifier: LGPL-2.1+ */

/*
 * cgfs-ng.c: this is a new, simplified implementation of a filesystem
 * cgroup backend.  The original cgfs.c was designed to be as flexible
 * as possible.  It would try to find cgroup filesystems no matter where
 * or how you had them mounted, and deduce the most usable mount for
 * each controller.
 *
 * This new implementation assumes that cgroup filesystems are mounted
 * under /sys/fs/cgroup/clist where clist is either the controller, or
 * a comma-separated list of controllers.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <grp.h>
#include <linux/kdev_t.h>
#include <linux/types.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <unistd.h>

#include "af_unix.h"
#include "caps.h"
#include "cgroup.h"
#include "cgroup2_devices.h"
#include "cgroup_utils.h"
#include "commands.h"
#include "commands_utils.h"
#include "conf.h"
#include "config.h"
#include "error_utils.h"
#include "log.h"
#include "macro.h"
#include "mainloop.h"
#include "memory_utils.h"
#include "mount_utils.h"
#include "storage/storage.h"
#include "string_utils.h"
#include "syscall_wrappers.h"
#include "utils.h"

#ifndef HAVE_STRLCPY
#include "include/strlcpy.h"
#endif

#ifndef HAVE_STRLCAT
#include "include/strlcat.h"
#endif

lxc_log_define(cgfsng, cgroup);

/*
 * Given a pointer to a null-terminated array of pointers, realloc to add one
 * entry, and point the new entry to NULL. Do not fail. Return the index to the
 * second-to-last entry - that is, the one which is now available for use
 * (keeping the list null-terminated).
 */
static int list_add(void ***list)
{
	int idx = 0;
	void **p;

	if (*list)
		for (; (*list)[idx]; idx++)
			;

	p = realloc(*list, (idx + 2) * sizeof(void **));
	if (!p)
		return ret_errno(ENOMEM);

	p[idx + 1] = NULL;
	*list = p;

	return idx;
}

/* Given a null-terminated array of strings, check whether @entry is one of the
 * strings.
 */
static bool string_in_list(char **list, const char *entry)
{
	if (!list)
		return false;

	for (int i = 0; list[i]; i++)
		if (strequal(list[i], entry))
			return true;

	return false;
}

/* Given a handler's cgroup data, return the struct hierarchy for the controller
 * @c, or NULL if there is none.
 */
static struct hierarchy *get_hierarchy(const struct cgroup_ops *ops, const char *controller)
{
	if (!ops->hierarchies)
		return log_trace_errno(NULL, errno, "There are no useable cgroup controllers");

	for (int i = 0; ops->hierarchies[i]; i++) {
		if (!controller) {
			/* This is the empty unified hierarchy. */
			if (ops->hierarchies[i]->controllers && !ops->hierarchies[i]->controllers[0])
				return ops->hierarchies[i];

			continue;
		}

		/*
		 * Handle controllers with significant implementation changes
		 * from cgroup to cgroup2.
		 */
		if (pure_unified_layout(ops)) {
			if (strequal(controller, "devices")) {
				if (device_utility_controller(ops->unified))
					return ops->unified;

				break;
			} else if (strequal(controller, "freezer")) {
				if (freezer_utility_controller(ops->unified))
					return ops->unified;

				break;
			}
		}

		if (string_in_list(ops->hierarchies[i]->controllers, controller))
			return ops->hierarchies[i];
	}

	if (controller)
		WARN("There is no useable %s controller", controller);
	else
		WARN("There is no empty unified cgroup hierarchy");

	return ret_set_errno(NULL, ENOENT);
}

int prepare_cgroup_fd(const struct cgroup_ops *ops, struct cgroup_fd *fd, bool limit)
{
	int dfd;
	const struct hierarchy *h;

	h = get_hierarchy(ops, fd->controller);
	if (!h)
		return ret_errno(ENOENT);

	/*
	 * The client requested that the controller must be in a specific
	 * cgroup version.
	 */
	if (fd->type != 0 && fd->type != h->fs_type)
		return ret_errno(EINVAL);

	if (limit)
		dfd = h->dfd_con;
	else
		dfd = h->dfd_lim;
	if (dfd < 0)
		return ret_errno(EBADF);

	fd->layout = ops->cgroup_layout;
	fd->type = h->fs_type;
	if (fd->type == UNIFIED_HIERARCHY)
		fd->utilities = h->utilities;
	fd->fd = dfd;

	return 0;
}

/* Taken over modified from the kernel sources. */
#define NBITS 32 /* bits in uint32_t */
#define DIV_ROUND_UP(n, d) (((n) + (d)-1) / (d))
#define BITS_TO_LONGS(nr) DIV_ROUND_UP(nr, NBITS)

static void set_bit(unsigned bit, uint32_t *bitarr)
{
	bitarr[bit / NBITS] |= (1 << (bit % NBITS));
}

static void clear_bit(unsigned bit, uint32_t *bitarr)
{
	bitarr[bit / NBITS] &= ~(1 << (bit % NBITS));
}

static bool is_set(unsigned bit, uint32_t *bitarr)
{
	return (bitarr[bit / NBITS] & (1 << (bit % NBITS))) != 0;
}

/* Create cpumask from cpulist aka turn:
 *
 *	0,2-3
 *
 * into bit array
 *
 *	1 0 1 1
 */
static uint32_t *lxc_cpumask(char *buf, size_t nbits)
{
	__do_free uint32_t *bitarr = NULL;
	char *token;
	size_t arrlen;

	arrlen = BITS_TO_LONGS(nbits);
	bitarr = calloc(arrlen, sizeof(uint32_t));
	if (!bitarr)
		return ret_set_errno(NULL, ENOMEM);

	lxc_iterate_parts(token, buf, ",") {
		errno = 0;
		unsigned end, start;
		char *range;

		start = strtoul(token, NULL, 0);
		end = start;
		range = strchr(token, '-');
		if (range)
			end = strtoul(range + 1, NULL, 0);

		if (!(start <= end))
			return ret_set_errno(NULL, EINVAL);

		if (end >= nbits)
			return ret_set_errno(NULL, EINVAL);

		while (start <= end)
			set_bit(start++, bitarr);
	}

	return move_ptr(bitarr);
}

/* Turn cpumask into simple, comma-separated cpulist. */
static char *lxc_cpumask_to_cpulist(uint32_t *bitarr, size_t nbits)
{
	__do_free_string_list char **cpulist = NULL;
	char numstr[INTTYPE_TO_STRLEN(size_t)] = {0};
	int ret;

	for (size_t i = 0; i <= nbits; i++) {
		if (!is_set(i, bitarr))
			continue;

		ret = strnprintf(numstr, sizeof(numstr), "%zu", i);
		if (ret < 0)
			return NULL;

		ret = lxc_append_string(&cpulist, numstr);
		if (ret < 0)
			return ret_set_errno(NULL, ENOMEM);
	}

	if (!cpulist)
		return ret_set_errno(NULL, ENOMEM);

	return lxc_string_join(",", (const char **)cpulist, false);
}

static ssize_t get_max_cpus(char *cpulist)
{
	char *c1, *c2;
	char *maxcpus = cpulist;
	size_t cpus = 0;

	c1 = strrchr(maxcpus, ',');
	if (c1)
		c1++;

	c2 = strrchr(maxcpus, '-');
	if (c2)
		c2++;

	if (!c1 && !c2)
		c1 = maxcpus;
	else if (c1 > c2)
		c2 = c1;
	else if (c1 < c2)
		c1 = c2;
	else if (!c1 && c2)
		c1 = c2;

	errno = 0;
	cpus = strtoul(c1, NULL, 0);
	if (errno != 0)
		return -1;

	return cpus;
}

static inline bool is_unified_hierarchy(const struct hierarchy *h)
{
	return h->fs_type == UNIFIED_HIERARCHY;
}

/* Return true if the controller @entry is found in the null-terminated list of
 * hierarchies @hlist.
 */
static bool controller_available(struct hierarchy **hlist, char *entry)
{
	if (!hlist)
		return false;

	for (int i = 0; hlist[i]; i++)
		if (string_in_list(hlist[i]->controllers, entry))
			return true;

	return false;
}

static bool controllers_available(struct cgroup_ops *ops)
{
	struct hierarchy **hlist;

	if (!ops->cgroup_use)
		return true;

	hlist = ops->hierarchies;
	for (char **cur = ops->cgroup_use; cur && *cur; cur++)
		if (!controller_available(hlist, *cur))
			return log_error(false, "The %s controller found", *cur);

	return true;
}

static char **list_new(void)
{
	__do_free_string_list char **list = NULL;
	int idx;

	idx = list_add((void ***)&list);
	if (idx < 0)
		return NULL;

	list[idx] = NULL;
	return move_ptr(list);
}

static int list_add_string(char ***list, char *entry)
{
	__do_free char *dup = NULL;
	int idx;

	dup = strdup(entry);
	if (!dup)
		return ret_errno(ENOMEM);

	idx = list_add((void ***)list);
	if (idx < 0)
		return idx;

	(*list)[idx] = move_ptr(dup);
	return 0;
}

static char **list_add_controllers(char *controllers)
{
	__do_free_string_list char **list = NULL;
	char *it;

	lxc_iterate_parts(it, controllers, ", \t\n") {
		int ret;

		ret = list_add_string(&list, it);
		if (ret < 0)
			return NULL;
	}

	return move_ptr(list);
}

static char **unified_controllers(int dfd, const char *file)
{
	__do_free char *buf = NULL;

	buf = read_file_at(dfd, file, PROTECT_OPEN, 0);
	if (!buf)
		return NULL;

	return list_add_controllers(buf);
}

static bool skip_hierarchy(const struct cgroup_ops *ops, char **controllers)
{
	if (!ops->cgroup_use)
		return false;

	for (char **cur_ctrl = controllers; cur_ctrl && *cur_ctrl; cur_ctrl++) {
		bool found = false;

		for (char **cur_use = ops->cgroup_use; cur_use && *cur_use; cur_use++) {
			if (!strequal(*cur_use, *cur_ctrl))
				continue;

			found = true;
			break;
		}

		if (found)
			continue;

		return true;
	}

	return false;
}

static int cgroup_hierarchy_add(struct cgroup_ops *ops, int dfd_mnt, char *mnt,
				int dfd_base, char *base_cgroup,
				char **controllers, cgroupfs_type_magic_t fs_type)
{
	__do_free struct hierarchy *new = NULL;
	int idx;

	if (abspath(base_cgroup))
		return syserror_set(-EINVAL, "Container base path must be relative to controller mount");

	new = zalloc(sizeof(*new));
	if (!new)
		return ret_errno(ENOMEM);

	new->dfd_con		= -EBADF;
	new->dfd_lim		= -EBADF;
	new->dfd_mon		= -EBADF;

	new->fs_type		= fs_type;
	new->controllers	= controllers;
	new->at_mnt		= mnt;
	new->at_base		= base_cgroup;

	new->dfd_mnt		= dfd_mnt;
	new->dfd_base		= dfd_base;

	TRACE("Adding cgroup hierarchy mounted at %s and base cgroup %s",
	      mnt, maybe_empty(base_cgroup));
	for (char *const *it = new->controllers; it && *it; it++)
		TRACE("The hierarchy contains the %s controller", *it);

	idx = list_add((void ***)&ops->hierarchies);
	if (idx < 0)
		return ret_errno(idx);

	if (fs_type == UNIFIED_HIERARCHY)
		ops->unified = new;
	(ops->hierarchies)[idx] = move_ptr(new);

	return 0;
}

static int cgroup_tree_remove(struct hierarchy **hierarchies, const char *path_prune)
{
	if (!path_prune || !hierarchies)
		return 0;

	for (int i = 0; hierarchies[i]; i++) {
		struct hierarchy *h = hierarchies[i];
		int ret;

		ret = cgroup_tree_prune(h->dfd_base, path_prune);
		if (ret < 0)
			SYSWARN("Failed to destroy %d(%s)", h->dfd_base, path_prune);
		else
			TRACE("Removed cgroup tree %d(%s)", h->dfd_base, path_prune);

		free_equal(h->path_lim, h->path_con);
	}

	return 0;
}

struct generic_userns_exec_data {
	struct hierarchy **hierarchies;
	const char *path_prune;
	struct lxc_conf *conf;
	uid_t origuid; /* target uid in parent namespace */
	char *path;
};

static int cgroup_tree_remove_wrapper(void *data)
{
	struct generic_userns_exec_data *arg = data;
	uid_t nsuid = (arg->conf->root_nsuid_map != NULL) ? 0 : arg->conf->init_uid;
	gid_t nsgid = (arg->conf->root_nsgid_map != NULL) ? 0 : arg->conf->init_gid;
	int ret;

	if (!lxc_drop_groups() && errno != EPERM)
		return log_error_errno(-1, errno, "Failed to setgroups(0, NULL)");

	ret = setresgid(nsgid, nsgid, nsgid);
	if (ret < 0)
		return log_error_errno(-1, errno, "Failed to setresgid(%d, %d, %d)",
				       (int)nsgid, (int)nsgid, (int)nsgid);

	ret = setresuid(nsuid, nsuid, nsuid);
	if (ret < 0)
		return log_error_errno(-1, errno, "Failed to setresuid(%d, %d, %d)",
				       (int)nsuid, (int)nsuid, (int)nsuid);

	return cgroup_tree_remove(arg->hierarchies, arg->path_prune);
}

__cgfsng_ops static void cgfsng_payload_destroy(struct cgroup_ops *ops,
						struct lxc_handler *handler)
{
	int ret;

	if (!ops) {
		ERROR("Called with uninitialized cgroup operations");
		return;
	}

	if (!ops->hierarchies)
		return;

	if (!handler) {
		ERROR("Called with uninitialized handler");
		return;
	}

	if (!handler->conf) {
		ERROR("Called with uninitialized conf");
		return;
	}

	if (!ops->container_limit_cgroup) {
		WARN("Uninitialized limit cgroup");
		return;
	}

	ret = bpf_program_cgroup_detach(handler->cgroup_ops->cgroup2_devices);
	if (ret < 0)
		WARN("Failed to detach bpf program from cgroup");

	if (!lxc_list_empty(&handler->conf->id_map)) {
		struct generic_userns_exec_data wrap = {
			.conf			= handler->conf,
			.path_prune		= ops->container_limit_cgroup,
			.hierarchies		= ops->hierarchies,
			.origuid		= 0,
		};
		ret = userns_exec_1(handler->conf, cgroup_tree_remove_wrapper,
				    &wrap, "cgroup_tree_remove_wrapper");
	} else {
		ret = cgroup_tree_remove(ops->hierarchies, ops->container_limit_cgroup);
	}
	if (ret < 0)
		SYSWARN("Failed to destroy cgroups");
}

#define __ISOL_CPUS "/sys/devices/system/cpu/isolated"
#define __OFFLINE_CPUS "/sys/devices/system/cpu/offline"
static bool cpuset1_cpus_initialize(int dfd_parent, int dfd_child,
				    bool am_initialized)
{
	__do_free char *cpulist = NULL, *fpath = NULL, *isolcpus = NULL,
		       *offlinecpus = NULL, *posscpus = NULL;
	__do_free uint32_t *isolmask = NULL, *offlinemask = NULL,
			   *possmask = NULL;
	int ret;
	ssize_t i;
	ssize_t maxisol = 0, maxoffline = 0, maxposs = 0;
	bool flipped_bit = false;

	posscpus = read_file_at(dfd_parent, "cpuset.cpus", PROTECT_OPEN, 0);
	if (!posscpus)
		return log_error_errno(false, errno, "Failed to read file \"%s\"", fpath);

	/* Get maximum number of cpus found in possible cpuset. */
	maxposs = get_max_cpus(posscpus);
	if (maxposs < 0 || maxposs >= INT_MAX - 1)
		return false;

	if (file_exists(__ISOL_CPUS)) {
		isolcpus = read_file_at(-EBADF, __ISOL_CPUS, PROTECT_OPEN, 0);
		if (!isolcpus)
			return log_error_errno(false, errno, "Failed to read file \"%s\"", __ISOL_CPUS);

		if (isdigit(isolcpus[0])) {
			/* Get maximum number of cpus found in isolated cpuset. */
			maxisol = get_max_cpus(isolcpus);
			if (maxisol < 0 || maxisol >= INT_MAX - 1)
				return false;
		}

		if (maxposs < maxisol)
			maxposs = maxisol;
		maxposs++;
	} else {
		TRACE("The path \""__ISOL_CPUS"\" to read isolated cpus from does not exist");
	}

	if (file_exists(__OFFLINE_CPUS)) {
		offlinecpus = read_file_at(-EBADF, __OFFLINE_CPUS, PROTECT_OPEN, 0);
		if (!offlinecpus)
			return log_error_errno(false, errno, "Failed to read file \"%s\"", __OFFLINE_CPUS);

		if (isdigit(offlinecpus[0])) {
			/* Get maximum number of cpus found in offline cpuset. */
			maxoffline = get_max_cpus(offlinecpus);
			if (maxoffline < 0 || maxoffline >= INT_MAX - 1)
				return false;
		}

		if (maxposs < maxoffline)
			maxposs = maxoffline;
		maxposs++;
	} else {
		TRACE("The path \""__OFFLINE_CPUS"\" to read offline cpus from does not exist");
	}

	if ((maxisol == 0) && (maxoffline == 0)) {
		cpulist = move_ptr(posscpus);
		goto copy_parent;
	}

	possmask = lxc_cpumask(posscpus, maxposs);
	if (!possmask)
		return log_error_errno(false, errno, "Failed to create cpumask for possible cpus");

	if (maxisol > 0) {
		isolmask = lxc_cpumask(isolcpus, maxposs);
		if (!isolmask)
			return log_error_errno(false, errno, "Failed to create cpumask for isolated cpus");
	}

	if (maxoffline > 0) {
		offlinemask = lxc_cpumask(offlinecpus, maxposs);
		if (!offlinemask)
			return log_error_errno(false, errno, "Failed to create cpumask for offline cpus");
	}

	for (i = 0; i <= maxposs; i++) {
		if ((isolmask && !is_set(i, isolmask)) ||
		    (offlinemask && !is_set(i, offlinemask)) ||
		    !is_set(i, possmask))
			continue;

		flipped_bit = true;
		clear_bit(i, possmask);
	}

	if (!flipped_bit) {
		cpulist = lxc_cpumask_to_cpulist(possmask, maxposs);
		TRACE("No isolated or offline cpus present in cpuset");
	} else {
		cpulist = move_ptr(posscpus);
		TRACE("Removed isolated or offline cpus from cpuset");
	}
	if (!cpulist)
		return log_error_errno(false, errno, "Failed to create cpu list");

copy_parent:
	if (!am_initialized) {
		ret = lxc_writeat(dfd_child, "cpuset.cpus", cpulist, strlen(cpulist));
		if (ret < 0)
			return log_error_errno(false, errno, "Failed to write cpu list to \"%d/cpuset.cpus\"", dfd_child);

		TRACE("Copied cpu settings of parent cgroup");
	}

	return true;
}

static bool cpuset1_initialize(int dfd_base, int dfd_next)
{
	char mems[PATH_MAX];
	ssize_t bytes;
	char v;

	/*
	* Determine whether the base cgroup has cpuset
	* inheritance turned on.
	 */
	bytes = lxc_readat(dfd_base, "cgroup.clone_children", &v, 1);
	if (bytes < 0)
		return syserror_ret(false, "Failed to read file %d(cgroup.clone_children)", dfd_base);

	/*
	* Initialize cpuset.cpus and make remove any isolated
	* and offline cpus.
	 */
	if (!cpuset1_cpus_initialize(dfd_base, dfd_next, v == '1'))
		return syserror_ret(false, "Failed to initialize cpuset.cpus");

	/* Read cpuset.mems from parent... */
	bytes = lxc_readat(dfd_base, "cpuset.mems", mems, sizeof(mems));
	if (bytes < 0)
		return syserror_ret(false, "Failed to read file %d(cpuset.mems)", dfd_base);

	/* ... and copy to first cgroup in the tree... */
	bytes = lxc_writeat(dfd_next, "cpuset.mems", mems, bytes);
	if (bytes < 0)
		return syserror_ret(false, "Failed to write %d(cpuset.mems)", dfd_next);

	/* ... and finally turn on cpuset inheritance. */
	bytes = lxc_writeat(dfd_next, "cgroup.clone_children", "1", 1);
	if (bytes < 0)
		return syserror_ret(false, "Failed to write %d(cgroup.clone_children)", dfd_next);

	return log_trace(true, "Initialized cpuset in the legacy hierarchy");
}

static int __cgroup_tree_create(int dfd_base, const char *path, mode_t mode,
				bool cpuset_v1, bool eexist_ignore)
{
	__do_close int dfd_final = -EBADF;
	int dfd_cur = dfd_base;
	int ret = 0;
	size_t len;
	char *cur;
	char buf[PATH_MAX];

	if (is_empty_string(path))
		return ret_errno(EINVAL);

	len = strlcpy(buf, path, sizeof(buf));
	if (len >= sizeof(buf))
		return ret_errno(E2BIG);

	lxc_iterate_parts(cur, buf, "/") {
		/*
		 * Even though we vetted the paths when we parsed the config
		 * we're paranoid here and check that the path is neither
		 * absolute nor walks upwards.
		 */
		if (abspath(cur))
			return syserror_set(-EINVAL, "No absolute paths allowed");

		if (strnequal(cur, "..", STRLITERALLEN("..")))
			return syserror_set(-EINVAL, "No upward walking paths allowed");

		ret = mkdirat(dfd_cur, cur, mode);
		if (ret < 0) {
			if (errno != EEXIST)
				return syserror("Failed to create %d(%s)", dfd_cur, cur);

			ret = -EEXIST;
		}
		TRACE("%s %d(%s) cgroup", !ret ? "Created" : "Reusing", dfd_cur, cur);

		dfd_final = open_at(dfd_cur, cur, PROTECT_OPATH_DIRECTORY, PROTECT_LOOKUP_BENEATH, 0);
		if (dfd_final < 0)
			return syserror("Fail to open%s directory %d(%s)",
					!ret ? " newly created" : "", dfd_base, cur);
		if (dfd_cur != dfd_base)
			close(dfd_cur);
		else if (cpuset_v1 && !cpuset1_initialize(dfd_base, dfd_final))
			return syserror_set(-EINVAL, "Failed to initialize cpuset controller in the legacy hierarchy");
		/*
		 * Leave dfd_final pointing to the last fd we opened so
		 * it will be automatically zapped if we return early.
		 */
		dfd_cur = dfd_final;
	}

	/* The final cgroup must be succesfully creatd by us. */
	if (ret) {
		if (ret != -EEXIST || !eexist_ignore)
			return syserror_set(ret, "Creating the final cgroup %d(%s) failed", dfd_base, path);
	}

	return move_fd(dfd_final);
}

static bool cgroup_tree_create(struct cgroup_ops *ops, struct lxc_conf *conf,
			       struct hierarchy *h, const char *cgroup_limit_dir,
			       const char *cgroup_leaf, bool payload)
{
	__do_close int fd_limit = -EBADF, fd_final = -EBADF;
	__do_free char *path = NULL, *limit_path = NULL;
	bool cpuset_v1 = false;

	/*
	 * The legacy cpuset controller needs massaging in case inheriting
	 * settings from its immediate ancestor cgroup hasn't been turned on.
	 */
	cpuset_v1 = !is_unified_hierarchy(h) && string_in_list(h->controllers, "cpuset");

	if (payload && cgroup_leaf) {
		/* With isolation both parts need to not already exist. */
		fd_limit = __cgroup_tree_create(h->dfd_base, cgroup_limit_dir, 0755, cpuset_v1, false);
		if (fd_limit < 0)
			return syserror_ret(false, "Failed to create limiting cgroup %d(%s)", h->dfd_base, cgroup_limit_dir);

		TRACE("Created limit cgroup %d->%d(%s)",
		      fd_limit, h->dfd_base, cgroup_limit_dir);

		/*
		 * With isolation the devices legacy cgroup needs to be
		 * iinitialized early, as it typically contains an 'a' (all)
		 * line, which is not possible once a subdirectory has been
		 * created.
		 */
		if (string_in_list(h->controllers, "devices") &&
		    !ops->setup_limits_legacy(ops, conf, true))
			return log_error(false, "Failed to setup legacy device limits");

		limit_path = make_cgroup_path(h, h->at_base, cgroup_limit_dir, NULL);
		path = must_make_path(limit_path, cgroup_leaf, NULL);

		/*
		 * If we use a separate limit cgroup, the leaf cgroup, i.e. the
		 * cgroup the container actually resides in, is below fd_limit.
		 */
		fd_final = __cgroup_tree_create(fd_limit, cgroup_leaf, 0755, cpuset_v1, false);
		if (fd_final < 0) {
			/* Ensure we don't leave any garbage behind. */
			if (cgroup_tree_prune(h->dfd_base, cgroup_limit_dir))
				SYSWARN("Failed to destroy %d(%s)", h->dfd_base, cgroup_limit_dir);
			else
				TRACE("Removed cgroup tree %d(%s)", h->dfd_base, cgroup_limit_dir);
		}
	} else {
		path = make_cgroup_path(h, h->at_base, cgroup_limit_dir, NULL);

		fd_final = __cgroup_tree_create(h->dfd_base, cgroup_limit_dir, 0755, cpuset_v1, false);
	}
	if (fd_final < 0)
		return syserror_ret(false, "Failed to create %s cgroup %d(%s)", payload ? "payload" : "monitor", h->dfd_base, cgroup_limit_dir);

	if (payload) {
		h->dfd_con = move_fd(fd_final);
		h->path_con = move_ptr(path);

		if (fd_limit < 0)
			h->dfd_lim = h->dfd_con;
		else
			h->dfd_lim = move_fd(fd_limit);

		if (limit_path)
			h->path_lim = move_ptr(limit_path);
		else
			h->path_lim = h->path_con;
	} else {
		h->dfd_mon = move_fd(fd_final);
	}

	return true;
}

static void cgroup_tree_prune_leaf(struct hierarchy *h, const char *path_prune,
				   bool payload)
{
	bool prune = true;

	if (payload) {
		/* Check whether we actually created the cgroup to prune. */
		if (h->dfd_lim < 0)
			prune = false;

		free_equal(h->path_con, h->path_lim);
		close_equal(h->dfd_con, h->dfd_lim);
	} else {
		/* Check whether we actually created the cgroup to prune. */
		if (h->dfd_mon < 0)
			prune = false;

		close_prot_errno_disarm(h->dfd_mon);
	}

	/* We didn't create this cgroup. */
	if (!prune)
		return;

	if (cgroup_tree_prune(h->dfd_base, path_prune))
		SYSWARN("Failed to destroy %d(%s)", h->dfd_base, path_prune);
	else
		TRACE("Removed cgroup tree %d(%s)", h->dfd_base, path_prune);
}

__cgfsng_ops static void cgfsng_monitor_destroy(struct cgroup_ops *ops,
						struct lxc_handler *handler)
{
	int len;
	char pidstr[INTTYPE_TO_STRLEN(pid_t)];
	const struct lxc_conf *conf;

	if (!ops) {
		ERROR("Called with uninitialized cgroup operations");
		return;
	}

	if (!ops->hierarchies)
		return;

	if (!handler) {
		ERROR("Called with uninitialized handler");
		return;
	}

	if (!handler->conf) {
		ERROR("Called with uninitialized conf");
		return;
	}
	conf = handler->conf;

	if (!ops->monitor_cgroup) {
		WARN("Uninitialized monitor cgroup");
		return;
	}

	len = strnprintf(pidstr, sizeof(pidstr), "%d", handler->monitor_pid);
	if (len < 0)
		return;

	for (int i = 0; ops->hierarchies[i]; i++) {
		__do_close int fd_pivot = -EBADF;
		__do_free char *pivot_path = NULL;
		struct hierarchy *h = ops->hierarchies[i];
		bool cpuset_v1 = false;
		int ret;

		/* Monitor might have died before we entered the cgroup. */
		if (handler->monitor_pid <= 0) {
			WARN("No valid monitor process found while destroying cgroups");
			goto cgroup_prune_tree;
		}

		if (conf->cgroup_meta.monitor_pivot_dir)
			pivot_path = must_make_path(conf->cgroup_meta.monitor_pivot_dir, CGROUP_PIVOT, NULL);
		else if (conf->cgroup_meta.dir)
			pivot_path = must_make_path(conf->cgroup_meta.dir, CGROUP_PIVOT, NULL);
		else
			pivot_path = must_make_path(CGROUP_PIVOT, NULL);

		cpuset_v1 = !is_unified_hierarchy(h) && string_in_list(h->controllers, "cpuset");

		fd_pivot = __cgroup_tree_create(h->dfd_base, pivot_path, 0755, cpuset_v1, true);
		if (fd_pivot < 0) {
			SYSWARN("Failed to create pivot cgroup %d(%s)", h->dfd_base, pivot_path);
			continue;
		}

		ret = lxc_writeat(fd_pivot, "cgroup.procs", pidstr, len);
		if (ret != 0) {
			SYSWARN("Failed to move monitor %s to \"%s\"", pidstr, pivot_path);
			continue;
		}

cgroup_prune_tree:
		ret = cgroup_tree_prune(h->dfd_base, ops->monitor_cgroup);
		if (ret < 0)
			SYSWARN("Failed to destroy %d(%s)", h->dfd_base, ops->monitor_cgroup);
		else
			TRACE("Removed cgroup tree %d(%s)", h->dfd_base, ops->monitor_cgroup);
	}
}

/*
 * Check we have no lxc.cgroup.dir, and that lxc.cgroup.dir.limit_prefix is a
 * proper prefix directory of lxc.cgroup.dir.payload.
 *
 * Returns the prefix length if it is set, otherwise zero on success.
 */
static bool check_cgroup_dir_config(struct lxc_conf *conf)
{
	const char *monitor_dir = conf->cgroup_meta.monitor_dir,
		   *container_dir = conf->cgroup_meta.container_dir,
		   *namespace_dir = conf->cgroup_meta.namespace_dir;

	/* none of the new options are set, all is fine */
	if (!monitor_dir && !container_dir && !namespace_dir)
		return true;

	/* some are set, make sure lxc.cgroup.dir is not also set*/
	if (conf->cgroup_meta.dir)
		return log_error_errno(false, EINVAL,
			"lxc.cgroup.dir conflicts with lxc.cgroup.dir.payload/monitor");

	/* make sure both monitor and payload are set */
	if (!monitor_dir || !container_dir)
		return log_error_errno(false, EINVAL,
			"lxc.cgroup.dir.payload and lxc.cgroup.dir.monitor must both be set");

	/* namespace_dir may be empty */
	return true;
}

__cgfsng_ops static bool cgfsng_monitor_create(struct cgroup_ops *ops, struct lxc_handler *handler)
{
	__do_free char *monitor_cgroup = NULL;
	int idx = 0;
	int i;
	size_t len;
	char *suffix = NULL;
	struct lxc_conf *conf;

	if (!ops)
		return ret_set_errno(false, ENOENT);

	if (!ops->hierarchies)
		return true;

	if (ops->monitor_cgroup)
		return ret_set_errno(false, EEXIST);

	if (!handler || !handler->conf)
		return ret_set_errno(false, EINVAL);

	conf = handler->conf;

	if (!check_cgroup_dir_config(conf))
		return false;

	if (conf->cgroup_meta.monitor_dir) {
		monitor_cgroup = strdup(conf->cgroup_meta.monitor_dir);
	} else if (conf->cgroup_meta.dir) {
		monitor_cgroup = must_concat(&len, conf->cgroup_meta.dir, "/",
					     DEFAULT_MONITOR_CGROUP_PREFIX,
					     handler->name,
					     CGROUP_CREATE_RETRY, NULL);
	} else if (ops->cgroup_pattern) {
		__do_free char *cgroup_tree = NULL;

		cgroup_tree = lxc_string_replace("%n", handler->name, ops->cgroup_pattern);
		if (!cgroup_tree)
			return ret_set_errno(false, ENOMEM);

		monitor_cgroup = must_concat(&len, cgroup_tree, "/",
					     DEFAULT_MONITOR_CGROUP,
					     CGROUP_CREATE_RETRY, NULL);
	} else {
		monitor_cgroup = must_concat(&len, DEFAULT_MONITOR_CGROUP_PREFIX,
					     handler->name,
					     CGROUP_CREATE_RETRY, NULL);
	}
	if (!monitor_cgroup)
		return ret_set_errno(false, ENOMEM);

	if (!conf->cgroup_meta.monitor_dir) {
		suffix = monitor_cgroup + len - CGROUP_CREATE_RETRY_LEN;
		*suffix = '\0';
	}
	do {
		if (idx && suffix)
			sprintf(suffix, "-%d", idx);

		for (i = 0; ops->hierarchies[i]; i++) {
			if (cgroup_tree_create(ops, handler->conf,
					       ops->hierarchies[i],
					       monitor_cgroup, NULL, false))
				continue;

			DEBUG("Failed to create cgroup %s)", monitor_cgroup);
			for (int j = 0; j <= i; j++)
				cgroup_tree_prune_leaf(ops->hierarchies[j],
						       monitor_cgroup, false);

			idx++;
			break;
		}
	} while (ops->hierarchies[i] && idx > 0 && idx < 1000 && suffix);

	if (idx == 1000 || (!suffix && idx != 0))
		return log_error_errno(false, ERANGE, "Failed to create monitor cgroup");

	ops->monitor_cgroup = move_ptr(monitor_cgroup);
	return log_info(true, "The monitor process uses \"%s\" as cgroup", ops->monitor_cgroup);
}

/*
 * Try to create the same cgroup in all hierarchies. Start with cgroup_pattern;
 * next cgroup_pattern-1, -2, ..., -999.
 */
__cgfsng_ops static bool cgfsng_payload_create(struct cgroup_ops *ops, struct lxc_handler *handler)
{
	__do_free char *container_cgroup = NULL, *__limit_cgroup = NULL;
	char *limit_cgroup;
	int idx = 0;
	int i;
	size_t len;
	char *suffix = NULL;
	struct lxc_conf *conf;

	if (!ops)
		return ret_set_errno(false, ENOENT);

	if (!ops->hierarchies)
		return true;

	if (ops->container_cgroup || ops->container_limit_cgroup)
		return ret_set_errno(false, EEXIST);

	if (!handler || !handler->conf)
		return ret_set_errno(false, EINVAL);

	conf = handler->conf;

	if (!check_cgroup_dir_config(conf))
		return false;

	if (conf->cgroup_meta.container_dir) {
		__limit_cgroup = strdup(conf->cgroup_meta.container_dir);
		if (!__limit_cgroup)
			return ret_set_errno(false, ENOMEM);

		if (conf->cgroup_meta.namespace_dir) {
			container_cgroup = must_make_path(__limit_cgroup,
							  conf->cgroup_meta.namespace_dir,
							  NULL);
			limit_cgroup = __limit_cgroup;
		} else {
			/* explicit paths but without isolation */
			limit_cgroup = move_ptr(__limit_cgroup);
			container_cgroup = limit_cgroup;
		}
	} else if (conf->cgroup_meta.dir) {
		limit_cgroup = must_concat(&len, conf->cgroup_meta.dir, "/",
					   DEFAULT_PAYLOAD_CGROUP_PREFIX,
					   handler->name,
					   CGROUP_CREATE_RETRY, NULL);
		container_cgroup = limit_cgroup;
	} else if (ops->cgroup_pattern) {
		__do_free char *cgroup_tree = NULL;

		cgroup_tree = lxc_string_replace("%n", handler->name, ops->cgroup_pattern);
		if (!cgroup_tree)
			return ret_set_errno(false, ENOMEM);

		limit_cgroup = must_concat(&len, cgroup_tree, "/",
					   DEFAULT_PAYLOAD_CGROUP,
					   CGROUP_CREATE_RETRY, NULL);
		container_cgroup = limit_cgroup;
	} else {
		limit_cgroup = must_concat(&len, DEFAULT_PAYLOAD_CGROUP_PREFIX,
					   handler->name,
					   CGROUP_CREATE_RETRY, NULL);
		container_cgroup = limit_cgroup;
	}
	if (!limit_cgroup)
		return ret_set_errno(false, ENOMEM);

	if (!conf->cgroup_meta.container_dir) {
		suffix = container_cgroup + len - CGROUP_CREATE_RETRY_LEN;
		*suffix = '\0';
	}
	do {
		if (idx && suffix)
			sprintf(suffix, "-%d", idx);

		for (i = 0; ops->hierarchies[i]; i++) {
			if (cgroup_tree_create(ops, handler->conf,
					       ops->hierarchies[i], limit_cgroup,
					       conf->cgroup_meta.namespace_dir,
					       true))
				continue;

			DEBUG("Failed to create cgroup \"%s\"", ops->hierarchies[i]->path_con ?: "(null)");
			for (int j = 0; j <= i; j++)
				cgroup_tree_prune_leaf(ops->hierarchies[j],
						       limit_cgroup, true);

			idx++;
			break;
		}
	} while (ops->hierarchies[i] && idx > 0 && idx < 1000 && suffix);

	if (idx == 1000 || (!suffix && idx != 0))
		return log_error_errno(false, ERANGE, "Failed to create container cgroup");

	ops->container_cgroup = move_ptr(container_cgroup);
	if (__limit_cgroup)
		ops->container_limit_cgroup = move_ptr(__limit_cgroup);
	else
		ops->container_limit_cgroup = ops->container_cgroup;
	INFO("The container process uses \"%s\" as inner and \"%s\" as limit cgroup",
	     ops->container_cgroup, ops->container_limit_cgroup);
	return true;
}

__cgfsng_ops static bool cgfsng_monitor_enter(struct cgroup_ops *ops,
					      struct lxc_handler *handler)
{
	int monitor_len, transient_len = 0;
	char monitor[INTTYPE_TO_STRLEN(pid_t)],
	    transient[INTTYPE_TO_STRLEN(pid_t)];

	if (!ops)
		return ret_set_errno(false, ENOENT);

	if (!ops->hierarchies)
		return true;

	if (!ops->monitor_cgroup)
		return ret_set_errno(false, ENOENT);

	if (!handler || !handler->conf)
		return ret_set_errno(false, EINVAL);

	monitor_len = strnprintf(monitor, sizeof(monitor), "%d", handler->monitor_pid);
	if (monitor_len < 0)
		return false;

	if (handler->transient_pid > 0) {
		transient_len = strnprintf(transient, sizeof(transient), "%d", handler->transient_pid);
		if (transient_len < 0)
			return false;
	}

	for (int i = 0; ops->hierarchies[i]; i++) {
		struct hierarchy *h = ops->hierarchies[i];
		int ret;

		ret = lxc_writeat(h->dfd_mon, "cgroup.procs", monitor, monitor_len);
		if (ret)
			return log_error_errno(false, errno, "Failed to enter cgroup %d", h->dfd_mon);

		TRACE("Moved monitor into cgroup %d", h->dfd_mon);

		if (handler->transient_pid <= 0)
			continue;

		ret = lxc_writeat(h->dfd_mon, "cgroup.procs", transient, transient_len);
		if (ret)
			return log_error_errno(false, errno, "Failed to enter cgroup %d", h->dfd_mon);

		TRACE("Moved transient process into cgroup %d", h->dfd_mon);

		/*
		 * we don't keep the fds for non-unified hierarchies around
		 * mainly because we don't make use of them anymore after the
		 * core cgroup setup is done but also because there are quite a
		 * lot of them.
		 */
		if (!is_unified_hierarchy(h))
			close_prot_errno_disarm(h->dfd_mon);
	}
	handler->transient_pid = -1;

	return true;
}

__cgfsng_ops static bool cgfsng_payload_enter(struct cgroup_ops *ops,
					      struct lxc_handler *handler)
{
	int len;
	char pidstr[INTTYPE_TO_STRLEN(pid_t)];

	if (!ops)
		return ret_set_errno(false, ENOENT);

	if (!ops->hierarchies)
		return true;

	if (!ops->container_cgroup)
		return ret_set_errno(false, ENOENT);

	if (!handler || !handler->conf)
		return ret_set_errno(false, EINVAL);

	len = strnprintf(pidstr, sizeof(pidstr), "%d", handler->pid);
	if (len < 0)
		return false;

	for (int i = 0; ops->hierarchies[i]; i++) {
		struct hierarchy *h = ops->hierarchies[i];
		int ret;

		if (is_unified_hierarchy(h) &&
		    (handler->clone_flags & CLONE_INTO_CGROUP))
			continue;

		ret = lxc_writeat(h->dfd_con, "cgroup.procs", pidstr, len);
		if (ret != 0)
			return log_error_errno(false, errno, "Failed to enter cgroup \"%s\"", h->path_con);

		TRACE("Moved container into %s cgroup via %d", h->path_con, h->dfd_con);
	}

	return true;
}

static int fchowmodat(int dirfd, const char *path, uid_t chown_uid,
		      gid_t chown_gid, mode_t chmod_mode)
{
	int ret;

	ret = fchownat(dirfd, path, chown_uid, chown_gid,
		       AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
	if (ret < 0)
		return log_warn_errno(-1,
				      errno, "Failed to fchownat(%d, %s, %d, %d, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW )",
				      dirfd, path, (int)chown_uid,
				      (int)chown_gid);

	ret = fchmodat(dirfd, (*path != '\0') ? path : ".", chmod_mode, 0);
	if (ret < 0)
		return log_warn_errno(-1, errno, "Failed to fchmodat(%d, %s, %d, AT_SYMLINK_NOFOLLOW)",
				      dirfd, path, (int)chmod_mode);

	return 0;
}

/* chgrp the container cgroups to container group.  We leave
 * the container owner as cgroup owner.  So we must make the
 * directories 775 so that the container can create sub-cgroups.
 *
 * Also chown the tasks and cgroup.procs files.  Those may not
 * exist depending on kernel version.
 */
static int chown_cgroup_wrapper(void *data)
{
	int ret;
	uid_t destuid;
	struct generic_userns_exec_data *arg = data;
	uid_t nsuid = (arg->conf->root_nsuid_map != NULL) ? 0 : arg->conf->init_uid;
	gid_t nsgid = (arg->conf->root_nsgid_map != NULL) ? 0 : arg->conf->init_gid;

	if (!lxc_drop_groups() && errno != EPERM)
		return log_error_errno(-1, errno, "Failed to setgroups(0, NULL)");

	ret = setresgid(nsgid, nsgid, nsgid);
	if (ret < 0)
		return log_error_errno(-1, errno, "Failed to setresgid(%d, %d, %d)",
				       (int)nsgid, (int)nsgid, (int)nsgid);

	ret = setresuid(nsuid, nsuid, nsuid);
	if (ret < 0)
		return log_error_errno(-1, errno, "Failed to setresuid(%d, %d, %d)",
				       (int)nsuid, (int)nsuid, (int)nsuid);

	destuid = get_ns_uid(arg->origuid);
	if (destuid == LXC_INVALID_UID)
		destuid = 0;

	for (int i = 0; arg->hierarchies[i]; i++) {
		int dirfd = arg->hierarchies[i]->dfd_con;

		if (dirfd < 0)
			return syserror_set(-EBADF, "Invalid cgroup file descriptor");

		(void)fchowmodat(dirfd, "", destuid, nsgid, 0775);

		/*
		 * Failures to chown() these are inconvenient but not
		 * detrimental We leave these owned by the container launcher,
		 * so that container root can write to the files to attach.  We
		 * chmod() them 664 so that container systemd can write to the
		 * files (which systemd in wily insists on doing).
		 */

		if (arg->hierarchies[i]->fs_type == LEGACY_HIERARCHY)
			(void)fchowmodat(dirfd, "tasks", destuid, nsgid, 0664);

		(void)fchowmodat(dirfd, "cgroup.procs", destuid, nsgid, 0664);

		if (arg->hierarchies[i]->fs_type != UNIFIED_HIERARCHY)
			continue;

		for (char **p = arg->hierarchies[i]->delegate; p && *p; p++)
			(void)fchowmodat(dirfd, *p, destuid, nsgid, 0664);
	}

	return 0;
}

__cgfsng_ops static bool cgfsng_chown(struct cgroup_ops *ops,
				      struct lxc_conf *conf)
{
	struct generic_userns_exec_data wrap;

	if (!ops)
		return ret_set_errno(false, ENOENT);

	if (!ops->hierarchies)
		return true;

	if (!ops->container_cgroup)
		return ret_set_errno(false, ENOENT);

	if (!conf)
		return ret_set_errno(false, EINVAL);

	if (lxc_list_empty(&conf->id_map))
		return true;

	wrap.origuid = geteuid();
	wrap.path = NULL;
	wrap.hierarchies = ops->hierarchies;
	wrap.conf = conf;

	if (userns_exec_1(conf, chown_cgroup_wrapper, &wrap, "chown_cgroup_wrapper") < 0)
		return log_error_errno(false, errno, "Error requesting cgroup chown in new user namespace");

	return true;
}

__cgfsng_ops static void cgfsng_finalize(struct cgroup_ops *ops)
{
	if (!ops)
		return;

	if (!ops->hierarchies)
		return;

	for (int i = 0; ops->hierarchies[i]; i++) {
		struct hierarchy *h = ops->hierarchies[i];

		/* Close all monitor cgroup file descriptors. */
		close_prot_errno_disarm(h->dfd_mon);
	}
	/* Close the cgroup root file descriptor. */
	close_prot_errno_disarm(ops->dfd_mnt);

	/*
	 * The checking for freezer support should obviously be done at cgroup
	 * initialization time but that doesn't work reliable. The freezer
	 * controller has been demoted (rightly so) to a simple file located in
	 * each non-root cgroup. At the time when the container is created we
	 * might still be located in /sys/fs/cgroup and so checking for
	 * cgroup.freeze won't tell us anything because this file doesn't exist
	 * in the root cgroup. We could then iterate through /sys/fs/cgroup and
	 * find an already existing cgroup and then check within that cgroup
	 * for the existence of cgroup.freeze but that will only work on
	 * systemd based hosts. Other init systems might not manage cgroups and
	 * so no cgroup will exist. So we defer until we have created cgroups
	 * for our container which means we check here.
	 */
        if (pure_unified_layout(ops) &&
            !faccessat(ops->unified->dfd_con, "cgroup.freeze", F_OK,
                       AT_SYMLINK_NOFOLLOW)) {
		TRACE("Unified hierarchy supports freezer");
		ops->unified->utilities |= FREEZER_CONTROLLER;
        }
}

/* cgroup-full:* is done, no need to create subdirs */
static inline bool cg_mount_needs_subdirs(int cgroup_automount_type)
{
	switch (cgroup_automount_type) {
	case LXC_AUTO_CGROUP_RO:
		return true;
	case LXC_AUTO_CGROUP_RW:
		return true;
	case LXC_AUTO_CGROUP_MIXED:
		return true;
	}

	return false;
}

/* After $rootfs/sys/fs/container/controller/the/cg/path has been created,
 * remount controller ro if needed and bindmount the cgroupfs onto
 * control/the/cg/path.
 */
static int cg_legacy_mount_controllers(int cgroup_automount_type, struct hierarchy *h,
				       char *hierarchy_mnt, char *cgpath,
				       const char *container_cgroup)
{
	__do_free char *sourcepath = NULL;
	int ret, remount_flags;
	int flags = MS_BIND;

	if ((cgroup_automount_type == LXC_AUTO_CGROUP_RO) ||
	    (cgroup_automount_type == LXC_AUTO_CGROUP_MIXED)) {
		ret = mount(hierarchy_mnt, hierarchy_mnt, "cgroup", MS_BIND, NULL);
		if (ret < 0)
			return log_error_errno(-1, errno, "Failed to bind mount \"%s\" onto \"%s\"",
					       hierarchy_mnt, hierarchy_mnt);

		remount_flags = add_required_remount_flags(hierarchy_mnt,
							   hierarchy_mnt,
							   flags | MS_REMOUNT);
		ret = mount(hierarchy_mnt, hierarchy_mnt, "cgroup",
			    remount_flags | MS_REMOUNT | MS_BIND | MS_RDONLY,
			    NULL);
		if (ret < 0)
			return log_error_errno(-1, errno, "Failed to remount \"%s\" ro", hierarchy_mnt);

		INFO("Remounted %s read-only", hierarchy_mnt);
	}

	sourcepath = make_cgroup_path(h, h->at_base, container_cgroup, NULL);
	if (cgroup_automount_type == LXC_AUTO_CGROUP_RO)
		flags |= MS_RDONLY;

	ret = mount(sourcepath, cgpath, "cgroup", flags, NULL);
	if (ret < 0)
		return log_error_errno(-1, errno, "Failed to mount \"%s\" onto \"%s\"",
				       h->controllers[0], cgpath);
	INFO("Mounted \"%s\" onto \"%s\"", h->controllers[0], cgpath);

	if (flags & MS_RDONLY) {
		remount_flags = add_required_remount_flags(sourcepath, cgpath,
							   flags | MS_REMOUNT);
		ret = mount(sourcepath, cgpath, "cgroup", remount_flags, NULL);
		if (ret < 0)
			return log_error_errno(-1, errno, "Failed to remount \"%s\" ro", cgpath);
		INFO("Remounted %s read-only", cgpath);
	}

	INFO("Completed second stage cgroup automounts for \"%s\"", cgpath);
	return 0;
}

/* __cgroupfs_mount
 *
 * Mount cgroup hierarchies directly without using bind-mounts. The main
 * uses-cases are mounting cgroup hierarchies in cgroup namespaces and mounting
 * cgroups for the LXC_AUTO_CGROUP_FULL option.
 */
static int __cgroupfs_mount(int cgroup_automount_type, struct hierarchy *h,
			    struct lxc_rootfs *rootfs, int dfd_mnt_cgroupfs,
			    const char *hierarchy_mnt)
{
	__do_close int fd_fs = -EBADF;
	unsigned int flags = 0;
	char *fstype;
	int ret;

	if (dfd_mnt_cgroupfs < 0)
		return ret_errno(EINVAL);

	flags |= MOUNT_ATTR_NOSUID;
	flags |= MOUNT_ATTR_NOEXEC;
	flags |= MOUNT_ATTR_NODEV;
	flags |= MOUNT_ATTR_RELATIME;

	if ((cgroup_automount_type == LXC_AUTO_CGROUP_RO) ||
	    (cgroup_automount_type == LXC_AUTO_CGROUP_FULL_RO))
		flags |= MOUNT_ATTR_RDONLY;

	if (is_unified_hierarchy(h))
		fstype = "cgroup2";
	else
		fstype = "cgroup";

	if (can_use_mount_api()) {
		fd_fs = fs_prepare(fstype, -EBADF, "", 0, 0);
		if (fd_fs < 0)
			return log_error_errno(-errno, errno, "Failed to prepare filesystem context for %s", fstype);

		if (!is_unified_hierarchy(h)) {
			for (const char **it = (const char **)h->controllers; it && *it; it++) {
				if (strnequal(*it, "name=", STRLITERALLEN("name=")))
					ret = fs_set_property(fd_fs, "name", *it + STRLITERALLEN("name="));
				else
					ret = fs_set_property(fd_fs, *it, "");
				if (ret < 0)
					return log_error_errno(-errno, errno, "Failed to add %s controller to cgroup filesystem context %d(dev)", *it, fd_fs);
			}
		}

		ret = fs_attach(fd_fs, dfd_mnt_cgroupfs, hierarchy_mnt,
				PROTECT_OPATH_DIRECTORY, PROTECT_LOOKUP_BENEATH,
				flags);
	} else {
		__do_free char *controllers = NULL, *target = NULL;
		unsigned int old_flags = 0;
		const char *rootfs_mnt;

		if (!is_unified_hierarchy(h)) {
			controllers = lxc_string_join(",", (const char **)h->controllers, false);
			if (!controllers)
				return ret_errno(ENOMEM);
		}

		rootfs_mnt = get_rootfs_mnt(rootfs);
		ret = mnt_attributes_old(flags, &old_flags);
		if (ret)
			return log_error_errno(-EINVAL, EINVAL, "Unsupported mount properties specified");

		target = must_make_path(rootfs_mnt, DEFAULT_CGROUP_MOUNTPOINT, hierarchy_mnt, NULL);
		ret = safe_mount(NULL, target, fstype, old_flags, controllers, rootfs_mnt);
	}
	if (ret < 0)
		return log_error_errno(ret, errno, "Failed to mount %s filesystem onto %d(%s)",
				       fstype, dfd_mnt_cgroupfs, maybe_empty(hierarchy_mnt));

	DEBUG("Mounted cgroup filesystem %s onto %d(%s)",
	      fstype, dfd_mnt_cgroupfs, maybe_empty(hierarchy_mnt));
	return 0;
}

static inline int cgroupfs_mount(int cgroup_automount_type, struct hierarchy *h,
				 struct lxc_rootfs *rootfs,
				 int dfd_mnt_cgroupfs, const char *hierarchy_mnt)
{
	return __cgroupfs_mount(cgroup_automount_type, h, rootfs,
				dfd_mnt_cgroupfs, hierarchy_mnt);
}

static inline int cgroupfs_bind_mount(int cgroup_automount_type, struct hierarchy *h,
				      struct lxc_rootfs *rootfs,
				      int dfd_mnt_cgroupfs,
				      const char *hierarchy_mnt)
{
	switch (cgroup_automount_type) {
	case LXC_AUTO_CGROUP_FULL_RO:
		break;
	case LXC_AUTO_CGROUP_FULL_RW:
		break;
	case LXC_AUTO_CGROUP_FULL_MIXED:
		break;
	default:
		return 0;
	}

	return __cgroupfs_mount(cgroup_automount_type, h, rootfs,
				dfd_mnt_cgroupfs, hierarchy_mnt);
}

__cgfsng_ops static bool cgfsng_mount(struct cgroup_ops *ops,
				      struct lxc_handler *handler, int cg_flags)
{
	__do_close int dfd_mnt_tmpfs = -EBADF, fd_fs = -EBADF;
	__do_free char *cgroup_root = NULL;
	int cgroup_automount_type;
	bool in_cgroup_ns = false, wants_force_mount = false;
	struct lxc_conf *conf = handler->conf;
	struct lxc_rootfs *rootfs = &conf->rootfs;
	const char *rootfs_mnt = get_rootfs_mnt(rootfs);
	int ret;

	if (!ops)
		return ret_set_errno(false, ENOENT);

	if (!ops->hierarchies)
		return true;

	if (!conf)
		return ret_set_errno(false, EINVAL);

	if ((cg_flags & LXC_AUTO_CGROUP_MASK) == 0)
		return log_trace(true, "No cgroup mounts requested");

	if (cg_flags & LXC_AUTO_CGROUP_FORCE) {
		cg_flags &= ~LXC_AUTO_CGROUP_FORCE;
		wants_force_mount = true;
	}

	switch (cg_flags) {
	case LXC_AUTO_CGROUP_RO:
		TRACE("Read-only cgroup mounts requested");
		break;
	case LXC_AUTO_CGROUP_RW:
		TRACE("Read-write cgroup mounts requested");
		break;
	case LXC_AUTO_CGROUP_MIXED:
		TRACE("Mixed cgroup mounts requested");
		break;
	case LXC_AUTO_CGROUP_FULL_RO:
		TRACE("Full read-only cgroup mounts requested");
		break;
	case LXC_AUTO_CGROUP_FULL_RW:
		TRACE("Full read-write cgroup mounts requested");
		break;
	case LXC_AUTO_CGROUP_FULL_MIXED:
		TRACE("Full mixed cgroup mounts requested");
		break;
	default:
		return log_error_errno(false, EINVAL, "Invalid cgroup mount options specified");
	}
	cgroup_automount_type = cg_flags;

	if (!wants_force_mount) {
		wants_force_mount = !lxc_wants_cap(CAP_SYS_ADMIN, conf);

		/*
		 * Most recent distro versions currently have init system that
		 * do support cgroup2 but do not mount it by default unless
		 * explicitly told so even if the host is cgroup2 only. That
		 * means they often will fail to boot. Fix this by pre-mounting
		 * cgroup2 by default. We will likely need to be doing this a
		 * few years until all distros have switched over to cgroup2 at
		 * which point we can safely assume that their init systems
		 * will mount it themselves.
		 */
		if (pure_unified_layout(ops))
			wants_force_mount = true;
	}

	if (cgns_supported() && container_uses_namespace(handler, CLONE_NEWCGROUP))
		in_cgroup_ns = true;

	if (in_cgroup_ns && !wants_force_mount)
		return log_trace(true, "Mounting cgroups not requested or needed");

	/* This is really the codepath that we want. */
	if (pure_unified_layout(ops)) {
		__do_close int dfd_mnt_unified = -EBADF;

		dfd_mnt_unified = open_at(rootfs->dfd_mnt, DEFAULT_CGROUP_MOUNTPOINT_RELATIVE,
					  PROTECT_OPATH_DIRECTORY, PROTECT_LOOKUP_BENEATH_XDEV, 0);
		if (dfd_mnt_unified < 0)
			return syserror_ret(false, "Failed to open %d(%s)",
					    rootfs->dfd_mnt, DEFAULT_CGROUP_MOUNTPOINT_RELATIVE);
		/*
		 * If cgroup namespaces are supported but the container will
		 * not have CAP_SYS_ADMIN after it has started we need to mount
		 * the cgroups manually.
		 *
		 * Note that here we know that wants_force_mount is true.
		 * Otherwise we would've returned early above.
		 */
		if (in_cgroup_ns) {
			/*
			 *  1. cgroup:rw:force    -> Mount the cgroup2 filesystem.
			 *  2. cgroup:ro:force    -> Mount the cgroup2 filesystem read-only.
			 *  3. cgroup:mixed:force -> See comment above how this
			 *                           does not apply so
			 *                           cgroup:mixed is equal to
			 *                           cgroup:rw when cgroup
			 *                           namespaces are supported.

			 *  4. cgroup:rw    -> No-op; init system responsible for mounting.
			 *  5. cgroup:ro    -> No-op; init system responsible for mounting.
			 *  6. cgroup:mixed -> No-op; init system responsible for mounting.
                         *
			 *  7. cgroup-full:rw    -> Not supported.
			 *  8. cgroup-full:ro    -> Not supported.
			 *  9. cgroup-full:mixed -> Not supported.

			 * 10. cgroup-full:rw:force    -> Not supported.
			 * 11. cgroup-full:ro:force    -> Not supported.
			 * 12. cgroup-full:mixed:force -> Not supported.
			 */
			ret = cgroupfs_mount(cgroup_automount_type, ops->unified, rootfs, dfd_mnt_unified, "");
			if (ret < 0)
				return syserror_ret(false, "Failed to force mount cgroup filesystem in cgroup namespace");

			return log_trace(true, "Force mounted cgroup filesystem in new cgroup namespace");
		} else {
			/*
			 * Either no cgroup namespace supported (highly
			 * unlikely unless we're dealing with a Frankenkernel.
			 * Or the user requested to keep the cgroup namespace
			 * of the host or another container.
			 */
			if (wants_force_mount) {
				/*
				 * 1. cgroup:rw:force    -> Bind-mount the cgroup2 filesystem writable.
				 * 2. cgroup:ro:force    -> Bind-mount the cgroup2 filesystem read-only.
				 * 3. cgroup:mixed:force -> bind-mount the cgroup2 filesystem and
				 *                          and make the parent directory of the
				 *                          container's cgroup read-only but the
				 *                          container's cgroup writable.
                                 *
				 * 10. cgroup-full:rw:force    ->
				 * 11. cgroup-full:ro:force    ->
				 * 12. cgroup-full:mixed:force ->
				 */
				errno = EOPNOTSUPP;
				SYSWARN("Force-mounting the unified cgroup hierarchy without cgroup namespace support is currently not supported");
			} else {
				errno = EOPNOTSUPP;
				SYSWARN("Mounting the unified cgroup hierarchy without cgroup namespace support is currently not supported");
			}
		}

		return syserror_ret(false, "Failed to mount cgroups");
	}

	/*
	 * Mount a tmpfs over DEFAULT_CGROUP_MOUNTPOINT. Note that we're
	 * relying on RESOLVE_BENEATH so we need to skip the leading "/" in the
	 * DEFAULT_CGROUP_MOUNTPOINT define.
	 */
	if (can_use_mount_api()) {
		fd_fs = fs_prepare("tmpfs", -EBADF, "", 0, 0);
		if (fd_fs < 0)
			return log_error_errno(-errno, errno, "Failed to create new filesystem context for tmpfs");

		ret = fs_set_property(fd_fs, "mode", "0755");
		if (ret < 0)
			return log_error_errno(-errno, errno, "Failed to mount tmpfs onto %d(dev)", fd_fs);

		ret = fs_set_property(fd_fs, "size", "10240k");
		if (ret < 0)
			return log_error_errno(-errno, errno, "Failed to mount tmpfs onto %d(dev)", fd_fs);

		ret = fs_attach(fd_fs, rootfs->dfd_mnt, DEFAULT_CGROUP_MOUNTPOINT_RELATIVE,
				PROTECT_OPATH_DIRECTORY, PROTECT_LOOKUP_BENEATH_XDEV,
				MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV |
				MOUNT_ATTR_NOEXEC | MOUNT_ATTR_RELATIME);
	} else {
		cgroup_root = must_make_path(rootfs_mnt, DEFAULT_CGROUP_MOUNTPOINT, NULL);
		ret = safe_mount(NULL, cgroup_root, "tmpfs",
				 MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME,
				 "size=10240k,mode=755", rootfs_mnt);
	}
	if (ret < 0)
		return log_error_errno(false, errno, "Failed to mount tmpfs on %s",
				       DEFAULT_CGROUP_MOUNTPOINT_RELATIVE);

	dfd_mnt_tmpfs = open_at(rootfs->dfd_mnt, DEFAULT_CGROUP_MOUNTPOINT_RELATIVE,
				PROTECT_OPATH_DIRECTORY, PROTECT_LOOKUP_BENEATH_XDEV, 0);
	if (dfd_mnt_tmpfs < 0)
		return syserror_ret(false, "Failed to open %d(%s)",
				    rootfs->dfd_mnt, DEFAULT_CGROUP_MOUNTPOINT_RELATIVE);

	for (int i = 0; ops->hierarchies[i]; i++) {
		__do_free char *hierarchy_mnt = NULL, *path2 = NULL;
		struct hierarchy *h = ops->hierarchies[i];

		ret = mkdirat(dfd_mnt_tmpfs, h->at_mnt, 0000);
		if (ret < 0)
			return syserror_ret(false, "Failed to create cgroup at_mnt %d(%s)", dfd_mnt_tmpfs, h->at_mnt);

		if (in_cgroup_ns && wants_force_mount) {
			/*
			 * If cgroup namespaces are supported but the container
			 * will not have CAP_SYS_ADMIN after it has started we
			 * need to mount the cgroups manually.
			 */
			ret = cgroupfs_mount(cgroup_automount_type, h, rootfs,
					     dfd_mnt_tmpfs, h->at_mnt);
			if (ret < 0)
				return false;

			continue;
		}

		/* Here is where the ancient kernel section begins. */
		ret = cgroupfs_bind_mount(cgroup_automount_type, h, rootfs,
					  dfd_mnt_tmpfs, h->at_mnt);
		if (ret < 0)
			return false;

		if (!cg_mount_needs_subdirs(cgroup_automount_type))
			continue;

		if (!cgroup_root)
			cgroup_root = must_make_path(rootfs_mnt, DEFAULT_CGROUP_MOUNTPOINT, NULL);

		hierarchy_mnt = must_make_path(cgroup_root, h->at_mnt, NULL);
		path2 = must_make_path(hierarchy_mnt, h->at_base,
				       ops->container_cgroup, NULL);
		ret = mkdir_p(path2, 0755);
		if (ret < 0 && (errno != EEXIST))
			return false;

		ret = cg_legacy_mount_controllers(cgroup_automount_type, h,
						  hierarchy_mnt, path2,
						  ops->container_cgroup);
		if (ret < 0)
			return false;
	}

	return true;
}

/* Only root needs to escape to the cgroup of its init. */
__cgfsng_ops static bool cgfsng_criu_escape(const struct cgroup_ops *ops,
					    struct lxc_conf *conf)
{
	if (!ops)
		return ret_set_errno(false, ENOENT);

	if (!ops->hierarchies)
		return true;

	if (!conf)
		return ret_set_errno(false, EINVAL);

	if (conf->cgroup_meta.relative || geteuid())
		return true;

	for (int i = 0; ops->hierarchies[i]; i++) {
		__do_free char *fullpath = NULL;
		int ret;

		fullpath = make_cgroup_path(ops->hierarchies[i],
					    ops->hierarchies[i]->at_base,
					    "cgroup.procs", NULL);
		ret = lxc_write_to_file(fullpath, "0", 2, false, 0666);
		if (ret != 0)
			return log_error_errno(false, errno, "Failed to escape to cgroup \"%s\"", fullpath);
	}

	return true;
}

__cgfsng_ops static int cgfsng_criu_num_hierarchies(struct cgroup_ops *ops)
{
	int i = 0;

	if (!ops)
		return ret_set_errno(-1, ENOENT);

	if (!ops->hierarchies)
		return 0;

	for (; ops->hierarchies[i]; i++)
		;

	return i;
}

__cgfsng_ops static bool cgfsng_criu_get_hierarchies(struct cgroup_ops *ops,
						     int n, char ***out)
{
	int i;

	if (!ops)
		return ret_set_errno(false, ENOENT);

	if (!ops->hierarchies)
		return ret_set_errno(false, ENOENT);

	/* consistency check n */
	for (i = 0; i < n; i++)
		if (!ops->hierarchies[i])
			return ret_set_errno(false, ENOENT);

	*out = ops->hierarchies[i]->controllers;

	return true;
}

static int cg_legacy_freeze(struct cgroup_ops *ops)
{
	struct hierarchy *h;

	h = get_hierarchy(ops, "freezer");
	if (!h)
		return ret_set_errno(-1, ENOENT);

	return lxc_write_openat(h->path_con, "freezer.state",
				"FROZEN", STRLITERALLEN("FROZEN"));
}

static int freezer_cgroup_events_cb(int fd, uint32_t events, void *cbdata,
				    struct lxc_epoll_descr *descr)
{
	__do_free char *line = NULL;
	__do_fclose FILE *f = NULL;
	int state = PTR_TO_INT(cbdata);
	size_t len;
	const char *state_string;

	f = fdopen_at(fd, "", "re", PROTECT_OPEN, PROTECT_LOOKUP_BENEATH);
	if (!f)
		return LXC_MAINLOOP_ERROR;

	if (state == 1)
		state_string = "frozen 1";
	else
		state_string = "frozen 0";

	while (getline(&line, &len, f) != -1)
		if (strnequal(line, state_string, STRLITERALLEN("frozen") + 2))
			return LXC_MAINLOOP_CLOSE;

	rewind(f);

	return LXC_MAINLOOP_CONTINUE;
}

static int cg_unified_freeze_do(struct cgroup_ops *ops, int timeout,
				const char *state_string,
				int state_num,
				const char *epoll_error,
				const char *wait_error)
{
	__do_close int fd = -EBADF;
	call_cleaner(lxc_mainloop_close) struct lxc_epoll_descr *descr_ptr = NULL;
	int ret;
	struct lxc_epoll_descr descr;
	struct hierarchy *h;

	h = ops->unified;
	if (!h)
		return ret_set_errno(-1, ENOENT);

	if (!h->path_con)
		return ret_set_errno(-1, EEXIST);

	if (timeout != 0) {
		__do_free char *events_file = NULL;

		events_file = must_make_path(h->path_con, "cgroup.events", NULL);
		fd = open(events_file, O_RDONLY | O_CLOEXEC);
		if (fd < 0)
			return log_error_errno(-1, errno, "Failed to open cgroup.events file");

		ret = lxc_mainloop_open(&descr);
		if (ret)
			return log_error_errno(-1, errno, "%s", epoll_error);

		/* automatically cleaned up now */
		descr_ptr = &descr;

		ret = lxc_mainloop_add_handler_events(&descr, fd, EPOLLPRI, freezer_cgroup_events_cb, INT_TO_PTR(state_num));
		if (ret < 0)
			return log_error_errno(-1, errno, "Failed to add cgroup.events fd handler to mainloop");
	}

	ret = lxc_write_openat(h->path_con, "cgroup.freeze", state_string, 1);
	if (ret < 0)
		return log_error_errno(-1, errno, "Failed to open cgroup.freeze file");

	if (timeout != 0 && lxc_mainloop(&descr, timeout))
		return log_error_errno(-1, errno, "%s", wait_error);

	return 0;
}

static int cg_unified_freeze(struct cgroup_ops *ops, int timeout)
{
	return cg_unified_freeze_do(ops, timeout, "1", 1,
		"Failed to create epoll instance to wait for container freeze",
		"Failed to wait for container to be frozen");
}

__cgfsng_ops static int cgfsng_freeze(struct cgroup_ops *ops, int timeout)
{
	if (!ops->hierarchies)
		return ret_set_errno(-1, ENOENT);

	if (ops->cgroup_layout != CGROUP_LAYOUT_UNIFIED)
		return cg_legacy_freeze(ops);

	return cg_unified_freeze(ops, timeout);
}

static int cg_legacy_unfreeze(struct cgroup_ops *ops)
{
	struct hierarchy *h;

	h = get_hierarchy(ops, "freezer");
	if (!h)
		return ret_set_errno(-1, ENOENT);

	return lxc_write_openat(h->path_con, "freezer.state",
				"THAWED", STRLITERALLEN("THAWED"));
}

static int cg_unified_unfreeze(struct cgroup_ops *ops, int timeout)
{
	return cg_unified_freeze_do(ops, timeout, "0", 0,
		"Failed to create epoll instance to wait for container unfreeze",
		"Failed to wait for container to be unfrozen");
}

__cgfsng_ops static int cgfsng_unfreeze(struct cgroup_ops *ops, int timeout)
{
	if (!ops->hierarchies)
		return ret_set_errno(-1, ENOENT);

	if (ops->cgroup_layout != CGROUP_LAYOUT_UNIFIED)
		return cg_legacy_unfreeze(ops);

	return cg_unified_unfreeze(ops, timeout);
}

static const char *cgfsng_get_cgroup_do(struct cgroup_ops *ops,
					const char *controller, bool limiting)
{
	struct hierarchy *h;
	size_t len;
	const char *path;

	h = get_hierarchy(ops, controller);
	if (!h)
		return log_warn_errno(NULL, ENOENT,
				      "Failed to find hierarchy for controller \"%s\"", maybe_empty(controller));

	if (limiting)
		path = h->path_lim;
	else
		path = h->path_con;
	if (!path)
		return NULL;

	len = strlen(h->at_mnt);
	if (!strnequal(h->at_mnt, DEFAULT_CGROUP_MOUNTPOINT,
		       STRLITERALLEN(DEFAULT_CGROUP_MOUNTPOINT))) {
		path += STRLITERALLEN(DEFAULT_CGROUP_MOUNTPOINT);
		path += strspn(path, "/");
	}
	return path += len;
}

__cgfsng_ops static const char *cgfsng_get_cgroup(struct cgroup_ops *ops,
						  const char *controller)
{
    return cgfsng_get_cgroup_do(ops, controller, false);
}

__cgfsng_ops static const char *cgfsng_get_limit_cgroup(struct cgroup_ops *ops,
							const char *controller)
{
    return cgfsng_get_cgroup_do(ops, controller, true);
}

/* Given a cgroup path returned from lxc_cmd_get_cgroup_path, build a full path,
 * which must be freed by the caller.
 */
static inline char *build_full_cgpath_from_monitorpath(struct hierarchy *h,
						       const char *inpath,
						       const char *filename)
{
	return make_cgroup_path(h, inpath, filename, NULL);
}

static int cgroup_attach_leaf(const struct lxc_conf *conf, int unified_fd, pid_t pid)
{
	int idx = 1;
	int ret;
	char pidstr[INTTYPE_TO_STRLEN(int64_t) + 1];
	ssize_t pidstr_len;

	/* Create leaf cgroup. */
	ret = mkdirat(unified_fd, ".lxc", 0755);
	if (ret < 0 && errno != EEXIST)
		return log_error_errno(-errno, errno, "Failed to create leaf cgroup \".lxc\"");

	pidstr_len = strnprintf(pidstr, sizeof(pidstr), INT64_FMT, (int64_t)pid);
	if (pidstr_len < 0)
		return pidstr_len;

	ret = lxc_writeat(unified_fd, ".lxc/cgroup.procs", pidstr, pidstr_len);
	if (ret < 0)
		ret = lxc_writeat(unified_fd, "cgroup.procs", pidstr, pidstr_len);
	if (ret == 0)
		return log_trace(0, "Moved process %s into cgroup %d(.lxc)", pidstr, unified_fd);

	/* this is a non-leaf node */
	if (errno != EBUSY)
		return log_error_errno(-errno, errno, "Failed to attach to unified cgroup");

	do {
		bool rm = false;
		char attach_cgroup[STRLITERALLEN(".lxc-/cgroup.procs") + INTTYPE_TO_STRLEN(int) + 1];
		char *slash = attach_cgroup;

		ret = strnprintf(attach_cgroup, sizeof(attach_cgroup), ".lxc-%d/cgroup.procs", idx);
		if (ret < 0)
			return ret;

		/*
		 * This shouldn't really happen but the compiler might complain
		 * that a short write would cause a buffer overrun. So be on
		 * the safe side.
		 */
		if (ret < STRLITERALLEN(".lxc-/cgroup.procs"))
			return log_error_errno(-EINVAL, EINVAL, "Unexpected short write would cause buffer-overrun");

		slash += (ret - STRLITERALLEN("/cgroup.procs"));
		*slash = '\0';

		ret = mkdirat(unified_fd, attach_cgroup, 0755);
		if (ret < 0 && errno != EEXIST)
			return log_error_errno(-1, errno, "Failed to create cgroup %s", attach_cgroup);
		if (ret == 0)
			rm = true;

		*slash = '/';

		ret = lxc_writeat(unified_fd, attach_cgroup, pidstr, pidstr_len);
		if (ret == 0)
			return log_trace(0, "Moved process %s into cgroup %d(%s)", pidstr, unified_fd, attach_cgroup);

		if (rm && unlinkat(unified_fd, attach_cgroup, AT_REMOVEDIR))
			SYSERROR("Failed to remove cgroup \"%d(%s)\"", unified_fd, attach_cgroup);

		/* this is a non-leaf node */
		if (errno != EBUSY)
			return log_error_errno(-1, errno, "Failed to attach to unified cgroup");

		idx++;
	} while (idx < 1000);

	return log_error_errno(-1, errno, "Failed to attach to unified cgroup");
}

static int cgroup_attach_create_leaf(const struct lxc_conf *conf,
				     int unified_fd, int *sk_fd)
{
	__do_close int sk = *sk_fd, target_fd0 = -EBADF, target_fd1 = -EBADF;
	int target_fds[2];
	ssize_t ret;

	/* Create leaf cgroup. */
	ret = mkdirat(unified_fd, ".lxc", 0755);
	if (ret < 0 && errno != EEXIST)
		return log_error_errno(-1, errno, "Failed to create leaf cgroup \".lxc\"");

	target_fd0 = open_at(unified_fd, ".lxc/cgroup.procs", PROTECT_OPEN_W, PROTECT_LOOKUP_BENEATH, 0);
	if (target_fd0 < 0)
		return log_error_errno(-errno, errno, "Failed to open \".lxc/cgroup.procs\"");
	target_fds[0] = target_fd0;

	target_fd1 = open_at(unified_fd, "cgroup.procs", PROTECT_OPEN_W, PROTECT_LOOKUP_BENEATH, 0);
	if (target_fd1 < 0)
		return log_error_errno(-errno, errno, "Failed to open \".lxc/cgroup.procs\"");
	target_fds[1] = target_fd1;

	ret = lxc_abstract_unix_send_fds(sk, target_fds, 2, NULL, 0);
	if (ret <= 0)
		return log_error_errno(-errno, errno, "Failed to send \".lxc/cgroup.procs\" fds %d and %d",
				       target_fd0, target_fd1);

	return log_debug(0, "Sent target cgroup fds %d and %d", target_fd0, target_fd1);
}

static int cgroup_attach_move_into_leaf(const struct lxc_conf *conf,
					int *sk_fd, pid_t pid)
{
	__do_close int sk = *sk_fd, target_fd0 = -EBADF, target_fd1 = -EBADF;
	char pidstr[INTTYPE_TO_STRLEN(int64_t) + 1];
	size_t pidstr_len;
	ssize_t ret;

	ret = lxc_abstract_unix_recv_two_fds(sk, &target_fd0, &target_fd1);
	if (ret < 0)
		return log_error_errno(-1, errno, "Failed to receive target cgroup fd");

	pidstr_len = sprintf(pidstr, INT64_FMT, (int64_t)pid);

	ret = lxc_write_nointr(target_fd0, pidstr, pidstr_len);
	if (ret > 0 && ret == pidstr_len)
		return log_debug(0, "Moved process into target cgroup via fd %d", target_fd0);

	ret = lxc_write_nointr(target_fd1, pidstr, pidstr_len);
	if (ret > 0 && ret == pidstr_len)
		return log_debug(0, "Moved process into target cgroup via fd %d", target_fd1);

	return log_debug_errno(-1, errno, "Failed to move process into target cgroup via fd %d and %d",
			       target_fd0, target_fd1);
}

struct userns_exec_unified_attach_data {
	const struct lxc_conf *conf;
	int unified_fd;
	int sk_pair[2];
	pid_t pid;
};

static int cgroup_unified_attach_child_wrapper(void *data)
{
	struct userns_exec_unified_attach_data *args = data;

	if (!args->conf || args->unified_fd < 0 || args->pid <= 0 ||
	    args->sk_pair[0] < 0 || args->sk_pair[1] < 0)
		return ret_errno(EINVAL);

	close_prot_errno_disarm(args->sk_pair[0]);
	return cgroup_attach_create_leaf(args->conf, args->unified_fd,
					 &args->sk_pair[1]);
}

static int cgroup_unified_attach_parent_wrapper(void *data)
{
	struct userns_exec_unified_attach_data *args = data;

	if (!args->conf || args->unified_fd < 0 || args->pid <= 0 ||
	    args->sk_pair[0] < 0 || args->sk_pair[1] < 0)
		return ret_errno(EINVAL);

	close_prot_errno_disarm(args->sk_pair[1]);
	return cgroup_attach_move_into_leaf(args->conf, &args->sk_pair[0],
					    args->pid);
}

/* Technically, we're always at a delegation boundary here (This is especially
 * true when cgroup namespaces are available.). The reasoning is that in order
 * for us to have been able to start a container in the first place the root
 * cgroup must have been a leaf node. Now, either the container's init system
 * has populated the cgroup and kept it as a leaf node or it has created
 * subtrees. In the former case we will simply attach to the leaf node we
 * created when we started the container in the latter case we create our own
 * cgroup for the attaching process.
 */
static int __cg_unified_attach(const struct hierarchy *h,
			       const struct lxc_conf *conf, const char *name,
			       const char *lxcpath, pid_t pid,
			       const char *controller)
{
	__do_close int unified_fd = -EBADF;
	__do_free char *path = NULL, *cgroup = NULL;
	int ret;

	if (!conf || !name || !lxcpath || pid <= 0)
		return ret_errno(EINVAL);

	ret = cgroup_attach(conf, name, lxcpath, pid);
	if (ret == 0)
		return log_trace(0, "Attached to unified cgroup via command handler");
	if (!ERRNO_IS_NOT_SUPPORTED(ret) && ret != -ENOCGROUP2)
		return log_error_errno(ret, errno, "Failed to attach to unified cgroup");

	/* Fall back to retrieving the path for the unified cgroup. */
	cgroup = lxc_cmd_get_cgroup_path(name, lxcpath, controller);
	/* not running */
	if (!cgroup)
		return 0;

	path = make_cgroup_path(h, cgroup, NULL);

	unified_fd = open(path, O_PATH | O_DIRECTORY | O_CLOEXEC);
	if (unified_fd < 0)
		return ret_errno(EBADF);

	if (!lxc_list_empty(&conf->id_map)) {
		struct userns_exec_unified_attach_data args = {
			.conf		= conf,
			.unified_fd	= unified_fd,
			.pid		= pid,
		};

		ret = socketpair(PF_LOCAL, SOCK_STREAM | SOCK_CLOEXEC, 0, args.sk_pair);
		if (ret < 0)
			return -errno;

		ret = userns_exec_minimal(conf,
					  cgroup_unified_attach_parent_wrapper,
					  &args,
					  cgroup_unified_attach_child_wrapper,
					  &args);
	} else {
		ret = cgroup_attach_leaf(conf, unified_fd, pid);
	}

	return ret;
}

__cgfsng_ops static bool cgfsng_attach(struct cgroup_ops *ops,
				       const struct lxc_conf *conf,
				       const char *name, const char *lxcpath,
				       pid_t pid)
{
	int len, ret;
	char pidstr[INTTYPE_TO_STRLEN(pid_t)];

	if (!ops)
		return ret_set_errno(false, ENOENT);

	if (!ops->hierarchies)
		return true;

	len = strnprintf(pidstr, sizeof(pidstr), "%d", pid);
	if (len < 0)
		return false;

	for (int i = 0; ops->hierarchies[i]; i++) {
		__do_free char *fullpath = NULL, *path = NULL;
		struct hierarchy *h = ops->hierarchies[i];

		if (h->fs_type == UNIFIED_HIERARCHY) {
			ret = __cg_unified_attach(h, conf, name, lxcpath, pid,
						  h->controllers[0]);
			if (ret < 0)
				return false;

			continue;
		}

		path = lxc_cmd_get_cgroup_path(name, lxcpath, h->controllers[0]);
		if (!path) {
			/*
			 * Someone might have created a name=<controller>
			 * controller after the container has started and so
			 * the container doesn't make use of this controller.
			 *
			 * Link: https://github.com/lxc/lxd/issues/8577
			 */
			TRACE("Skipping unused %s controller", maybe_empty(h->controllers[0]));
			continue;
		}

		fullpath = build_full_cgpath_from_monitorpath(h, path, "cgroup.procs");
		ret = lxc_write_to_file(fullpath, pidstr, len, false, 0666);
		if (ret < 0)
			return log_error_errno(false, errno, "Failed to attach %d to %s",
					       (int)pid, fullpath);
	}

	return true;
}

/* Called externally (i.e. from 'lxc-cgroup') to query cgroup limits.  Here we
 * don't have a cgroup_data set up, so we ask the running container through the
 * commands API for the cgroup path.
 */
__cgfsng_ops static int cgfsng_get(struct cgroup_ops *ops, const char *filename,
				     char *value, size_t len, const char *name,
				     const char *lxcpath)
{
	__do_free char *path = NULL;
	__do_free char *controller = NULL;
	char *p;
	struct hierarchy *h;
	int ret = -1;

	if (!ops)
		return ret_set_errno(-1, ENOENT);

	controller = strdup(filename);
	if (!controller)
		return ret_errno(ENOMEM);

	p = strchr(controller, '.');
	if (p)
		*p = '\0';

	path = lxc_cmd_get_limit_cgroup_path(name, lxcpath, controller);
	/* not running */
	if (!path)
		return -1;

	h = get_hierarchy(ops, controller);
	if (h) {
		__do_free char *fullpath = NULL;

		fullpath = build_full_cgpath_from_monitorpath(h, path, filename);
		ret = lxc_read_from_file(fullpath, value, len);
	}

	return ret;
}

static int device_cgroup_parse_access(struct device_item *device, const char *val)
{
	for (int count = 0; count < 3; count++, val++) {
		switch (*val) {
		case 'r':
			device->access[count] = *val;
			break;
		case 'w':
			device->access[count] = *val;
			break;
		case 'm':
			device->access[count] = *val;
			break;
		case '\n':
		case '\0':
			count = 3;
			break;
		default:
			return ret_errno(EINVAL);
		}
	}

	return 0;
}

static int device_cgroup_rule_parse(struct device_item *device, const char *key,
				    const char *val)
{
	int count, ret;
	char temp[50];

	if (strequal("devices.allow", key))
		device->allow = 1; /* allow the device */
	else
		device->allow = 0; /* deny the device */

	if (strequal(val, "a")) {
		/* global rule */
		device->type = 'a';
		device->major = -1;
		device->minor = -1;
		return 0;
	}

	switch (*val) {
	case 'a':
		__fallthrough;
	case 'b':
		__fallthrough;
	case 'c':
		device->type = *val;
		break;
	default:
		return -1;
	}

	val++;
	if (!isspace(*val))
		return -1;
	val++;
	if (*val == '*') {
		device->major = -1;
		val++;
	} else if (isdigit(*val)) {
		memset(temp, 0, sizeof(temp));
		for (count = 0; count < sizeof(temp) - 1; count++) {
			temp[count] = *val;
			val++;
			if (!isdigit(*val))
				break;
		}
		ret = lxc_safe_int(temp, &device->major);
		if (ret)
			return -1;
	} else {
		return -1;
	}
	if (*val != ':')
		return -1;
	val++;

	/* read minor */
	if (*val == '*') {
		device->minor = -1;
		val++;
	} else if (isdigit(*val)) {
		memset(temp, 0, sizeof(temp));
		for (count = 0; count < sizeof(temp) - 1; count++) {
			temp[count] = *val;
			val++;
			if (!isdigit(*val))
				break;
		}
		ret = lxc_safe_int(temp, &device->minor);
		if (ret)
			return -1;
	} else {
		return -1;
	}
	if (!isspace(*val))
		return -1;

	return device_cgroup_parse_access(device, ++val);
}

/* Called externally (i.e. from 'lxc-cgroup') to set new cgroup limits.  Here we
 * don't have a cgroup_data set up, so we ask the running container through the
 * commands API for the cgroup path.
 */
__cgfsng_ops static int cgfsng_set(struct cgroup_ops *ops,
				     const char *key, const char *value,
				     const char *name, const char *lxcpath)
{
	__do_free char *path = NULL;
	__do_free char *controller = NULL;
	char *p;
	struct hierarchy *h;
	int ret = -1;

	if (!ops || is_empty_string(key) || is_empty_string(value) ||
	    is_empty_string(name) || is_empty_string(lxcpath))
		return ret_errno(EINVAL);

	controller = strdup(key);
	if (!controller)
		return ret_errno(ENOMEM);

	p = strchr(controller, '.');
	if (p)
		*p = '\0';

	if (pure_unified_layout(ops) && strequal(controller, "devices")) {
		struct device_item device = {};

		ret = device_cgroup_rule_parse(&device, key, value);
		if (ret < 0)
			return log_error_errno(-1, EINVAL, "Failed to parse device string %s=%s",
					       key, value);

		ret = lxc_cmd_add_bpf_device_cgroup(name, lxcpath, &device);
		if (ret < 0)
			return -1;

		return 0;
	}

	path = lxc_cmd_get_limit_cgroup_path(name, lxcpath, controller);
	/* not running */
	if (!path)
		return -1;

	h = get_hierarchy(ops, controller);
	if (h) {
		__do_free char *fullpath = NULL;

		fullpath = build_full_cgpath_from_monitorpath(h, path, key);
		ret = lxc_write_to_file(fullpath, value, strlen(value), false, 0666);
	}

	return ret;
}

/* take devices cgroup line
 *    /dev/foo rwx
 * and convert it to a valid
 *    type major:minor mode
 * line. Return <0 on error. Dest is a preallocated buffer long enough to hold
 * the output.
 */
static int device_cgroup_rule_parse_devpath(struct device_item *device,
					    const char *devpath)
{
	__do_free char *path = NULL;
	char *mode = NULL;
	int n_parts, ret;
	char *p;
	struct stat sb;

	path = strdup(devpath);
	if (!path)
		return ret_errno(ENOMEM);

	/*
	 * Read path followed by mode. Ignore any trailing text.
	 * A '    # comment' would be legal. Technically other text is not
	 * legal, we could check for that if we cared to.
	 */
	for (n_parts = 1, p = path; *p; p++) {
		if (*p != ' ')
			continue;
		*p = '\0';

		if (n_parts != 1)
			break;
		p++;
		n_parts++;

		while (*p == ' ')
			p++;

		mode = p;

		if (*p == '\0')
			return ret_set_errno(-1, EINVAL);
	}

	if (!mode)
		return ret_errno(EINVAL);

	if (device_cgroup_parse_access(device, mode) < 0)
		return -1;

	ret = stat(path, &sb);
	if (ret < 0)
		return ret_set_errno(-1, errno);

	mode_t m = sb.st_mode & S_IFMT;
	switch (m) {
	case S_IFBLK:
		device->type = 'b';
		break;
	case S_IFCHR:
		device->type = 'c';
		break;
	default:
		return log_error_errno(-1, EINVAL, "Unsupported device type %i for \"%s\"", m, path);
	}

	device->major = MAJOR(sb.st_rdev);
	device->minor = MINOR(sb.st_rdev);
	device->allow = 1;

	return 0;
}

static int convert_devpath(const char *invalue, char *dest)
{
	struct device_item device = {};
	int ret;

	ret = device_cgroup_rule_parse_devpath(&device, invalue);
	if (ret < 0)
		return -1;

	ret = strnprintf(dest, 50, "%c %d:%d %s", device.type, device.major,
			 device.minor, device.access);
	if (ret < 0)
		return log_error_errno(ret, -ret,
				       "Error on configuration value \"%c %d:%d %s\" (max 50 chars)",
				       device.type, device.major, device.minor,
				       device.access);

	return 0;
}

/* Called from setup_limits - here we have the container's cgroup_data because
 * we created the cgroups.
 */
static int cg_legacy_set_data(struct cgroup_ops *ops, const char *filename,
			      const char *value, bool is_cpuset)
{
	__do_free char *controller = NULL;
	char *p;
	/* "b|c <2^64-1>:<2^64-1> r|w|m" = 47 chars max */
	char converted_value[50];
	struct hierarchy *h;

	controller = strdup(filename);
	if (!controller)
		return ret_errno(ENOMEM);

	p = strchr(controller, '.');
	if (p)
		*p = '\0';

	if (strequal("devices.allow", filename) && value[0] == '/') {
		int ret;

		ret = convert_devpath(value, converted_value);
		if (ret < 0)
			return ret;
		value = converted_value;
	}

	h = get_hierarchy(ops, controller);
	if (!h)
		return log_error_errno(-ENOENT, ENOENT, "Failed to setup limits for the \"%s\" controller. The controller seems to be unused by \"cgfsng\" cgroup driver or not enabled on the cgroup hierarchy", controller);

	if (is_cpuset) {
		int ret = lxc_write_openat(h->path_con, filename, value, strlen(value));
		if (ret)
			return ret;
	}
	return lxc_write_openat(h->path_lim, filename, value, strlen(value));
}

__cgfsng_ops static bool cgfsng_setup_limits_legacy(struct cgroup_ops *ops,
						    struct lxc_conf *conf,
						    bool do_devices)
{
	__do_free struct lxc_list *sorted_cgroup_settings = NULL;
	struct lxc_list *cgroup_settings = &conf->cgroup;
	struct lxc_list *iterator, *next;
	struct lxc_cgroup *cg;
	bool ret = false;

	if (!ops)
		return ret_set_errno(false, ENOENT);

	if (!conf)
		return ret_set_errno(false, EINVAL);

	cgroup_settings = &conf->cgroup;
	if (lxc_list_empty(cgroup_settings))
		return true;

	if (!ops->hierarchies)
		return ret_set_errno(false, EINVAL);

	if (pure_unified_layout(ops))
		return log_warn_errno(true, EINVAL, "Ignoring legacy cgroup limits on pure cgroup2 system");

	sorted_cgroup_settings = sort_cgroup_settings(cgroup_settings);
	if (!sorted_cgroup_settings)
		return false;

	lxc_list_for_each(iterator, sorted_cgroup_settings) {
		cg = iterator->elem;

		if (do_devices == strnequal("devices", cg->subsystem, 7)) {
			if (cg_legacy_set_data(ops, cg->subsystem, cg->value, strnequal("cpuset", cg->subsystem, 6))) {
				if (do_devices && (errno == EACCES || errno == EPERM)) {
					SYSWARN("Failed to set \"%s\" to \"%s\"", cg->subsystem, cg->value);
					continue;
				}
				SYSERROR("Failed to set \"%s\" to \"%s\"", cg->subsystem, cg->value);
				goto out;
			}
			DEBUG("Set controller \"%s\" set to \"%s\"", cg->subsystem, cg->value);
		}
	}

	ret = true;
	INFO("Limits for the legacy cgroup hierarchies have been setup");
out:
	lxc_list_for_each_safe(iterator, sorted_cgroup_settings, next) {
		lxc_list_del(iterator);
		free(iterator);
	}

	return ret;
}

/*
 * Some of the parsing logic comes from the original cgroup device v1
 * implementation in the kernel.
 */
static int bpf_device_cgroup_prepare(struct cgroup_ops *ops,
				     struct lxc_conf *conf, const char *key,
				     const char *val)
{
	struct device_item device_item = {};
	int ret;

	if (strequal("devices.allow", key) && abspath(val))
		ret = device_cgroup_rule_parse_devpath(&device_item, val);
	else
		ret = device_cgroup_rule_parse(&device_item, key, val);
	if (ret < 0)
		return syserror_set(EINVAL, "Failed to parse device rule %s=%s", key, val);

	/*
	 * Note that bpf_list_add_device() returns 1 if it altered the device
	 * list and 0 if it didn't; both return values indicate success.
	 * Only a negative return value indicates an error.
	 */
	ret = bpf_list_add_device(&conf->bpf_devices, &device_item);
	if (ret < 0)
		return -1;

	return 0;
}

__cgfsng_ops static bool cgfsng_setup_limits(struct cgroup_ops *ops,
					     struct lxc_handler *handler)
{
	struct lxc_list *cgroup_settings, *iterator;
	struct hierarchy *h;
	struct lxc_conf *conf;

	if (!ops)
		return ret_set_errno(false, ENOENT);

	if (!ops->hierarchies)
		return true;

	if (!ops->container_cgroup)
		return ret_set_errno(false, EINVAL);

	if (!handler || !handler->conf)
		return ret_set_errno(false, EINVAL);
	conf = handler->conf;

	cgroup_settings = &conf->cgroup2;
	if (lxc_list_empty(cgroup_settings))
		return true;

	if (!pure_unified_layout(ops))
		return log_warn_errno(true, EINVAL, "Ignoring cgroup2 limits on legacy cgroup system");

	if (!ops->unified)
		return false;
	h = ops->unified;

	lxc_list_for_each (iterator, cgroup_settings) {
		struct lxc_cgroup *cg = iterator->elem;
		int ret;

		if (strnequal("devices", cg->subsystem, 7))
			ret = bpf_device_cgroup_prepare(ops, conf, cg->subsystem, cg->value);
		else
			ret = lxc_write_openat(h->path_lim, cg->subsystem, cg->value, strlen(cg->value));
		if (ret < 0)
			return log_error_errno(false, errno, "Failed to set \"%s\" to \"%s\"", cg->subsystem, cg->value);

		TRACE("Set \"%s\" to \"%s\"", cg->subsystem, cg->value);
	}

	return log_info(true, "Limits for the unified cgroup hierarchy have been setup");
}

__cgfsng_ops static bool cgfsng_devices_activate(struct cgroup_ops *ops, struct lxc_handler *handler)
{
	struct lxc_conf *conf;
	struct hierarchy *unified;

	if (!ops)
		return ret_set_errno(false, ENOENT);

	if (!ops->hierarchies)
		return true;

	if (!ops->container_cgroup)
		return ret_set_errno(false, EEXIST);

	if (!handler || !handler->conf)
		return ret_set_errno(false, EINVAL);
	conf = handler->conf;

	unified = ops->unified;
	if (!unified || !device_utility_controller(unified) ||
	    !unified->path_con ||
	    lxc_list_empty(&(conf->bpf_devices).device_item))
		return true;

	return bpf_cgroup_devices_attach(ops, &conf->bpf_devices);
}

static bool __cgfsng_delegate_controllers(struct cgroup_ops *ops, const char *cgroup)
{
	__do_close int dfd_final = -EBADF;
	__do_free char *add_controllers = NULL, *copy = NULL;
	size_t full_len = 0;
	struct hierarchy *unified;
	int dfd_cur, ret;
	char *cur;
	char **it;

	if (!ops->hierarchies || !pure_unified_layout(ops))
		return true;

	unified = ops->unified;
	if (!unified->controllers[0])
		return true;

	/* For now we simply enable all controllers that we have detected by
	 * creating a string like "+memory +pids +cpu +io".
	 * TODO: In the near future we might want to support "-<controller>"
	 * etc. but whether supporting semantics like this make sense will need
	 * some thinking.
	 */
	for (it = unified->controllers; it && *it; it++) {
		full_len += strlen(*it) + 2;
		add_controllers = must_realloc(add_controllers, full_len + 1);

		if (unified->controllers[0] == *it)
			add_controllers[0] = '\0';

		(void)strlcat(add_controllers, "+", full_len + 1);
		(void)strlcat(add_controllers, *it, full_len + 1);

		if ((it + 1) && *(it + 1))
			(void)strlcat(add_controllers, " ", full_len + 1);
	}

	copy = strdup(cgroup);
	if (!copy)
		return false;

	/*
	 * Placing the write to cgroup.subtree_control before the open() is
	 * intentional because of the cgroup2 delegation model. It enforces
	 * that leaf cgroups don't have any controllers enabled for delegation.
	 */
	dfd_cur = unified->dfd_base;
	lxc_iterate_parts(cur, copy, "/") {
		/*
		 * Even though we vetted the paths when we parsed the config
		 * we're paranoid here and check that the path is neither
		 * absolute nor walks upwards.
		 */
		if (abspath(cur))
			return syserror_set(-EINVAL, "No absolute paths allowed");

		if (strnequal(cur, "..", STRLITERALLEN("..")))
			return syserror_set(-EINVAL, "No upward walking paths allowed");

		ret = lxc_writeat(dfd_cur, "cgroup.subtree_control", add_controllers, full_len);
		if (ret < 0)
			return syserror("Could not enable \"%s\" controllers in the unified cgroup %d", add_controllers, dfd_cur);

		TRACE("Enabled \"%s\" controllers in the unified cgroup %d", add_controllers, dfd_cur);

		dfd_final = open_at(dfd_cur, cur, PROTECT_OPATH_DIRECTORY, PROTECT_LOOKUP_BENEATH, 0);
		if (dfd_final < 0)
			return syserror("Fail to open directory %d(%s)", dfd_cur, cur);
		if (dfd_cur != unified->dfd_base)
			close(dfd_cur);
		/*
		 * Leave dfd_final pointing to the last fd we opened so
		 * it will be automatically zapped if we return early.
		 */
		dfd_cur = dfd_final;
	}

	return true;
}

__cgfsng_ops static bool cgfsng_monitor_delegate_controllers(struct cgroup_ops *ops)
{
	if (!ops)
		return ret_set_errno(false, ENOENT);

	return __cgfsng_delegate_controllers(ops, ops->monitor_cgroup);
}

__cgfsng_ops static bool cgfsng_payload_delegate_controllers(struct cgroup_ops *ops)
{
	if (!ops)
		return ret_set_errno(false, ENOENT);

	return __cgfsng_delegate_controllers(ops, ops->container_cgroup);
}

static inline bool unified_cgroup(const char *line)
{
	return *line == '0';
}

static inline char *current_unified_cgroup(bool relative, char *line)
{
	char *current_cgroup;

	line += STRLITERALLEN("0::");

	if (!abspath(line))
		return ERR_PTR(-EINVAL);

	/* remove init.scope */
	if (!relative)
		line = prune_init_scope(line);

	/* create a relative path */
	line = deabs(line);

	current_cgroup = strdup(line);
	if (!current_cgroup)
		return ERR_PTR(-ENOMEM);

	return current_cgroup;
}

static inline const char *unprefix(const char *controllers)
{
	if (strnequal(controllers, "name=", STRLITERALLEN("name=")))
		return controllers + STRLITERALLEN("name=");
	return controllers;
}

static int __list_cgroup_delegate(char ***delegate)
{
	__do_free char **list = NULL;
	__do_free char *buf = NULL;
	char *standard[] = {
		"cgroup.procs",
		"cgroup.threads",
		"cgroup.subtree_control",
		"memory.oom.group",
		NULL,
	};
	char *token;
	int ret;

	buf = read_file_at(-EBADF, "/sys/kernel/cgroup/delegate", PROTECT_OPEN, 0);
	if (!buf) {
		for (char **p = standard; p && *p; p++) {
			ret = list_add_string(&list, *p);
			if (ret < 0)
				return ret;
		}

		*delegate = move_ptr(list);
		return syswarn_ret(0, "Failed to read /sys/kernel/cgroup/delegate");
	}

	lxc_iterate_parts(token, buf, " \t\n") {
		/*
		 * We always need to chown this for both cgroup and
		 * cgroup2.
		 */
		if (strequal(token, "cgroup.procs"))
			continue;

		ret = list_add_string(&list, token);
		if (ret < 0)
			return ret;
	}

	*delegate = move_ptr(list);
	return 0;
}

static bool unified_hierarchy_delegated(int dfd_base, char ***ret_files)
{
	__do_free_string_list char **list = NULL;
	int ret;

	ret = __list_cgroup_delegate(&list);
	if (ret < 0)
		return syserror_ret(ret, "Failed to determine unified cgroup delegation requirements");

	for (char *const *s = list; s && *s; s++) {
		if (!faccessat(dfd_base, *s, W_OK, 0) || errno == ENOENT)
			continue;

		return sysinfo_ret(false, "The %s file is not writable, skipping unified hierarchy", *s);
	}

	*ret_files = move_ptr(list);
	return true;
}

static bool legacy_hierarchy_delegated(int dfd_base)
{
	int ret;

	ret = faccessat(dfd_base, ".", W_OK, 0);
	if (ret < 0 && errno != ENOENT)
		return sysinfo_ret(false, "Legacy hierarchy not writable, skipping");

	return true;
}

/**
 * systemd guarantees that the order of co-mounted controllers is stable. On
 * some systems the order of the controllers might be reversed though.
 *
 * For example, this is how the order is mismatched on CentOS 7:
 *
 *      [root@localhost ~]# cat /proc/self/cgroup
 *      11:perf_event:/
 *      10:pids:/
 *      9:freezer:/
 * >>>> 8:cpuacct,cpu:/
 *      7:memory:/
 *      6:blkio:/
 *      5:devices:/
 *      4:hugetlb:/
 * >>>> 3:net_prio,net_cls:/
 *      2:cpuset:/
 *      1:name=systemd:/user.slice/user-0.slice/session-c1.scope
 *
 * whereas the mountpoint:
 *
 *      | |-/sys/fs/cgroup                    tmpfs         tmpfs      ro,nosuid,nodev,noexec,mode=755
 *      | | |-/sys/fs/cgroup/systemd          cgroup        cgroup     rw,nosuid,nodev,noexec,relatime,xattr,release_agent=/usr/lib/systemd/systemd-cgroups-agent,name=systemd
 *      | | |-/sys/fs/cgroup/cpuset           cgroup        cgroup     rw,nosuid,nodev,noexec,relatime,cpuset
 * >>>> | | |-/sys/fs/cgroup/net_cls,net_prio cgroup        cgroup     rw,nosuid,nodev,noexec,relatime,net_prio,net_cls
 *      | | |-/sys/fs/cgroup/hugetlb          cgroup        cgroup     rw,nosuid,nodev,noexec,relatime,hugetlb
 *      | | |-/sys/fs/cgroup/devices          cgroup        cgroup     rw,nosuid,nodev,noexec,relatime,devices
 *      | | |-/sys/fs/cgroup/blkio            cgroup        cgroup     rw,nosuid,nodev,noexec,relatime,blkio
 *      | | |-/sys/fs/cgroup/memory           cgroup        cgroup     rw,nosuid,nodev,noexec,relatime,memory
 * >>>> | | |-/sys/fs/cgroup/cpu,cpuacct      cgroup        cgroup     rw,nosuid,nodev,noexec,relatime,cpuacct,cpu
 *      | | |-/sys/fs/cgroup/freezer          cgroup        cgroup     rw,nosuid,nodev,noexec,relatime,freezer
 *      | | |-/sys/fs/cgroup/pids             cgroup        cgroup     rw,nosuid,nodev,noexec,relatime,pids
 *      | | `-/sys/fs/cgroup/perf_event       cgroup        cgroup     rw,nosuid,nodev,noexec,relatime,perf_event
 *
 * Ensure that we always use the systemd-guaranteed stable order when checking
 * for the mountpoint.
 */
__attribute__((returns_nonnull)) __attribute__((nonnull))
static const char *stable_order(const char *controllers)
{
	if (strequal(controllers, "cpuacct,cpu"))
		return "cpu,cpuacct";

	if (strequal(controllers, "net_prio,net_cls"))
		return "net_cls,net_prio";

	return unprefix(controllers);
}

static int __initialize_cgroups(struct cgroup_ops *ops, bool relative,
				bool unprivileged)
{
	__do_free char *cgroup_info = NULL;
	char *it;

	/*
	 * Root spawned containers escape the current cgroup, so use init's
	 * cgroups as our base in that case.
	 */
	if (!relative && (geteuid() == 0))
		cgroup_info = read_file_at(-EBADF, "/proc/1/cgroup", PROTECT_OPEN, 0);
	else
		cgroup_info = read_file_at(-EBADF, "/proc/self/cgroup", PROTECT_OPEN, 0);
	if (!cgroup_info)
		return ret_errno(ENOMEM);

	lxc_iterate_parts(it, cgroup_info, "\n") {
		__do_close int dfd_base = -EBADF, dfd_mnt = -EBADF;
		__do_free char *controllers = NULL, *current_cgroup = NULL;
		__do_free_string_list char **controller_list = NULL,
					   **delegate = NULL;
		char *line;
		int dfd, ret, type;

		/* Handle the unified cgroup hierarchy. */
		line = it;
		if (unified_cgroup(line)) {
			char *unified_mnt;

			type = UNIFIED_HIERARCHY;

			current_cgroup = current_unified_cgroup(relative, line);
			if (IS_ERR(current_cgroup))
				return PTR_ERR(current_cgroup);

			if (unified_cgroup_fd(ops->dfd_mnt)) {
				dfd_mnt = dup_cloexec(ops->dfd_mnt);
				unified_mnt = "";
			} else {
				dfd_mnt = open_at(ops->dfd_mnt,
						  "unified",
						  PROTECT_OPATH_DIRECTORY,
						  PROTECT_LOOKUP_ABSOLUTE_XDEV, 0);
				unified_mnt = "unified";
			}
			if (dfd_mnt < 0) {
				if (errno != ENOENT)
					return syserror("Failed to open %d/unified", ops->dfd_mnt);

				SYSTRACE("Unified cgroup not mounted");
				continue;
			}
			dfd = dfd_mnt;

			if (!is_empty_string(current_cgroup)) {
				dfd_base = open_at(dfd_mnt, current_cgroup,
						   PROTECT_OPATH_DIRECTORY,
						   PROTECT_LOOKUP_BENEATH_XDEV, 0);
				if (dfd_base < 0) {
					if (errno != ENOENT)
						return syserror("Failed to open %d/%s",
								dfd_mnt, current_cgroup);

					SYSTRACE("Current cgroup %d/%s does not exist (funky cgroup layout?)",
						 dfd_mnt, current_cgroup);
					continue;
				}
				dfd = dfd_base;
			}

			if (!unified_hierarchy_delegated(dfd, &delegate))
				continue;

			controller_list = unified_controllers(dfd, "cgroup.controllers");
			if (!controller_list) {
				TRACE("No controllers are enabled for delegation in the unified hierarchy");
				controller_list = list_new();
				if (!controller_list)
					return syserror_set(-ENOMEM, "Failed to create empty controller list");
			}

			controllers = strdup(unified_mnt);
			if (!controllers)
				return ret_errno(ENOMEM);
		} else {
			char *__controllers, *__current_cgroup;

			type = LEGACY_HIERARCHY;

			__controllers = strchr(line, ':');
			if (!__controllers)
				return ret_errno(EINVAL);
			__controllers++;

			__current_cgroup = strchr(__controllers, ':');
			if (!__current_cgroup)
				return ret_errno(EINVAL);
			*__current_cgroup = '\0';
			__current_cgroup++;

			controllers = strdup(stable_order(__controllers));
			if (!controllers)
				return ret_errno(ENOMEM);

			dfd_mnt = open_at(ops->dfd_mnt,
					  controllers,
					  PROTECT_OPATH_DIRECTORY,
					  PROTECT_LOOKUP_ABSOLUTE_XDEV, 0);
			if (dfd_mnt < 0) {
				if (errno != ENOENT)
					return syserror("Failed to open %d/%s",
							ops->dfd_mnt, controllers);

				SYSTRACE("%s not mounted", controllers);
				continue;
			}
			dfd = dfd_mnt;

			if (!abspath(__current_cgroup))
				return ret_errno(EINVAL);

			/* remove init.scope */
			if (!relative)
				__current_cgroup = prune_init_scope(__current_cgroup);

			/* create a relative path */
			__current_cgroup = deabs(__current_cgroup);

			current_cgroup = strdup(__current_cgroup);
			if (!current_cgroup)
				return ret_errno(ENOMEM);

			if (!is_empty_string(current_cgroup)) {
				dfd_base = open_at(dfd_mnt, current_cgroup,
						   PROTECT_OPATH_DIRECTORY,
						   PROTECT_LOOKUP_BENEATH_XDEV, 0);
				if (dfd_base < 0) {
					if (errno != ENOENT)
						return syserror("Failed to open %d/%s",
								dfd_mnt, current_cgroup);

					SYSTRACE("Current cgroup %d/%s does not exist (funky cgroup layout?)",
						 dfd_mnt, current_cgroup);
					continue;
				}
				dfd = dfd_base;
			}

			if (!legacy_hierarchy_delegated(dfd))
				continue;

			/*
			 * We intentionally pass __current_cgroup here and not
			 * controllers because we would otherwise chop the
			 * mountpoint.
			 */
			controller_list = list_add_controllers(__controllers);
			if (!controller_list)
				return syserror_set(-ENOMEM, "Failed to create controller list from %s", __controllers);

			if (skip_hierarchy(ops, controller_list))
				continue;

			ops->cgroup_layout = CGROUP_LAYOUT_LEGACY;
		}

		ret = cgroup_hierarchy_add(ops, dfd_mnt, controllers, dfd,
					   current_cgroup, controller_list, type);
		if (ret < 0)
			return syserror_ret(ret, "Failed to add %s hierarchy", controllers);

		/* Transfer ownership. */
		move_fd(dfd_mnt);
		move_fd(dfd_base);
		move_ptr(current_cgroup);
		move_ptr(controllers);
		move_ptr(controller_list);
		if (type == UNIFIED_HIERARCHY)
			ops->unified->delegate = move_ptr(delegate);
	}

	/* determine cgroup layout */
	if (ops->unified) {
		if (ops->cgroup_layout == CGROUP_LAYOUT_LEGACY) {
			ops->cgroup_layout = CGROUP_LAYOUT_HYBRID;
		} else {
			if (bpf_devices_cgroup_supported())
				ops->unified->utilities |= DEVICES_CONTROLLER;
			ops->cgroup_layout = CGROUP_LAYOUT_UNIFIED;
		}
	}

	if (!controllers_available(ops))
		return syserror_set(-ENOENT, "One or more requested controllers unavailable or not delegated");

	return 0;
}

static int initialize_cgroups(struct cgroup_ops *ops, struct lxc_conf *conf)
{
	__do_close int dfd = -EBADF;
	int ret;
	const char *controllers_use;

	if (ops->dfd_mnt >= 0)
		return ret_errno(EBUSY);

	/*
	 * I don't see the need for allowing symlinks here. If users want to
	 * have their hierarchy available in different locations I strongly
	 * suggest bind-mounts.
	 */
	dfd = open_at(-EBADF, DEFAULT_CGROUP_MOUNTPOINT,
			PROTECT_OPATH_DIRECTORY, PROTECT_LOOKUP_ABSOLUTE_XDEV, 0);
	if (dfd < 0)
		return syserror("Failed to open " DEFAULT_CGROUP_MOUNTPOINT);

	controllers_use = lxc_global_config_value("lxc.cgroup.use");
	if (controllers_use) {
		__do_free char *dup = NULL;
		char *it;

		dup = strdup(controllers_use);
		if (!dup)
			return -errno;

		lxc_iterate_parts(it, dup, ",") {
			ret = list_add_string(&ops->cgroup_use, it);
			if (ret < 0)
				return ret;
		}
	}

	/*
	 * Keep dfd referenced by the cleanup function and actually move the fd
	 * once we know the initialization succeeded. So if we fail we clean up
	 * the dfd.
	 */
	ops->dfd_mnt = dfd;

	ret = __initialize_cgroups(ops, conf->cgroup_meta.relative, !lxc_list_empty(&conf->id_map));
	if (ret < 0)
		return syserror_ret(ret, "Failed to initialize cgroups");

	/* Transfer ownership to cgroup_ops. */
	move_fd(dfd);
	return 0;
}

__cgfsng_ops static int cgfsng_data_init(struct cgroup_ops *ops)
{
	const char *cgroup_pattern;

	if (!ops)
		return ret_set_errno(-1, ENOENT);

	/* copy system-wide cgroup information */
	cgroup_pattern = lxc_global_config_value("lxc.cgroup.pattern");
	if (cgroup_pattern && !strequal(cgroup_pattern, "")) {
		ops->cgroup_pattern = strdup(cgroup_pattern);
		if (!ops->cgroup_pattern)
			return ret_errno(ENOMEM);
	}

	return 0;
}

struct cgroup_ops *cgroup_ops_init(struct lxc_conf *conf)
{
	__cleanup_cgroup_ops struct cgroup_ops *cgfsng_ops = NULL;

	cgfsng_ops = zalloc(sizeof(struct cgroup_ops));
	if (!cgfsng_ops)
		return ret_set_errno(NULL, ENOMEM);

	cgfsng_ops->cgroup_layout	= CGROUP_LAYOUT_UNKNOWN;
	cgfsng_ops->dfd_mnt		= -EBADF;

	if (initialize_cgroups(cgfsng_ops, conf))
		return NULL;

	cgfsng_ops->data_init				= cgfsng_data_init;
	cgfsng_ops->payload_destroy			= cgfsng_payload_destroy;
	cgfsng_ops->monitor_destroy			= cgfsng_monitor_destroy;
	cgfsng_ops->monitor_create			= cgfsng_monitor_create;
	cgfsng_ops->monitor_enter			= cgfsng_monitor_enter;
	cgfsng_ops->monitor_delegate_controllers	= cgfsng_monitor_delegate_controllers;
	cgfsng_ops->payload_delegate_controllers	= cgfsng_payload_delegate_controllers;
	cgfsng_ops->payload_create			= cgfsng_payload_create;
	cgfsng_ops->payload_enter			= cgfsng_payload_enter;
	cgfsng_ops->finalize				= cgfsng_finalize;
	cgfsng_ops->get_cgroup				= cgfsng_get_cgroup;
	cgfsng_ops->get					= cgfsng_get;
	cgfsng_ops->set 				= cgfsng_set;
	cgfsng_ops->freeze				= cgfsng_freeze;
	cgfsng_ops->unfreeze				= cgfsng_unfreeze;
	cgfsng_ops->setup_limits_legacy			= cgfsng_setup_limits_legacy;
	cgfsng_ops->setup_limits			= cgfsng_setup_limits;
	cgfsng_ops->driver				= "cgfsng";
	cgfsng_ops->version				= "1.0.0";
	cgfsng_ops->attach				= cgfsng_attach;
	cgfsng_ops->chown				= cgfsng_chown;
	cgfsng_ops->mount 				= cgfsng_mount;
	cgfsng_ops->devices_activate			= cgfsng_devices_activate;
	cgfsng_ops->get_limit_cgroup			= cgfsng_get_limit_cgroup;

	cgfsng_ops->criu_escape				= cgfsng_criu_escape;
	cgfsng_ops->criu_num_hierarchies		= cgfsng_criu_num_hierarchies;
	cgfsng_ops->criu_get_hierarchies		= cgfsng_criu_get_hierarchies;

	return move_ptr(cgfsng_ops);
}

static int __unified_attach_fd(const struct lxc_conf *conf, int fd_unified, pid_t pid)
{
	int ret;

	if (!lxc_list_empty(&conf->id_map)) {
		struct userns_exec_unified_attach_data args = {
			.conf		= conf,
			.unified_fd	= fd_unified,
			.pid		= pid,
		};

		ret = socketpair(PF_LOCAL, SOCK_STREAM | SOCK_CLOEXEC, 0, args.sk_pair);
		if (ret < 0)
			return -errno;

		ret = userns_exec_minimal(conf,
					  cgroup_unified_attach_parent_wrapper,
					  &args,
					  cgroup_unified_attach_child_wrapper,
					  &args);
	} else {
		ret = cgroup_attach_leaf(conf, fd_unified, pid);
	}

	return ret;
}

static int __cgroup_attach_many(const struct lxc_conf *conf, const char *name,
				const char *lxcpath, pid_t pid)
{
	call_cleaner(put_cgroup_ctx) struct cgroup_ctx *ctx = &(struct cgroup_ctx){};
	int ret;
	size_t idx;
	ssize_t pidstr_len;
	char pidstr[INTTYPE_TO_STRLEN(pid_t)];

	ret = lxc_cmd_get_cgroup_ctx(name, lxcpath, sizeof(struct cgroup_ctx), ctx);
	if (ret < 0)
		return ret_errno(ENOSYS);

	pidstr_len = strnprintf(pidstr, sizeof(pidstr), "%d", pid);
	if (pidstr_len < 0)
		return pidstr_len;

	for (idx = 0; idx < ctx->fd_len; idx++) {
		int dfd_con = ctx->fd[idx];

		if (unified_cgroup_fd(dfd_con))
			ret = __unified_attach_fd(conf, dfd_con, pid);
		else
			ret = lxc_writeat(dfd_con, "cgroup.procs", pidstr, pidstr_len);
		if (ret)
			return syserror_ret(ret, "Failed to attach to cgroup fd %d", dfd_con);
		else
			TRACE("Attached to cgroup fd %d", dfd_con);
	}

	if (idx == 0)
		return syserror_set(-ENOENT, "Failed to attach to cgroups");

	TRACE("Attached to %s cgroup layout", cgroup_layout_name(ctx->layout));
	return 0;
}

static int __cgroup_attach_unified(const struct lxc_conf *conf, const char *name,
				   const char *lxcpath, pid_t pid)
{
	__do_close int dfd_unified = -EBADF;

	if (!conf || is_empty_string(name) || is_empty_string(lxcpath) || pid <= 0)
		return ret_errno(EINVAL);

	dfd_unified = lxc_cmd_get_cgroup2_fd(name, lxcpath);
	if (dfd_unified < 0)
		return ret_errno(ENOSYS);

	return __unified_attach_fd(conf, dfd_unified, pid);
}

int cgroup_attach(const struct lxc_conf *conf, const char *name,
		  const char *lxcpath, pid_t pid)
{
	int ret;

	ret = __cgroup_attach_many(conf, name, lxcpath, pid);
	if (ret < 0) {
		if (!ERRNO_IS_NOT_SUPPORTED(ret))
			return ret;

		ret = __cgroup_attach_unified(conf, name, lxcpath, pid);
		if (ret < 0 && ERRNO_IS_NOT_SUPPORTED(ret))
			return ret_errno(ENOSYS);
	}

	return ret;
}

/* Connects to command socket therefore isn't callable from command handler. */
int cgroup_get(const char *name, const char *lxcpath, const char *key, char *buf, size_t len)
{
	__do_close int dfd = -EBADF;
	struct cgroup_fd fd = {
		.fd = -EBADF,
	};
	size_t len_controller;
	int ret;

	if (is_empty_string(name) || is_empty_string(lxcpath) ||
	    is_empty_string(key))
		return ret_errno(EINVAL);

	if ((buf && !len) || (len && !buf))
		return ret_errno(EINVAL);

	len_controller = strcspn(key, ".");
	len_controller++; /* Don't forget the \0 byte. */
	if (len_controller >= MAX_CGROUP_ROOT_NAMELEN)
		return ret_errno(EINVAL);
	(void)strlcpy(fd.controller, key, len_controller);

	ret = lxc_cmd_get_limit_cgroup_fd(name, lxcpath, sizeof(struct cgroup_fd), &fd);
	if (ret < 0) {
		if (!ERRNO_IS_NOT_SUPPORTED(ret))
			return ret;

		dfd = lxc_cmd_get_limit_cgroup2_fd(name, lxcpath);
		if (dfd < 0) {
			if (!ERRNO_IS_NOT_SUPPORTED(ret))
				return ret;

			return ret_errno(ENOSYS);
		}
		fd.type = UNIFIED_HIERARCHY;
		fd.fd = move_fd(dfd);
	}
	dfd = move_fd(fd.fd);

	TRACE("Reading %s from %s cgroup hierarchy", key, cgroup_hierarchy_name(fd.type));

	if (fd.type == UNIFIED_HIERARCHY && strequal(fd.controller, "devices"))
		return ret_errno(EOPNOTSUPP);
	else
		ret = lxc_read_try_buf_at(dfd, key, buf, len);

	return ret;
}

/* Connects to command socket therefore isn't callable from command handler. */
int cgroup_set(const char *name, const char *lxcpath, const char *key, const char *value)
{
	__do_close int dfd = -EBADF;
	struct cgroup_fd fd = {
		.fd = -EBADF,
	};
	size_t len_controller;
	int ret;

	if (is_empty_string(name) || is_empty_string(lxcpath) ||
	    is_empty_string(key) || is_empty_string(value))
		return ret_errno(EINVAL);

	len_controller = strcspn(key, ".");
	len_controller++; /* Don't forget the \0 byte. */
	if (len_controller >= MAX_CGROUP_ROOT_NAMELEN)
		return ret_errno(EINVAL);
	(void)strlcpy(fd.controller, key, len_controller);

	ret = lxc_cmd_get_limit_cgroup_fd(name, lxcpath, sizeof(struct cgroup_fd), &fd);
	if (ret < 0) {
		if (!ERRNO_IS_NOT_SUPPORTED(ret))
			return ret;

		dfd = lxc_cmd_get_limit_cgroup2_fd(name, lxcpath);
		if (dfd < 0) {
			if (!ERRNO_IS_NOT_SUPPORTED(ret))
				return ret;

			return ret_errno(ENOSYS);
		}
		fd.type = UNIFIED_HIERARCHY;
		fd.fd = move_fd(dfd);
	}
	dfd = move_fd(fd.fd);

	TRACE("Setting %s to %s in %s cgroup hierarchy", key, value, cgroup_hierarchy_name(fd.type));

	if (fd.type == UNIFIED_HIERARCHY && strequal(fd.controller, "devices")) {
		struct device_item device = {};

		ret = device_cgroup_rule_parse(&device, key, value);
		if (ret < 0)
			return log_error_errno(-1, EINVAL, "Failed to parse device string %s=%s",
					       key, value);

		ret = lxc_cmd_add_bpf_device_cgroup(name, lxcpath, &device);
	} else {
		ret = lxc_writeat(dfd, key, value, strlen(value));
	}

	return ret;
}

static int do_cgroup_freeze(int unified_fd,
			    const char *state_string,
			    int state_num,
			    int timeout,
			    const char *epoll_error,
			    const char *wait_error)
{
	__do_close int events_fd = -EBADF;
	call_cleaner(lxc_mainloop_close) struct lxc_epoll_descr *descr_ptr = NULL;
	int ret;
	struct lxc_epoll_descr descr = {};

	if (timeout != 0) {
		ret = lxc_mainloop_open(&descr);
		if (ret)
			return log_error_errno(-1, errno, "%s", epoll_error);

		/* automatically cleaned up now */
		descr_ptr = &descr;

		events_fd = open_at(unified_fd, "cgroup.events", PROTECT_OPEN, PROTECT_LOOKUP_BENEATH, 0);
		if (events_fd < 0)
			return log_error_errno(-errno, errno, "Failed to open cgroup.events file");

		ret = lxc_mainloop_add_handler_events(&descr, events_fd, EPOLLPRI, freezer_cgroup_events_cb, INT_TO_PTR(state_num));
		if (ret < 0)
			return log_error_errno(-1, errno, "Failed to add cgroup.events fd handler to mainloop");
	}

	ret = lxc_writeat(unified_fd, "cgroup.freeze", state_string, 1);
	if (ret < 0)
		return log_error_errno(-1, errno, "Failed to open cgroup.freeze file");

	if (timeout != 0) {
		ret = lxc_mainloop(&descr, timeout);
		if (ret)
			return log_error_errno(-1, errno, "%s", wait_error);
	}

	return log_trace(0, "Container now %s", (state_num == 1) ? "frozen" : "unfrozen");
}

static inline int __cgroup_freeze(int unified_fd, int timeout)
{
	return do_cgroup_freeze(unified_fd, "1", 1, timeout,
			        "Failed to create epoll instance to wait for container freeze",
			        "Failed to wait for container to be frozen");
}

int cgroup_freeze(const char *name, const char *lxcpath, int timeout)
{
	__do_close int unified_fd = -EBADF;
	int ret;

	if (is_empty_string(name) || is_empty_string(lxcpath))
		return ret_errno(EINVAL);

	unified_fd = lxc_cmd_get_limit_cgroup2_fd(name, lxcpath);
	if (unified_fd < 0)
		return ret_errno(ENOCGROUP2);

	lxc_cmd_notify_state_listeners(name, lxcpath, FREEZING);
	ret = __cgroup_freeze(unified_fd, timeout);
	lxc_cmd_notify_state_listeners(name, lxcpath, !ret ? FROZEN : RUNNING);
	return ret;
}

int __cgroup_unfreeze(int unified_fd, int timeout)
{
	return do_cgroup_freeze(unified_fd, "0", 0, timeout,
			        "Failed to create epoll instance to wait for container freeze",
			        "Failed to wait for container to be frozen");
}

int cgroup_unfreeze(const char *name, const char *lxcpath, int timeout)
{
	__do_close int unified_fd = -EBADF;
	int ret;

	if (is_empty_string(name) || is_empty_string(lxcpath))
		return ret_errno(EINVAL);

	unified_fd = lxc_cmd_get_limit_cgroup2_fd(name, lxcpath);
	if (unified_fd < 0)
		return ret_errno(ENOCGROUP2);

	lxc_cmd_notify_state_listeners(name, lxcpath, THAWED);
	ret = __cgroup_unfreeze(unified_fd, timeout);
	lxc_cmd_notify_state_listeners(name, lxcpath, !ret ? RUNNING : FROZEN);
	return ret;
}
