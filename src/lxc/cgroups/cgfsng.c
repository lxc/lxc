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

/* Given a pointer to a null-terminated array of pointers, realloc to add one
 * entry, and point the new entry to NULL. Do not fail. Return the index to the
 * second-to-last entry - that is, the one which is now available for use
 * (keeping the list null-terminated).
 */
static int append_null_to_list(void ***list)
{
	int newentry = 0;

	if (*list)
		for (; (*list)[newentry]; newentry++)
			;

	*list = must_realloc(*list, (newentry + 2) * sizeof(void **));
	(*list)[newentry + 1] = NULL;
	return newentry;
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

/* Return a copy of @entry prepending "name=", i.e.  turn "systemd" into
 * "name=systemd". Do not fail.
 */
static char *cg_legacy_must_prefix_named(char *entry)
{
	size_t len;
	char *prefixed;

	len = strlen(entry);
	prefixed = must_realloc(NULL, len + 6);

	memcpy(prefixed, "name=", STRLITERALLEN("name="));
	memcpy(prefixed + STRLITERALLEN("name="), entry, len);
	prefixed[len + 5] = '\0';

	return prefixed;
}

/* Append an entry to the clist. Do not fail. @clist must be NULL the first time
 * we are called.
 *
 * We also handle named subsystems here. Any controller which is not a kernel
 * subsystem, we prefix "name=". Any which is both a kernel and named subsystem,
 * we refuse to use because we're not sure which we have here.
 * (TODO: We could work around this in some cases by just remounting to be
 * unambiguous, or by comparing mountpoint contents with current cgroup.)
 *
 * The last entry will always be NULL.
 */
static void must_append_controller(char **klist, char **nlist, char ***clist,
				   char *entry)
{
	int newentry;
	char *copy;

	if (string_in_list(klist, entry) && string_in_list(nlist, entry)) {
		ERROR("Refusing to use ambiguous controller \"%s\"", entry);
		ERROR("It is both a named and kernel subsystem");
		return;
	}

	newentry = append_null_to_list((void ***)clist);

	if (strnequal(entry, "name=", 5))
		copy = must_copy_string(entry);
	else if (string_in_list(klist, entry))
		copy = must_copy_string(entry);
	else
		copy = cg_legacy_must_prefix_named(entry);

	(*clist)[newentry] = copy;
}

/* Given a handler's cgroup data, return the struct hierarchy for the controller
 * @c, or NULL if there is none.
 */
static struct hierarchy *get_hierarchy(struct cgroup_ops *ops, const char *controller)
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
				if (ops->unified->bpf_device_controller)
					return ops->unified;

				break;
			} else if (strequal(controller, "freezer")) {
				if (ops->unified->freezer_controller)
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
	return h->version == CGROUP2_SUPER_MAGIC;
}

/* Given two null-terminated lists of strings, return true if any string is in
 * both.
 */
static bool controller_lists_intersect(char **l1, char **l2)
{
	if (!l1 || !l2)
		return false;

	for (int i = 0; l1[i]; i++)
		if (string_in_list(l2, l1[i]))
			return true;

	return false;
}

/* For a null-terminated list of controllers @clist, return true if any of those
 * controllers is already listed the null-terminated list of hierarchies @hlist.
 * Realistically, if one is present, all must be present.
 */
static bool controller_list_is_dup(struct hierarchy **hlist, char **clist)
{
	if (!hlist)
		return false;

	for (int i = 0; hlist[i]; i++)
		if (controller_lists_intersect(hlist[i]->controllers, clist))
			return true;

	return false;
}

/* Return true if the controller @entry is found in the null-terminated list of
 * hierarchies @hlist.
 */
static bool controller_found(struct hierarchy **hlist, char *entry)
{
	if (!hlist)
		return false;

	for (int i = 0; hlist[i]; i++)
		if (string_in_list(hlist[i]->controllers, entry))
			return true;

	return false;
}

/* Return true if all of the controllers which we require have been found.  The
 * required list is  freezer and anything in lxc.cgroup.use.
 */
static bool all_controllers_found(struct cgroup_ops *ops)
{
	struct hierarchy **hlist;

	if (!ops->cgroup_use)
		return true;

	hlist = ops->hierarchies;
	for (char **cur = ops->cgroup_use; cur && *cur; cur++)
		if (!controller_found(hlist, *cur))
			return log_error(false, "No %s controller mountpoint found", *cur);

	return true;
}

/* Get the controllers from a mountinfo line There are other ways we could get
 * this info. For lxcfs, field 3 is /cgroup/controller-list. For cgroupfs, we
 * could parse the mount options. But we simply assume that the mountpoint must
 * be /sys/fs/cgroup/controller-list
 */
static char **cg_hybrid_get_controllers(char **klist, char **nlist, char *line,
					int type)
{
	/* The fourth field is /sys/fs/cgroup/comma-delimited-controller-list
	 * for legacy hierarchies.
	 */
	__do_free_string_list char **aret = NULL;
	int i;
	char *p2, *tok;
	char *p = line, *sep = ",";

	for (i = 0; i < 4; i++) {
		p = strchr(p, ' ');
		if (!p)
			return NULL;
		p++;
	}

	/* Note, if we change how mountinfo works, then our caller will need to
	 * verify /sys/fs/cgroup/ in this field.
	 */
	if (!strnequal(p, DEFAULT_CGROUP_MOUNTPOINT "/", 15))
		return log_warn(NULL, "Found hierarchy not under " DEFAULT_CGROUP_MOUNTPOINT ": \"%s\"", p);

	p += 15;
	p2 = strchr(p, ' ');
	if (!p2)
		return log_error(NULL, "Corrupt mountinfo");
	*p2 = '\0';

	if (type == CGROUP_SUPER_MAGIC) {
		__do_free char *dup = NULL;

		/* strdup() here for v1 hierarchies. Otherwise
		 * lxc_iterate_parts() will destroy mountpoints such as
		 * "/sys/fs/cgroup/cpu,cpuacct".
		 */
		dup = must_copy_string(p);
		if (!dup)
			return NULL;

		lxc_iterate_parts(tok, dup, sep)
			must_append_controller(klist, nlist, &aret, tok);
	}
	*p2 = ' ';

	return move_ptr(aret);
}

static char **cg_unified_make_empty_controller(void)
{
	__do_free_string_list char **aret = NULL;
	int newentry;

	newentry = append_null_to_list((void ***)&aret);
	aret[newentry] = NULL;
	return move_ptr(aret);
}

static char **cg_unified_get_controllers(int dfd, const char *file)
{
	__do_free char *buf = NULL;
	__do_free_string_list char **aret = NULL;
	char *sep = " \t\n";
	char *tok;

	buf = read_file_at(dfd, file, PROTECT_OPEN, 0);
	if (!buf)
		return NULL;

	lxc_iterate_parts(tok, buf, sep) {
		int newentry;
		char *copy;

		newentry = append_null_to_list((void ***)&aret);
		copy = must_copy_string(tok);
		aret[newentry] = copy;
	}

	return move_ptr(aret);
}

static bool cgroup_use_wants_controllers(const struct cgroup_ops *ops,
				       char **controllers)
{
	if (!ops->cgroup_use)
		return true;

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

		return false;
	}

	return true;
}

static int add_hierarchy(struct cgroup_ops *ops, char **clist, char *mountpoint,
			 char *container_base_path, int type)
{
	__do_close int dfd_base = -EBADF, dfd_mnt = -EBADF;
	__do_free struct hierarchy *new = NULL;
	__do_free_string_list char **controllers = clist;
	int newentry;

	if (abspath(container_base_path))
		return syserrno(-errno, "Container base path must be relative to controller mount");

	if (!controllers && type != CGROUP2_SUPER_MAGIC)
		return syserrno_set(-EINVAL, "Empty controller list for non-unified cgroup hierarchy passed");

	dfd_mnt = open_at(-EBADF, mountpoint, PROTECT_OPATH_DIRECTORY,
			  PROTECT_LOOKUP_ABSOLUTE_XDEV, 0);
	if (dfd_mnt < 0)
		return syserrno(-errno, "Failed to open %s", mountpoint);

	if (is_empty_string(container_base_path))
		dfd_base = dfd_mnt;
	else
		dfd_base = open_at(dfd_mnt, container_base_path,
				   PROTECT_OPATH_DIRECTORY,
				   PROTECT_LOOKUP_BENEATH_XDEV, 0);
	if (dfd_base < 0)
		return syserrno(-errno, "Failed to open %d(%s)", dfd_base, container_base_path);

	if (!controllers) {
		/*
		* We assume that the cgroup we're currently in has been delegated to
		* us and we are free to further delege all of the controllers listed
		* in cgroup.controllers further down the hierarchy.
		 */
		controllers = cg_unified_get_controllers(dfd_base, "cgroup.controllers");
		if (!controllers)
			controllers = cg_unified_make_empty_controller();
		if (!controllers[0])
			TRACE("No controllers are enabled for delegation");
	}

	/* Exclude all controllers that cgroup use does not want. */
	if (!cgroup_use_wants_controllers(ops, controllers))
		return log_trace(0, "Skipping cgroup hiearchy with non-requested controllers");

	new = zalloc(sizeof(*new));
	if (!new)
		return ret_errno(ENOMEM);

	new->version			= type;
	new->controllers		= move_ptr(controllers);
	new->mountpoint			= mountpoint;
	new->container_base_path	= container_base_path;
	new->cgfd_con			= -EBADF;
	new->cgfd_limit			= -EBADF;
	new->cgfd_mon			= -EBADF;

	TRACE("Adding cgroup hierarchy with mountpoint %s and base cgroup %s",
	      mountpoint, container_base_path);
	for (char *const *it = new->controllers; it && *it; it++)
		TRACE("The detected hierarchy contains the %s controller", *it);

	newentry = append_null_to_list((void ***)&ops->hierarchies);
	new->dfd_mnt = move_fd(dfd_mnt);
	new->dfd_base = move_fd(dfd_base);
	if (type == CGROUP2_SUPER_MAGIC)
		ops->unified = new;
	(ops->hierarchies)[newentry] = move_ptr(new);
	return 0;
}

/* Get a copy of the mountpoint from @line, which is a line from
 * /proc/self/mountinfo.
 */
static char *cg_hybrid_get_mountpoint(char *line)
{
	char *p = line, *sret = NULL;
	size_t len;
	char *p2;

	for (int i = 0; i < 4; i++) {
		p = strchr(p, ' ');
		if (!p)
			return NULL;
		p++;
	}

	if (!strnequal(p, DEFAULT_CGROUP_MOUNTPOINT "/", 15))
		return NULL;

	p2 = strchr(p + 15, ' ');
	if (!p2)
		return NULL;
	*p2 = '\0';

	len = strlen(p);
	sret = must_realloc(NULL, len + 1);
	memcpy(sret, p, len);
	sret[len] = '\0';

	return sret;
}

/* Given a multi-line string, return a null-terminated copy of the current line. */
static char *copy_to_eol(char *p)
{
	char *p2, *sret;
	size_t len;

	p2 = strchr(p, '\n');
	if (!p2)
		return NULL;

	len = p2 - p;
	sret = must_realloc(NULL, len + 1);
	memcpy(sret, p, len);
	sret[len] = '\0';

	return sret;
}

/* cgline: pointer to character after the first ':' in a line in a \n-terminated
 * /proc/self/cgroup file. Check whether controller c is present.
 */
static bool controller_in_clist(char *cgline, char *c)
{
	__do_free char *tmp = NULL;
	char *tok, *eol;
	size_t len;

	eol = strchr(cgline, ':');
	if (!eol)
		return false;

	len = eol - cgline;
	tmp = must_realloc(NULL, len + 1);
	memcpy(tmp, cgline, len);
	tmp[len] = '\0';

	lxc_iterate_parts(tok, tmp, ",")
		if (strequal(tok, c))
			return true;

	return false;
}

static inline char *trim(char *s)
{
	size_t len;

	len = strlen(s);
	while ((len > 1) && (s[len - 1] == '\n'))
		s[--len] = '\0';

	return s;
}

/* @basecginfo is a copy of /proc/$$/cgroup. Return the current cgroup for
 * @controller.
 */
static char *cg_hybrid_get_current_cgroup(bool relative, char *basecginfo,
					  char *controller, int type)
{
	char *base_cgroup = basecginfo;

	for (;;) {
		bool is_cgv2_base_cgroup = false;

		/* cgroup v2 entry in "/proc/<pid>/cgroup": "0::/some/path" */
		if ((type == CGROUP2_SUPER_MAGIC) && (*base_cgroup == '0'))
			is_cgv2_base_cgroup = true;

		base_cgroup = strchr(base_cgroup, ':');
		if (!base_cgroup)
			return NULL;
		base_cgroup++;

		if (is_cgv2_base_cgroup || (controller && controller_in_clist(base_cgroup, controller))) {
			__do_free char *copy = NULL;

			base_cgroup = strchr(base_cgroup, ':');
			if (!base_cgroup)
				return NULL;
			base_cgroup++;

			copy = copy_to_eol(base_cgroup);
			if (!copy)
				return NULL;
			trim(copy);

			if (!relative) {
				base_cgroup = prune_init_scope(copy);
				if (!base_cgroup)
					return NULL;
			} else {
				base_cgroup = copy;
			}

			if (abspath(base_cgroup))
				base_cgroup = deabs(base_cgroup);

			/* We're allowing base_cgroup to be "". */
			return strdup(base_cgroup);
		}

		base_cgroup = strchr(base_cgroup, '\n');
		if (!base_cgroup)
			return NULL;
		base_cgroup++;
	}
}

static void must_append_string(char ***list, char *entry)
{
	int newentry;
	char *copy;

	newentry = append_null_to_list((void ***)list);
	copy = must_copy_string(entry);
	(*list)[newentry] = copy;
}

static int get_existing_subsystems(char ***klist, char ***nlist)
{
	__do_free char *line = NULL;
	__do_fclose FILE *f = NULL;
	size_t len = 0;

	f = fopen("/proc/self/cgroup", "re");
	if (!f)
		return -1;

	while (getline(&line, &len, f) != -1) {
		char *p, *p2, *tok;
		p = strchr(line, ':');
		if (!p)
			continue;
		p++;
		p2 = strchr(p, ':');
		if (!p2)
			continue;
		*p2 = '\0';

		/* If the kernel has cgroup v2 support, then /proc/self/cgroup
		 * contains an entry of the form:
		 *
		 *	0::/some/path
		 *
		 * In this case we use "cgroup2" as controller name.
		 */
		if ((p2 - p) == 0) {
			must_append_string(klist, "cgroup2");
			continue;
		}

		lxc_iterate_parts(tok, p, ",") {
			if (strnequal(tok, "name=", 5))
				must_append_string(nlist, tok);
			else
				must_append_string(klist, tok);
		}
	}

	return 0;
}

static void lxc_cgfsng_print_basecg_debuginfo(char *basecginfo, char **klist,
					      char **nlist)
{
	int k;
	char **it;

	TRACE("basecginfo is:");
	TRACE("%s", basecginfo);

	for (k = 0, it = klist; it && *it; it++, k++)
		TRACE("kernel subsystem %d: %s", k, *it);

	for (k = 0, it = nlist; it && *it; it++, k++)
		TRACE("named subsystem %d: %s", k, *it);
}

static int cgroup_tree_remove(struct hierarchy **hierarchies, const char *container_cgroup)
{
	if (!container_cgroup || !hierarchies)
		return 0;

	for (int i = 0; hierarchies[i]; i++) {
		struct hierarchy *h = hierarchies[i];
		int ret;

		if (!h->container_limit_path)
			continue;

		ret = lxc_rm_rf(h->container_limit_path);
		if (ret < 0)
			WARN("Failed to destroy \"%s\"", h->container_limit_path);

		if (h->container_limit_path != h->container_full_path)
			free_disarm(h->container_limit_path);
		free_disarm(h->container_full_path);
	}

	return 0;
}

struct generic_userns_exec_data {
	struct hierarchy **hierarchies;
	const char *container_cgroup;
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

	return cgroup_tree_remove(arg->hierarchies, arg->container_cgroup);
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

#ifdef HAVE_STRUCT_BPF_CGROUP_DEV_CTX
	ret = bpf_program_cgroup_detach(handler->cgroup_ops->cgroup2_devices);
	if (ret < 0)
		WARN("Failed to detach bpf program from cgroup");
#endif

	if (!lxc_list_empty(&handler->conf->id_map)) {
		struct generic_userns_exec_data wrap = {
			.conf			= handler->conf,
			.container_cgroup	= ops->container_cgroup,
			.hierarchies		= ops->hierarchies,
			.origuid		= 0,
		};
		ret = userns_exec_1(handler->conf, cgroup_tree_remove_wrapper,
				    &wrap, "cgroup_tree_remove_wrapper");
	} else {
		ret = cgroup_tree_remove(ops->hierarchies, ops->container_cgroup);
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
		return syserrno(false, "Failed to read file %d(cgroup.clone_children)", dfd_base);

	/*
	* Initialize cpuset.cpus and make remove any isolated
	* and offline cpus.
	 */
	if (!cpuset1_cpus_initialize(dfd_base, dfd_next, v == '1'))
		return syserrno(false, "Failed to initialize cpuset.cpus");

	/* Read cpuset.mems from parent... */
	bytes = lxc_readat(dfd_base, "cpuset.mems", mems, sizeof(mems));
	if (bytes < 0)
		return syserrno(false, "Failed to read file %d(cpuset.mems)", dfd_base);

	/* ... and copy to first cgroup in the tree... */
	bytes = lxc_writeat(dfd_next, "cpuset.mems", mems, bytes);
	if (bytes < 0)
		return syserrno(false, "Failed to write %d(cpuset.mems)", dfd_next);

	/* ... and finally turn on cpuset inheritance. */
	bytes = lxc_writeat(dfd_next, "cgroup.clone_children", "1", 1);
	if (bytes < 0)
		return syserrno(false, "Failed to write %d(cgroup.clone_children)", dfd_next);

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
		return ret_errno(-EINVAL);

	len = strlcpy(buf, path, sizeof(buf));
	if (len >= sizeof(buf))
		return -E2BIG;

	lxc_iterate_parts(cur, buf, "/") {
		/*
		 * Even though we vetted the paths when we parsed the config
		 * we're paranoid here and check that the path is neither
		 * absolute nor walks upwards.
		 */
		if (abspath(buf))
			return syserrno_set(-EINVAL, "No absolute paths allowed");

		if (strnequal(buf, "..", STRLITERALLEN("..")))
			return syserrno_set(-EINVAL, "No upward walking paths allowed");

		ret = mkdirat(dfd_cur, cur, mode);
		if (ret < 0) {
			if (errno != EEXIST)
				return syserrno(-errno, "Failed to create %d(%s)", dfd_cur, cur);

			ret = -EEXIST;
		}
		TRACE("%s %d(%s) cgroup", !ret ? "Created" : "Reusing", dfd_cur, cur);

		dfd_final = open_at(dfd_cur, cur, PROTECT_OPATH_DIRECTORY, PROTECT_LOOKUP_BENEATH, 0);
		if (dfd_final < 0)
			return syserrno(-errno, "Fail to open%s directory %d(%s)",
					!ret ? " newly created" : "", dfd_base, cur);
		if (dfd_cur != dfd_base)
			close(dfd_cur);
		else if (cpuset_v1 && !cpuset1_initialize(dfd_base, dfd_final))
			return syserrno(-EINVAL, "Failed to initialize cpuset controller in the legacy hierarchy");
		/*
		 * Leave dfd_final pointing to the last fd we opened so
		 * it will be automatically zapped if we return early.
		 */
		dfd_cur = dfd_final;
	}

	/* The final cgroup must be succesfully creatd by us. */
	if (ret) {
		if (ret != -EEXIST || !eexist_ignore)
			return syserrno_set(ret, "Creating the final cgroup %d(%s) failed", dfd_base, path);
	}

	return move_fd(dfd_final);
}

static bool cgroup_tree_create(struct cgroup_ops *ops, struct lxc_conf *conf,
			       struct hierarchy *h, const char *cgroup_tree,
			       const char *cgroup_leaf, bool payload,
			       const char *cgroup_limit_dir)
{
	__do_close int fd_limit = -EBADF, fd_final = -EBADF;
	__do_free char *path = NULL, *limit_path = NULL;
	bool cpuset_v1 = false;

	/* Don't bother with all the rest if the final cgroup already exists. */
	if (exists_dir_at(h->dfd_base, cgroup_leaf))
		return syswarn(false, "The %d(%s) cgroup already existed", h->dfd_base, cgroup_leaf);

	/*
	 * The legacy cpuset controller needs massaging in case inheriting
	 * settings from its immediate ancestor cgroup hasn't been turned on.
	 */
	cpuset_v1 = !is_unified_hierarchy(h) && string_in_list(h->controllers, "cpuset");

	if (payload && cgroup_limit_dir) {
		/* With isolation both parts need to not already exist. */
		fd_limit = __cgroup_tree_create(h->dfd_base, cgroup_limit_dir, 0755, cpuset_v1, false);
		if (fd_limit < 0)
			return syserrno(false, "Failed to create limiting cgroup %d(%s)", h->dfd_base, cgroup_limit_dir);

		limit_path = must_make_path(h->mountpoint, h->container_base_path, cgroup_limit_dir, NULL);

		/*
		 * With isolation the devices legacy cgroup needs to be
		 * iinitialized early, as it typically contains an 'a' (all)
		 * line, which is not possible once a subdirectory has been
		 * created.
		 */
		if (string_in_list(h->controllers, "devices") &&
		    !ops->setup_limits_legacy(ops, conf, true))
			return log_error(false, "Failed to setup legacy device limits");
	}

	fd_final = __cgroup_tree_create(h->dfd_base, cgroup_leaf, 0755, cpuset_v1, false);
	if (fd_final < 0)
		return syserrno(false, "Failed to create %s cgroup %d(%s)", payload ? "payload" : "monitor", h->dfd_base, cgroup_limit_dir);

	path = must_make_path(h->mountpoint, h->container_base_path, cgroup_leaf, NULL);
	if (payload) {
		h->cgfd_con = move_fd(fd_final);
		h->container_full_path = move_ptr(path);

		if (fd_limit < 0)
			h->cgfd_limit = h->cgfd_con;
		else
			h->cgfd_limit = move_fd(fd_limit);

		if (!limit_path)
			h->container_limit_path = h->container_full_path;
		else
			h->container_limit_path = move_ptr(limit_path);
	} else {
		h->cgfd_mon = move_fd(fd_final);
		h->monitor_full_path = move_ptr(path);
	}

	return true;
}

static void cgroup_tree_leaf_remove(struct hierarchy *h, bool payload)
{
	__do_free char *full_path = NULL, *__limit_path = NULL;
	char *limit_path = NULL;

	if (payload) {
		__lxc_unused __do_close int fd = move_fd(h->cgfd_con);
		full_path = move_ptr(h->container_full_path);
		limit_path = move_ptr(h->container_limit_path);
		if (limit_path != full_path)
			__limit_path = limit_path;
	} else {
		__lxc_unused __do_close int fd = move_fd(h->cgfd_mon);
		full_path = move_ptr(h->monitor_full_path);
	}

	if (full_path && rmdir(full_path))
		SYSWARN("Failed to rmdir(\"%s\") cgroup", full_path);
	if (limit_path && rmdir(limit_path))
		SYSWARN("Failed to rmdir(\"%s\") cgroup", limit_path);
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

	len = strnprintf(pidstr, sizeof(pidstr), "%d", handler->monitor_pid);
	if (len < 0)
		return;

	for (int i = 0; ops->hierarchies[i]; i++) {
		__do_close int fd_pivot = -EBADF;
		__do_free char *pivot_path = NULL;
		struct hierarchy *h = ops->hierarchies[i];
		bool cpuset_v1 = false;
		int ret;

		if (!h->monitor_full_path)
			continue;

		/* Monitor might have died before we entered the cgroup. */
		if (handler->monitor_pid <= 0) {
			WARN("No valid monitor process found while destroying cgroups");
			goto try_lxc_rm_rf;
		}

		if (conf->cgroup_meta.monitor_pivot_dir)
			pivot_path = must_make_path(conf->cgroup_meta.monitor_pivot_dir, CGROUP_PIVOT, NULL);
		else if (conf->cgroup_meta.monitor_dir)
			pivot_path = must_make_path(conf->cgroup_meta.monitor_dir, CGROUP_PIVOT, NULL);
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

try_lxc_rm_rf:
		ret = lxc_rm_rf(h->monitor_full_path);
		if (ret < 0)
			WARN("Failed to destroy \"%s\"", h->monitor_full_path);
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
	__do_free char *monitor_cgroup = NULL, *__cgroup_tree = NULL;
	const char *cgroup_tree;
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
		cgroup_tree = NULL;
		monitor_cgroup = strdup(conf->cgroup_meta.monitor_dir);
	} else if (conf->cgroup_meta.dir) {
		cgroup_tree = conf->cgroup_meta.dir;
		monitor_cgroup = must_concat(&len, conf->cgroup_meta.dir, "/",
					     DEFAULT_MONITOR_CGROUP_PREFIX,
					     handler->name,
					     CGROUP_CREATE_RETRY, NULL);
	} else if (ops->cgroup_pattern) {
		__cgroup_tree = lxc_string_replace("%n", handler->name, ops->cgroup_pattern);
		if (!__cgroup_tree)
			return ret_set_errno(false, ENOMEM);

		cgroup_tree = __cgroup_tree;
		monitor_cgroup = must_concat(&len, cgroup_tree, "/",
					     DEFAULT_MONITOR_CGROUP,
					     CGROUP_CREATE_RETRY, NULL);
	} else {
		cgroup_tree = NULL;
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
				               ops->hierarchies[i], cgroup_tree,
				               monitor_cgroup, false, NULL))
				continue;

			DEBUG("Failed to create cgroup \"%s\"", maybe_empty(ops->hierarchies[i]->monitor_full_path));
			for (int j = 0; j < i; j++)
				cgroup_tree_leaf_remove(ops->hierarchies[j], false);

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
	__do_free char *container_cgroup = NULL,
		       *__cgroup_tree = NULL,
		       *limiting_cgroup = NULL;
	const char *cgroup_tree;
	int idx = 0;
	int i;
	size_t len;
	char *suffix = NULL;
	struct lxc_conf *conf;

	if (!ops)
		return ret_set_errno(false, ENOENT);

	if (!ops->hierarchies)
		return true;

	if (ops->container_cgroup)
		return ret_set_errno(false, EEXIST);

	if (!handler || !handler->conf)
		return ret_set_errno(false, EINVAL);

	conf = handler->conf;

	if (!check_cgroup_dir_config(conf))
		return false;

	if (conf->cgroup_meta.container_dir) {
		cgroup_tree = NULL;

		limiting_cgroup = strdup(conf->cgroup_meta.container_dir);
		if (!limiting_cgroup)
			return ret_set_errno(false, ENOMEM);

		if (conf->cgroup_meta.namespace_dir) {
			container_cgroup = must_make_path(limiting_cgroup,
							  conf->cgroup_meta.namespace_dir,
							  NULL);
		} else {
			/* explicit paths but without isolation */
			container_cgroup = move_ptr(limiting_cgroup);
		}
	} else if (conf->cgroup_meta.dir) {
		cgroup_tree = conf->cgroup_meta.dir;
		container_cgroup = must_concat(&len, cgroup_tree, "/",
					     DEFAULT_PAYLOAD_CGROUP_PREFIX,
					     handler->name,
					     CGROUP_CREATE_RETRY, NULL);
	} else if (ops->cgroup_pattern) {
		__cgroup_tree = lxc_string_replace("%n", handler->name, ops->cgroup_pattern);
		if (!__cgroup_tree)
			return ret_set_errno(false, ENOMEM);

		cgroup_tree = __cgroup_tree;
		container_cgroup = must_concat(&len, cgroup_tree, "/",
					       DEFAULT_PAYLOAD_CGROUP,
					       CGROUP_CREATE_RETRY, NULL);
	} else {
		cgroup_tree = NULL;
		container_cgroup = must_concat(&len, DEFAULT_PAYLOAD_CGROUP_PREFIX,
					     handler->name,
					     CGROUP_CREATE_RETRY, NULL);
	}
	if (!container_cgroup)
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
					       ops->hierarchies[i], cgroup_tree,
					       container_cgroup, true,
					       limiting_cgroup))
				continue;

			DEBUG("Failed to create cgroup \"%s\"", ops->hierarchies[i]->container_full_path ?: "(null)");
			for (int j = 0; j < i; j++)
				cgroup_tree_leaf_remove(ops->hierarchies[j], true);

			idx++;
			break;
		}
	} while (ops->hierarchies[i] && idx > 0 && idx < 1000 && suffix);

	if (idx == 1000 || (!suffix && idx != 0))
		return log_error_errno(false, ERANGE, "Failed to create container cgroup");

	ops->container_cgroup = move_ptr(container_cgroup);
	INFO("The container process uses \"%s\" as cgroup", ops->container_cgroup);
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

		ret = lxc_writeat(h->cgfd_mon, "cgroup.procs", monitor, monitor_len);
		if (ret)
			return log_error_errno(false, errno, "Failed to enter cgroup \"%s\"", h->monitor_full_path);

		TRACE("Moved monitor into %s cgroup via %d", h->monitor_full_path, h->cgfd_mon);

		if (handler->transient_pid <= 0)
			continue;

		ret = lxc_writeat(h->cgfd_mon, "cgroup.procs", transient, transient_len);
		if (ret)
			return log_error_errno(false, errno, "Failed to enter cgroup \"%s\"", h->monitor_full_path);

		TRACE("Moved transient process into %s cgroup via %d", h->monitor_full_path, h->cgfd_mon);

		/*
		 * we don't keep the fds for non-unified hierarchies around
		 * mainly because we don't make use of them anymore after the
		 * core cgroup setup is done but also because there are quite a
		 * lot of them.
		 */
		if (!is_unified_hierarchy(h))
			close_prot_errno_disarm(h->cgfd_mon);
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

		ret = lxc_writeat(h->cgfd_con, "cgroup.procs", pidstr, len);
		if (ret != 0)
			return log_error_errno(false, errno, "Failed to enter cgroup \"%s\"", h->container_full_path);

		TRACE("Moved container into %s cgroup via %d", h->container_full_path, h->cgfd_con);
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
		int dirfd = arg->hierarchies[i]->cgfd_con;

		(void)fchowmodat(dirfd, "", destuid, nsgid, 0775);

		/*
		 * Failures to chown() these are inconvenient but not
		 * detrimental We leave these owned by the container launcher,
		 * so that container root can write to the files to attach.  We
		 * chmod() them 664 so that container systemd can write to the
		 * files (which systemd in wily insists on doing).
		 */

		if (arg->hierarchies[i]->version == CGROUP_SUPER_MAGIC)
			(void)fchowmodat(dirfd, "tasks", destuid, nsgid, 0664);

		(void)fchowmodat(dirfd, "cgroup.procs", destuid, nsgid, 0664);

		if (arg->hierarchies[i]->version != CGROUP2_SUPER_MAGIC)
			continue;

		for (char **p = arg->hierarchies[i]->cgroup2_chown; p && *p; p++)
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

__cgfsng_ops static void cgfsng_payload_finalize(struct cgroup_ops *ops)
{
	if (!ops)
		return;

	if (!ops->hierarchies)
		return;

	for (int i = 0; ops->hierarchies[i]; i++) {
		struct hierarchy *h = ops->hierarchies[i];
		/*
		 * we don't keep the fds for non-unified hierarchies around
		 * mainly because we don't make use of them anymore after the
		 * core cgroup setup is done but also because there are quite a
		 * lot of them.
		 */
		if (!is_unified_hierarchy(h))
			close_prot_errno_disarm(h->cgfd_con);
	}

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
            !faccessat(ops->unified->cgfd_con, "cgroup.freeze", F_OK,
                       AT_SYMLINK_NOFOLLOW)) {
		TRACE("Unified hierarchy supports freezer");
		ops->unified->freezer_controller = 1;
        }
}

/* cgroup-full:* is done, no need to create subdirs */
static inline bool cg_mount_needs_subdirs(int cg_flags)
{
	return !(cg_flags >= LXC_AUTO_CGROUP_FULL_RO);
}

/* After $rootfs/sys/fs/container/controller/the/cg/path has been created,
 * remount controller ro if needed and bindmount the cgroupfs onto
 * control/the/cg/path.
 */
static int cg_legacy_mount_controllers(int cg_flags, struct hierarchy *h,
				       char *controllerpath, char *cgpath,
				       const char *container_cgroup)
{
	__do_free char *sourcepath = NULL;
	int ret, remount_flags;
	int flags = MS_BIND;

	if ((cg_flags & LXC_AUTO_CGROUP_RO) || (cg_flags & LXC_AUTO_CGROUP_MIXED)) {
		ret = mount(controllerpath, controllerpath, "cgroup", MS_BIND, NULL);
		if (ret < 0)
			return log_error_errno(-1, errno, "Failed to bind mount \"%s\" onto \"%s\"",
					       controllerpath, controllerpath);

		remount_flags = add_required_remount_flags(controllerpath,
							   controllerpath,
							   flags | MS_REMOUNT);
		ret = mount(controllerpath, controllerpath, "cgroup",
			    remount_flags | MS_REMOUNT | MS_BIND | MS_RDONLY,
			    NULL);
		if (ret < 0)
			return log_error_errno(-1, errno, "Failed to remount \"%s\" ro", controllerpath);

		INFO("Remounted %s read-only", controllerpath);
	}

	sourcepath = must_make_path(h->mountpoint, h->container_base_path,
				    container_cgroup, NULL);
	if ((cg_flags & LXC_AUTO_CGROUP_RO))
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
static int __cgroupfs_mount(int cg_flags, struct hierarchy *h,
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

	if ((cg_flags & LXC_AUTO_CGROUP_RO) ||
	    (cg_flags & LXC_AUTO_CGROUP_FULL_RO))
		flags |= MOUNT_ATTR_RDONLY;

	if (is_unified_hierarchy(h)) {
		fstype = "cgroup2";
	} else {
		fstype = "cgroup";
	}

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

static inline int cgroupfs_mount(int cg_flags, struct hierarchy *h,
				 struct lxc_rootfs *rootfs,
				 int dfd_mnt_cgroupfs, const char *hierarchy_mnt)
{
	return __cgroupfs_mount(cg_flags, h, rootfs, dfd_mnt_cgroupfs, hierarchy_mnt);
}

static inline int cgroupfs_bind_mount(int cg_flags, struct hierarchy *h,
				      struct lxc_rootfs *rootfs,
				      int dfd_mnt_cgroupfs,
				      const char *hierarchy_mnt)
{
	if (!(cg_flags & LXC_AUTO_CGROUP_FULL_RO) &&
	    !(cg_flags & LXC_AUTO_CGROUP_FULL_MIXED))
		return 0;

	return __cgroupfs_mount(cg_flags, h, rootfs, dfd_mnt_cgroupfs, hierarchy_mnt);
}

__cgfsng_ops static bool cgfsng_mount(struct cgroup_ops *ops,
				      struct lxc_handler *handler, int cg_flags)
{
	__do_close int dfd_mnt_cgroupfs = -EBADF, fd_fs = -EBADF;
	__do_free char *cgroup_root = NULL;
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

	if (cg_flags & LXC_AUTO_CGROUP_FORCE)
		wants_force_mount = true;

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

	if (cgns_supported() && container_uses_namespace(handler, CLONE_NEWCGROUP)) {
		in_cgroup_ns = true;
		/*
		 * When cgroup namespaces are supported and used by the
		 * container the LXC_AUTO_CGROUP_MIXED and
		 * LXC_AUTO_CGROUP_FULL_MIXED auto mount options don't apply
		 * since the parent directory of the container's cgroup is not
		 * accessible to the container.
		 */
		cg_flags &= ~LXC_AUTO_CGROUP_MIXED;
		cg_flags &= ~LXC_AUTO_CGROUP_FULL_MIXED;
	}

	if (in_cgroup_ns && !wants_force_mount)
		return log_trace(true, "Mounting cgroups not requested or needed");

	/*
	 * Fallback to a mixed layout when the user did not specify what cgroup
	 * layout they want.
	 */
	if ((cg_flags & LXC_AUTO_CGROUP_NOSPEC))
		cg_flags = LXC_AUTO_CGROUP_MIXED;
	else if (cg_flags & LXC_AUTO_CGROUP_FULL_NOSPEC)
		cg_flags = LXC_AUTO_CGROUP_FULL_MIXED;

	/* This is really the codepath that we want. */
	if (pure_unified_layout(ops)) {
		dfd_mnt_cgroupfs = open_at(rootfs->dfd_mnt,
					   DEFAULT_CGROUP_MOUNTPOINT_RELATIVE,
					   PROTECT_OPATH_DIRECTORY,
					   PROTECT_LOOKUP_BENEATH_XDEV, 0);
		if (dfd_mnt_cgroupfs < 0)
			return log_error_errno(-errno, errno, "Failed to open %d(%s)",
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
			ret = cgroupfs_mount(cg_flags, ops->unified, rootfs, dfd_mnt_cgroupfs, "");
			if (ret < 0)
				return syserrno(false, "Failed to force mount cgroup filesystem in cgroup namespace");

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

		return syserrno(false, "Failed to mount cgroups");
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

	dfd_mnt_cgroupfs = open_at(rootfs->dfd_mnt,
				   DEFAULT_CGROUP_MOUNTPOINT_RELATIVE,
				   PROTECT_OPATH_DIRECTORY,
				   PROTECT_LOOKUP_BENEATH_XDEV, 0);
	if (dfd_mnt_cgroupfs < 0)
		return log_error_errno(-errno, errno, "Failed to open %d(%s)",
				       rootfs->dfd_mnt, DEFAULT_CGROUP_MOUNTPOINT_RELATIVE);

	for (int i = 0; ops->hierarchies[i]; i++) {
		__do_free char *controllerpath = NULL, *path2 = NULL;
		struct hierarchy *h = ops->hierarchies[i];
		char *controller = strrchr(h->mountpoint, '/');

		if (!controller)
			continue;
		controller++;

		ret = mkdirat(dfd_mnt_cgroupfs, controller, 0000);
		if (ret < 0)
			return log_error_errno(false, errno, "Failed to create cgroup mountpoint %d(%s)", dfd_mnt_cgroupfs, controller);

		if (in_cgroup_ns && wants_force_mount) {
			/*
			 * If cgroup namespaces are supported but the container
			 * will not have CAP_SYS_ADMIN after it has started we
			 * need to mount the cgroups manually.
			 */
			ret = cgroupfs_mount(cg_flags, h, rootfs, dfd_mnt_cgroupfs, controller);
			if (ret < 0)
				return false;

			continue;
		}

		/* Here is where the ancient kernel section begins. */
		ret = cgroupfs_bind_mount(cg_flags, h, rootfs, dfd_mnt_cgroupfs, controller);
		if (ret < 0)
			return false;

		if (!cg_mount_needs_subdirs(cg_flags))
			continue;

		controllerpath = must_make_path(cgroup_root, controller, NULL);
		if (dir_exists(controllerpath))
			continue;

		path2 = must_make_path(controllerpath, h->container_base_path, ops->container_cgroup, NULL);
		ret = mkdir_p(path2, 0755);
		if (ret < 0)
			return false;

		ret = cg_legacy_mount_controllers(cg_flags, h, controllerpath, path2, ops->container_cgroup);
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

		fullpath =
		    must_make_path(ops->hierarchies[i]->mountpoint,
				   ops->hierarchies[i]->container_base_path,
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

	/* sanity check n */
	for (i = 0; i < n; i++)
		if (!ops->hierarchies[i])
			return ret_set_errno(false, ENOENT);

	*out = ops->hierarchies[i]->controllers;

	return true;
}

static bool cg_legacy_freeze(struct cgroup_ops *ops)
{
	struct hierarchy *h;

	h = get_hierarchy(ops, "freezer");
	if (!h)
		return ret_set_errno(-1, ENOENT);

	return lxc_write_openat(h->container_full_path, "freezer.state",
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

	if (!h->container_full_path)
		return ret_set_errno(-1, EEXIST);

	if (timeout != 0) {
		__do_free char *events_file = NULL;

		events_file = must_make_path(h->container_full_path, "cgroup.events", NULL);
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

	ret = lxc_write_openat(h->container_full_path, "cgroup.freeze", state_string, 1);
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

	return lxc_write_openat(h->container_full_path, "freezer.state",
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

	h = get_hierarchy(ops, controller);
	if (!h)
		return log_warn_errno(NULL, ENOENT, "Failed to find hierarchy for controller \"%s\"",
				      controller ? controller : "(null)");

	if (limiting)
		return h->container_limit_path
			   ? h->container_limit_path + strlen(h->mountpoint)
			   : NULL;

	return h->container_full_path
		   ? h->container_full_path + strlen(h->mountpoint)
		   : NULL;
}

__cgfsng_ops static const char *cgfsng_get_cgroup(struct cgroup_ops *ops,
						  const char *controller)
{
    return cgfsng_get_cgroup_do(ops, controller, false);
}

__cgfsng_ops static const char *cgfsng_get_limiting_cgroup(struct cgroup_ops *ops,
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
	return must_make_path(h->mountpoint, inpath, filename, NULL);
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
	int target_fds[2];
	char pidstr[INTTYPE_TO_STRLEN(int64_t) + 1];
	size_t pidstr_len;
	ssize_t ret;

	ret = lxc_abstract_unix_recv_fds(sk, target_fds, 2, NULL, 0);
	if (ret <= 0)
		return log_error_errno(-1, errno, "Failed to receive target cgroup fd");
	target_fd0 = target_fds[0];
	target_fd1 = target_fds[1];

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
	if (ret != -ENOCGROUP2)
		return log_error_errno(ret, errno, "Failed to attach to unified cgroup");

	/* Fall back to retrieving the path for the unified cgroup. */
	cgroup = lxc_cmd_get_cgroup_path(name, lxcpath, controller);
	/* not running */
	if (!cgroup)
		return 0;

	path = must_make_path(h->mountpoint, cgroup, NULL);

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

		if (h->version == CGROUP2_SUPER_MAGIC) {
			ret = __cg_unified_attach(h, conf, name, lxcpath, pid,
						  h->controllers[0]);
			if (ret < 0)
				return false;

			continue;
		}

		path = lxc_cmd_get_cgroup_path(name, lxcpath, h->controllers[0]);
		/* not running */
		if (!path)
			return false;

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

	controller = must_copy_string(filename);
	p = strchr(controller, '.');
	if (p)
		*p = '\0';

	path = lxc_cmd_get_limiting_cgroup_path(name, lxcpath, controller);
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
		device->allow = 1;
	else
		device->allow = 0;

	if (strequal(val, "a")) {
		/* global rule */
		device->type = 'a';
		device->major = -1;
		device->minor = -1;
		device->global_rule = device->allow
					  ? LXC_BPF_DEVICE_CGROUP_DENYLIST
					  : LXC_BPF_DEVICE_CGROUP_ALLOWLIST;
		device->allow = -1;
		return 0;
	}

	/* local rule */
	device->global_rule = LXC_BPF_DEVICE_CGROUP_LOCAL_RULE;

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

	controller = must_copy_string(key);
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

	path = lxc_cmd_get_limiting_cgroup_path(name, lxcpath, controller);
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

	path = must_copy_string(devpath);

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
	device->global_rule = LXC_BPF_DEVICE_CGROUP_LOCAL_RULE;

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

	controller = must_copy_string(filename);
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
		int ret = lxc_write_openat(h->container_full_path, filename, value, strlen(value));
		if (ret)
			return ret;
	}
	return lxc_write_openat(h->container_limit_path, filename, value, strlen(value));
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
#ifdef HAVE_STRUCT_BPF_CGROUP_DEV_CTX
	struct device_item device_item = {};
	int ret;

	if (strequal("devices.allow", key) && *val == '/')
		ret = device_cgroup_rule_parse_devpath(&device_item, val);
	else
		ret = device_cgroup_rule_parse(&device_item, key, val);
	if (ret < 0)
		return log_error_errno(-1, EINVAL, "Failed to parse device string %s=%s", key, val);

	ret = bpf_list_add_device(conf, &device_item);
	if (ret < 0)
		return -1;
#endif
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
			ret = lxc_write_openat(h->container_limit_path, cg->subsystem, cg->value, strlen(cg->value));
		if (ret < 0)
			return log_error_errno(false, errno, "Failed to set \"%s\" to \"%s\"", cg->subsystem, cg->value);

		TRACE("Set \"%s\" to \"%s\"", cg->subsystem, cg->value);
	}

	return log_info(true, "Limits for the unified cgroup hierarchy have been setup");
}

__cgfsng_ops static bool cgfsng_devices_activate(struct cgroup_ops *ops, struct lxc_handler *handler)
{
#ifdef HAVE_STRUCT_BPF_CGROUP_DEV_CTX
	__do_bpf_program_free struct bpf_program *prog = NULL;
	int ret;
	struct lxc_conf *conf;
	struct hierarchy *unified;
	struct lxc_list *it;
	struct bpf_program *prog_old;

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
	if (!unified || !unified->bpf_device_controller ||
	    !unified->container_full_path || lxc_list_empty(&conf->devices))
		return true;

	prog = bpf_program_new(BPF_PROG_TYPE_CGROUP_DEVICE);
	if (!prog)
		return log_error_errno(false, ENOMEM, "Failed to create new bpf program");

	ret = bpf_program_init(prog);
	if (ret)
		return log_error_errno(false, ENOMEM, "Failed to initialize bpf program");

	lxc_list_for_each(it, &conf->devices) {
		struct device_item *cur = it->elem;

		ret = bpf_program_append_device(prog, cur);
		if (ret)
			return log_error_errno(false, ENOMEM, "Failed to add new rule to bpf device program: type %c, major %d, minor %d, access %s, allow %d, global_rule %d",
					       cur->type,
					       cur->major,
					       cur->minor,
					       cur->access,
					       cur->allow,
					       cur->global_rule);
		TRACE("Added rule to bpf device program: type %c, major %d, minor %d, access %s, allow %d, global_rule %d",
		      cur->type,
		      cur->major,
		      cur->minor,
		      cur->access,
		      cur->allow,
		      cur->global_rule);
	}

	ret = bpf_program_finalize(prog);
	if (ret)
		return log_error_errno(false, ENOMEM, "Failed to finalize bpf program");

	ret = bpf_program_cgroup_attach(prog, BPF_CGROUP_DEVICE,
					unified->container_limit_path,
					BPF_F_ALLOW_MULTI);
	if (ret)
		return log_error_errno(false, ENOMEM, "Failed to attach bpf program");

	/* Replace old bpf program. */
	prog_old = move_ptr(ops->cgroup2_devices);
	ops->cgroup2_devices = move_ptr(prog);
	prog = move_ptr(prog_old);
#endif
	return true;
}

static bool __cgfsng_delegate_controllers(struct cgroup_ops *ops, const char *cgroup)
{
	__do_close int fd_base = -EBADF;
	__do_free char *add_controllers = NULL, *base_path = NULL;
	__do_free_string_list char **parts = NULL;
	struct hierarchy *unified = ops->unified;
	ssize_t parts_len;
	char **it;
	size_t full_len = 0;

	if (!ops->hierarchies || !pure_unified_layout(ops) ||
	    !unified->controllers[0])
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

	base_path = must_make_path(unified->mountpoint, unified->container_base_path, NULL);
	fd_base = lxc_open_dirfd(base_path);
	if (fd_base < 0)
		return false;

	if (!unified_cgroup_fd(fd_base))
		return log_error_errno(false, EINVAL, "File descriptor does not refer to cgroup2 filesystem");

	parts = lxc_string_split(cgroup, '/');
	if (!parts)
		return false;

	parts_len = lxc_array_len((void **)parts);
	if (parts_len > 0)
		parts_len--;

	for (ssize_t i = -1; i < parts_len; i++) {
		int ret;

		if (i >= 0) {
			int fd_next;

			fd_next = openat(fd_base, parts[i], PROTECT_OPATH_DIRECTORY, PROTECT_LOOKUP_BENEATH);
			if (fd_next < 0)
				return log_error_errno(false, errno, "Failed to open %d(%s)", fd_next, parts[i]);
			close_prot_errno_move(fd_base, fd_next);
		}

		ret = lxc_writeat(fd_base, "cgroup.subtree_control", add_controllers, full_len);
		if (ret < 0)
			return log_error_errno(false, errno,
					       "Could not enable \"%s\" controllers in the unified cgroup %d(%s)",
					       add_controllers, fd_base, (i >= 0) ? parts[i] : unified->container_base_path);

		TRACE("Enable \"%s\" controllers in the unified cgroup %d(%s)",
		      add_controllers, fd_base, (i >= 0) ? parts[i] : unified->container_base_path);
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

static void cg_unified_delegate(char ***delegate)
{
	__do_free char *buf = NULL;
	char *standard[] = {"cgroup.subtree_control", "cgroup.threads", NULL};
	char *token;
	int idx;

	buf = read_file_at(-EBADF, "/sys/kernel/cgroup/delegate", PROTECT_OPEN, 0);
	if (!buf) {
		for (char **p = standard; p && *p; p++) {
			idx = append_null_to_list((void ***)delegate);
			(*delegate)[idx] = must_copy_string(*p);
		}
		SYSWARN("Failed to read /sys/kernel/cgroup/delegate");
		return;
	}

	lxc_iterate_parts(token, buf, " \t\n") {
		/*
		 * We always need to chown this for both cgroup and
		 * cgroup2.
		 */
		if (strequal(token, "cgroup.procs"))
			continue;

		idx = append_null_to_list((void ***)delegate);
		(*delegate)[idx] = must_copy_string(token);
	}
}

/* At startup, parse_hierarchies finds all the info we need about cgroup
 * mountpoints and current cgroups, and stores it in @d.
 */
static int cg_hybrid_init(struct cgroup_ops *ops, bool relative, bool unprivileged)
{
	__do_free char *basecginfo = NULL, *line = NULL;
	__do_free_string_list char **klist = NULL, **nlist = NULL;
	__do_fclose FILE *f = NULL;
	int ret;
	size_t len = 0;

	/* Root spawned containers escape the current cgroup, so use init's
	 * cgroups as our base in that case.
	 */
	if (!relative && (geteuid() == 0))
		basecginfo = read_file_at(-EBADF, "/proc/1/cgroup", PROTECT_OPEN, 0);
	else
		basecginfo = read_file_at(-EBADF, "/proc/self/cgroup", PROTECT_OPEN, 0);
	if (!basecginfo)
		return ret_set_errno(-1, ENOMEM);

	ret = get_existing_subsystems(&klist, &nlist);
	if (ret < 0)
		return log_error_errno(-1, errno, "Failed to retrieve available legacy cgroup controllers");

	f = fopen("/proc/self/mountinfo", "re");
	if (!f)
		return log_error_errno(-1, errno, "Failed to open \"/proc/self/mountinfo\"");

	lxc_cgfsng_print_basecg_debuginfo(basecginfo, klist, nlist);

	while (getline(&line, &len, f) != -1) {
		__do_free char *base_cgroup = NULL, *mountpoint = NULL;
		__do_free_string_list char **controller_list = NULL;
		int type;
		bool writeable;

		type = get_cgroup_version(line);
		if (type == 0)
			continue;

		if (type == CGROUP2_SUPER_MAGIC && ops->unified)
			continue;

		if (ops->cgroup_layout == CGROUP_LAYOUT_UNKNOWN) {
			if (type == CGROUP2_SUPER_MAGIC)
				ops->cgroup_layout = CGROUP_LAYOUT_UNIFIED;
			else if (type == CGROUP_SUPER_MAGIC)
				ops->cgroup_layout = CGROUP_LAYOUT_LEGACY;
		} else if (ops->cgroup_layout == CGROUP_LAYOUT_UNIFIED) {
			if (type == CGROUP_SUPER_MAGIC)
				ops->cgroup_layout = CGROUP_LAYOUT_HYBRID;
		} else if (ops->cgroup_layout == CGROUP_LAYOUT_LEGACY) {
			if (type == CGROUP2_SUPER_MAGIC)
				ops->cgroup_layout = CGROUP_LAYOUT_HYBRID;
		}

		controller_list = cg_hybrid_get_controllers(klist, nlist, line, type);
		if (!controller_list && type == CGROUP_SUPER_MAGIC)
			continue;

		if (type == CGROUP_SUPER_MAGIC)
			if (controller_list_is_dup(ops->hierarchies, controller_list)) {
				TRACE("Skipping duplicating controller");
				continue;
			}

		mountpoint = cg_hybrid_get_mountpoint(line);
		if (!mountpoint) {
			WARN("Failed parsing mountpoint from \"%s\"", line);
			continue;
		}

		if (type == CGROUP_SUPER_MAGIC)
			base_cgroup = cg_hybrid_get_current_cgroup(relative, basecginfo, controller_list[0], CGROUP_SUPER_MAGIC);
		else
			base_cgroup = cg_hybrid_get_current_cgroup(relative, basecginfo, NULL, CGROUP2_SUPER_MAGIC);
		if (!base_cgroup) {
			WARN("Failed to find current cgroup");
			continue;
		}

		if (type == CGROUP2_SUPER_MAGIC)
			writeable = test_writeable_v2(mountpoint, base_cgroup);
		else
			writeable = test_writeable_v1(mountpoint, base_cgroup);
		if (!writeable) {
			TRACE("The %s group is not writeable", base_cgroup);
			continue;
		}

		if (type == CGROUP2_SUPER_MAGIC)
			ret = add_hierarchy(ops, NULL, move_ptr(mountpoint), move_ptr(base_cgroup), type);
		else
			ret = add_hierarchy(ops, move_ptr(controller_list), move_ptr(mountpoint), move_ptr(base_cgroup), type);
		if (ret)
			return syserrno(ret, "Failed to add cgroup hierarchy");
		if (ops->unified && unprivileged)
			cg_unified_delegate(&(ops->unified)->cgroup2_chown);
	}

	/* verify that all controllers in cgroup.use and all crucial
	 * controllers are accounted for
	 */
	if (!all_controllers_found(ops))
		return log_error_errno(-1, ENOENT, "Failed to find all required controllers");

	return 0;
}

/* Get current cgroup from /proc/self/cgroup for the cgroupfs v2 hierarchy. */
static char *cg_unified_get_current_cgroup(bool relative)
{
	__do_free char *basecginfo = NULL, *copy = NULL;
	char *base_cgroup;

	if (!relative && (geteuid() == 0))
		basecginfo = read_file_at(-EBADF, "/proc/1/cgroup", PROTECT_OPEN, 0);
	else
		basecginfo = read_file_at(-EBADF, "/proc/self/cgroup", PROTECT_OPEN, 0);
	if (!basecginfo)
		return NULL;

	base_cgroup = strstr(basecginfo, "0::/");
	if (!base_cgroup)
		return NULL;

	base_cgroup = base_cgroup + 3;
	copy = copy_to_eol(base_cgroup);
	if (!copy)
		return NULL;
	trim(copy);

	if (!relative) {
		base_cgroup = prune_init_scope(copy);
		if (!base_cgroup)
			return NULL;
	} else {
		base_cgroup = copy;
	}

	if (abspath(base_cgroup))
		base_cgroup = deabs(base_cgroup);

	/* We're allowing base_cgroup to be "". */
	return strdup(base_cgroup);
}

static int cg_unified_init(struct cgroup_ops *ops, bool relative,
			   bool unprivileged)
{
	__do_free char *base_cgroup = NULL;
	int ret;

	base_cgroup = cg_unified_get_current_cgroup(relative);
	if (!base_cgroup)
		return ret_errno(EINVAL);

	/* TODO: If the user requested specific controllers via lxc.cgroup.use
	 * we should verify here. The reason I'm not doing it right is that I'm
	 * not convinced that lxc.cgroup.use will be the future since it is a
	 * global property. I much rather have an option that lets you request
	 * controllers per container.
	 */

	ret = add_hierarchy(ops, NULL,
			    must_copy_string(DEFAULT_CGROUP_MOUNTPOINT),
			    move_ptr(base_cgroup), CGROUP2_SUPER_MAGIC);
	if (ret)
		return syserrno(ret, "Failed to add unified cgroup hierarchy");

	if (unprivileged)
		cg_unified_delegate(&(ops->unified)->cgroup2_chown);

	if (bpf_devices_cgroup_supported())
		ops->unified->bpf_device_controller = 1;

	ops->cgroup_layout = CGROUP_LAYOUT_UNIFIED;
	return CGROUP2_SUPER_MAGIC;
}

static int __cgroup_init(struct cgroup_ops *ops, struct lxc_conf *conf)
{
	__do_close int dfd = -EBADF;
	bool relative = conf->cgroup_meta.relative;
	int ret;
	const char *tmp;

	if (ops->dfd_mnt_cgroupfs_host >= 0)
		return ret_errno(EINVAL);

	/*
	 * I don't see the need for allowing symlinks here. If users want to
	 * have their hierarchy available in different locations I strongly
	 * suggest bind-mounts.
	 */
	dfd = open_at(-EBADF, DEFAULT_CGROUP_MOUNTPOINT,
			PROTECT_OPATH_DIRECTORY, PROTECT_LOOKUP_ABSOLUTE_XDEV, 0);
	if (dfd < 0)
		return syserrno(-errno, "Failed to open " DEFAULT_CGROUP_MOUNTPOINT);

	tmp = lxc_global_config_value("lxc.cgroup.use");
	if (tmp) {
		__do_free char *pin = NULL;
		char *chop, *cur;

		pin = must_copy_string(tmp);
		chop = pin;

		lxc_iterate_parts(cur, chop, ",")
			must_append_string(&ops->cgroup_use, cur);
	}

	/*
	 * Keep dfd referenced by the cleanup function and actually move the fd
	 * once we know the initialization succeeded. So if we fail we clean up
	 * the dfd.
	 */
	ops->dfd_mnt_cgroupfs_host = dfd;

	if (unified_cgroup_fd(dfd))
		ret = cg_unified_init(ops, relative, !lxc_list_empty(&conf->id_map));
	else
		ret = cg_hybrid_init(ops, relative, !lxc_list_empty(&conf->id_map));
	if (ret < 0)
		return syserrno(ret, "Failed to initialize cgroups");

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
	if (cgroup_pattern && !strequal(cgroup_pattern, ""))
		ops->cgroup_pattern = must_copy_string(cgroup_pattern);

	return 0;
}

struct cgroup_ops *cgfsng_ops_init(struct lxc_conf *conf)
{
	__do_free struct cgroup_ops *cgfsng_ops = NULL;

	cgfsng_ops = zalloc(sizeof(struct cgroup_ops));
	if (!cgfsng_ops)
		return ret_set_errno(NULL, ENOMEM);

	cgfsng_ops->cgroup_layout = CGROUP_LAYOUT_UNKNOWN;
	cgfsng_ops->dfd_mnt_cgroupfs_host = -EBADF;

	if (__cgroup_init(cgfsng_ops, conf))
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
	cgfsng_ops->payload_finalize			= cgfsng_payload_finalize;
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
	cgfsng_ops->get_limiting_cgroup			= cgfsng_get_limiting_cgroup;

	cgfsng_ops->criu_escape				= cgfsng_criu_escape;
	cgfsng_ops->criu_num_hierarchies		= cgfsng_criu_num_hierarchies;
	cgfsng_ops->criu_get_hierarchies		= cgfsng_criu_get_hierarchies;

	return move_ptr(cgfsng_ops);
}

int cgroup_attach(const struct lxc_conf *conf, const char *name,
		  const char *lxcpath, pid_t pid)
{
	__do_close int unified_fd = -EBADF;
	int ret;

	if (!conf || is_empty_string(name) || is_empty_string(lxcpath) || pid <= 0)
		return ret_errno(EINVAL);

	unified_fd = lxc_cmd_get_cgroup2_fd(name, lxcpath);
	if (unified_fd < 0)
		return ret_errno(ENOCGROUP2);

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

/* Connects to command socket therefore isn't callable from command handler. */
int cgroup_get(const char *name, const char *lxcpath,
	       const char *filename, char *buf, size_t len)
{
	__do_close int unified_fd = -EBADF;
	ssize_t ret;

	if (is_empty_string(filename) || is_empty_string(name) ||
	    is_empty_string(lxcpath))
		return ret_errno(EINVAL);

	if ((buf && !len) || (len && !buf))
		return ret_errno(EINVAL);

	unified_fd = lxc_cmd_get_limiting_cgroup2_fd(name, lxcpath);
	if (unified_fd < 0)
		return ret_errno(ENOCGROUP2);

	ret = lxc_read_try_buf_at(unified_fd, filename, buf, len);
	if (ret < 0)
		SYSERROR("Failed to read cgroup value");

	return ret;
}

/* Connects to command socket therefore isn't callable from command handler. */
int cgroup_set(const char *name, const char *lxcpath,
	       const char *filename, const char *value)
{
	__do_close int unified_fd = -EBADF;
	ssize_t ret;

	if (is_empty_string(filename) || is_empty_string(value) ||
	    is_empty_string(name) || is_empty_string(lxcpath))
		return ret_errno(EINVAL);

	unified_fd = lxc_cmd_get_limiting_cgroup2_fd(name, lxcpath);
	if (unified_fd < 0)
		return ret_errno(ENOCGROUP2);

	if (strnequal(filename, "devices.", STRLITERALLEN("devices."))) {
		struct device_item device = {};

		ret = device_cgroup_rule_parse(&device, filename, value);
		if (ret < 0)
			return log_error_errno(-1, EINVAL, "Failed to parse device string %s=%s", filename, value);

		ret = lxc_cmd_add_bpf_device_cgroup(name, lxcpath, &device);
	} else {
		ret = lxc_writeat(unified_fd, filename, value, strlen(value));
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

	unified_fd = lxc_cmd_get_limiting_cgroup2_fd(name, lxcpath);
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

	unified_fd = lxc_cmd_get_limiting_cgroup2_fd(name, lxcpath);
	if (unified_fd < 0)
		return ret_errno(ENOCGROUP2);

	lxc_cmd_notify_state_listeners(name, lxcpath, THAWED);
	ret = __cgroup_unfreeze(unified_fd, timeout);
	lxc_cmd_notify_state_listeners(name, lxcpath, !ret ? RUNNING : FROZEN);
	return ret;
}
