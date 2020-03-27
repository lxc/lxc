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
#include <sys/types.h>
#include <unistd.h>

#include "caps.h"
#include "cgroup.h"
#include "cgroup2_devices.h"
#include "cgroup_utils.h"
#include "commands.h"
#include "conf.h"
#include "config.h"
#include "log.h"
#include "macro.h"
#include "mainloop.h"
#include "memory_utils.h"
#include "storage/storage.h"
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
		if (strcmp(list[i], entry) == 0)
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

	if (strncmp(entry, "name=", 5) == 0)
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
struct hierarchy *get_hierarchy(struct cgroup_ops *ops, const char *controller)
{
	if (!ops->hierarchies)
		return log_trace_errno(NULL, errno, "There are no useable cgroup controllers");

	for (int i = 0; ops->hierarchies[i]; i++) {
		if (!controller) {
			/* This is the empty unified hierarchy. */
			if (ops->hierarchies[i]->controllers &&
			    !ops->hierarchies[i]->controllers[0])
				return ops->hierarchies[i];
			continue;
		} else if (pure_unified_layout(ops) &&
			   strcmp(controller, "devices") == 0) {
			if (ops->unified->bpf_device_controller)
				return ops->unified;
			break;
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

#define BATCH_SIZE 50
static void batch_realloc(char **mem, size_t oldlen, size_t newlen)
{
	int newbatches = (newlen / BATCH_SIZE) + 1;
	int oldbatches = (oldlen / BATCH_SIZE) + 1;

	if (!*mem || newbatches > oldbatches)
		*mem = must_realloc(*mem, newbatches * BATCH_SIZE);
}

static void append_line(char **dest, size_t oldlen, char *new, size_t newlen)
{
	size_t full = oldlen + newlen;

	batch_realloc(dest, oldlen, full + 1);

	memcpy(*dest + oldlen, new, newlen + 1);
}

/* Slurp in a whole file */
static char *read_file(const char *fnam)
{
	__do_free char *buf = NULL, *line = NULL;
	__do_fclose FILE *f = NULL;
	size_t len = 0, fulllen = 0;
	int linelen;

	f = fopen(fnam, "re");
	if (!f)
		return NULL;

	while ((linelen = getline(&line, &len, f)) != -1) {
		append_line(&buf, fulllen, line, linelen);
		fulllen += linelen;
	}

	return move_ptr(buf);
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

		ret = snprintf(numstr, sizeof(numstr), "%zu", i);
		if (ret < 0 || (size_t)ret >= sizeof(numstr))
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

#define __ISOL_CPUS "/sys/devices/system/cpu/isolated"
#define __OFFLINE_CPUS "/sys/devices/system/cpu/offline"
static bool cg_legacy_filter_and_set_cpus(const char *parent_cgroup,
					  char *child_cgroup, bool am_initialized)
{
	__do_free char *cpulist = NULL, *fpath = NULL, *isolcpus = NULL,
		       *offlinecpus = NULL, *posscpus = NULL;
	__do_free uint32_t *isolmask = NULL, *offlinemask = NULL,
			   *possmask = NULL;
	int ret;
	ssize_t i;
	ssize_t maxisol = 0, maxoffline = 0, maxposs = 0;
	bool flipped_bit = false;

	fpath = must_make_path(parent_cgroup, "cpuset.cpus", NULL);
	posscpus = read_file(fpath);
	if (!posscpus)
		return log_error_errno(false, errno, "Failed to read file \"%s\"", fpath);

	/* Get maximum number of cpus found in possible cpuset. */
	maxposs = get_max_cpus(posscpus);
	if (maxposs < 0 || maxposs >= INT_MAX - 1)
		return false;

	if (file_exists(__ISOL_CPUS)) {
		isolcpus = read_file(__ISOL_CPUS);
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
		offlinecpus = read_file(__OFFLINE_CPUS);
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
		ret = lxc_write_openat(child_cgroup, "cpuset.cpus", cpulist, strlen(cpulist));
		if (ret < 0)
			return log_error_errno(false,
					       errno, "Failed to write cpu list to \"%s/cpuset.cpus\"",
					       child_cgroup);

		TRACE("Copied cpu settings of parent cgroup");
	}

	return true;
}

/* Copy contents of parent(@path)/@file to @path/@file */
static bool copy_parent_file(const char *parent_cgroup,
			     const char *child_cgroup, const char *file)
{
	__do_free char *parent_file = NULL, *value = NULL;
	int len = 0;
	int ret;

	parent_file = must_make_path(parent_cgroup, file, NULL);
	len = lxc_read_from_file(parent_file, NULL, 0);
	if (len <= 0)
		return log_error_errno(false, errno, "Failed to determine buffer size");

	value = must_realloc(NULL, len + 1);
	value[len] = '\0';
	ret = lxc_read_from_file(parent_file, value, len);
	if (ret != len)
		return log_error_errno(false, errno, "Failed to read from parent file \"%s\"", parent_file);

	ret = lxc_write_openat(child_cgroup, file, value, len);
	if (ret < 0 && errno != EACCES)
		return log_error_errno(false, errno, "Failed to write \"%s\" to file \"%s/%s\"",
				       value, child_cgroup, file);
	return true;
}

static inline bool is_unified_hierarchy(const struct hierarchy *h)
{
	return h->version == CGROUP2_SUPER_MAGIC;
}

/*
 * Initialize the cpuset hierarchy in first directory of @cgroup_leaf and set
 * cgroup.clone_children so that children inherit settings. Since the
 * h->base_path is populated by init or ourselves, we know it is already
 * initialized.
 *
 * returns -1 on error, 0 when we didn't created a cgroup, 1 if we created a
 * cgroup.
 */
static int cg_legacy_handle_cpuset_hierarchy(struct hierarchy *h,
					     const char *cgroup_leaf)
{
	__do_free char *parent_cgroup = NULL, *child_cgroup = NULL, *dup = NULL;
	__do_close int cgroup_fd = -EBADF;
	int fret = -1;
	int ret;
	char v;
	char *leaf, *slash;

	if (is_unified_hierarchy(h))
		return 0;

	if (!string_in_list(h->controllers, "cpuset"))
		return 0;

	if (!cgroup_leaf)
		return ret_set_errno(-1, EINVAL);

	dup = strdup(cgroup_leaf);
	if (!dup)
		return ret_set_errno(-1, ENOMEM);

	parent_cgroup = must_make_path(h->mountpoint, h->container_base_path, NULL);

	leaf = dup;
	leaf += strspn(leaf, "/");
	slash = strchr(leaf, '/');
	if (slash)
		*slash = '\0';
	child_cgroup = must_make_path(parent_cgroup, leaf, NULL);
	if (slash)
		*slash = '/';

	fret = 1;
	ret = mkdir(child_cgroup, 0755);
	if (ret < 0) {
		if (errno != EEXIST)
			return log_error_errno(-1, errno, "Failed to create directory \"%s\"", child_cgroup);

		fret = 0;
	}

	cgroup_fd = lxc_open_dirfd(child_cgroup);
	if (cgroup_fd < 0)
		return -1;

	ret = lxc_readat(cgroup_fd, "cgroup.clone_children", &v, 1);
	if (ret < 0)
		return log_error_errno(-1, errno, "Failed to read file \"%s/cgroup.clone_children\"", child_cgroup);

	/* Make sure any isolated cpus are removed from cpuset.cpus. */
	if (!cg_legacy_filter_and_set_cpus(parent_cgroup, child_cgroup, v == '1'))
		return log_error_errno(-1, errno, "Failed to remove isolated cpus");

	/* Already set for us by someone else. */
	if (v == '1')
		TRACE("\"cgroup.clone_children\" was already set to \"1\"");

	/* copy parent's settings */
	if (!copy_parent_file(parent_cgroup, child_cgroup, "cpuset.mems"))
		return log_error_errno(-1, errno, "Failed to copy \"cpuset.mems\" settings");

	/* Set clone_children so children inherit our settings */
	ret = lxc_writeat(cgroup_fd, "cgroup.clone_children", "1", 1);
	if (ret < 0)
		return log_error_errno(-1, errno, "Failed to write 1 to \"%s/cgroup.clone_children\"", child_cgroup);

	return fret;
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
	if (strncmp(p, DEFAULT_CGROUP_MOUNTPOINT "/", 15) != 0)
		return log_error(NULL, "Found hierarchy not under " DEFAULT_CGROUP_MOUNTPOINT ": \"%s\"", p);

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

		lxc_iterate_parts (tok, dup, sep)
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

static char **cg_unified_get_controllers(const char *file)
{
	__do_free char *buf = NULL;
	__do_free_string_list char **aret = NULL;
	char *sep = " \t\n";
	char *tok;

	buf = read_file(file);
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

static struct hierarchy *add_hierarchy(struct hierarchy ***h, char **clist, char *mountpoint,
				       char *container_base_path, int type)
{
	struct hierarchy *new;
	int newentry;

	new = zalloc(sizeof(*new));
	new->controllers = clist;
	new->mountpoint = mountpoint;
	new->container_base_path = container_base_path;
	new->version = type;
	new->cgfd_con = -EBADF;
	new->cgfd_mon = -EBADF;

	newentry = append_null_to_list((void ***)h);
	(*h)[newentry] = new;
	return new;
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

	if (strncmp(p, DEFAULT_CGROUP_MOUNTPOINT "/", 15) != 0)
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
		if (strcmp(tok, c) == 0)
			return true;

	return false;
}

/* @basecginfo is a copy of /proc/$$/cgroup. Return the current cgroup for
 * @controller.
 */
static char *cg_hybrid_get_current_cgroup(char *basecginfo, char *controller,
					  int type)
{
	char *p = basecginfo;

	for (;;) {
		bool is_cgv2_base_cgroup = false;

		/* cgroup v2 entry in "/proc/<pid>/cgroup": "0::/some/path" */
		if ((type == CGROUP2_SUPER_MAGIC) && (*p == '0'))
			is_cgv2_base_cgroup = true;

		p = strchr(p, ':');
		if (!p)
			return NULL;
		p++;

		if (is_cgv2_base_cgroup || (controller && controller_in_clist(p, controller))) {
			p = strchr(p, ':');
			if (!p)
				return NULL;
			p++;
			return copy_to_eol(p);
		}

		p = strchr(p, '\n');
		if (!p)
			return NULL;
		p++;
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
			if (strncmp(tok, "name=", 5) == 0)
				must_append_string(nlist, tok);
			else
				must_append_string(klist, tok);
		}
	}

	return 0;
}

static char *trim(char *s)
{
	size_t len;

	len = strlen(s);
	while ((len > 1) && (s[len - 1] == '\n'))
		s[--len] = '\0';

	return s;
}

static void lxc_cgfsng_print_hierarchies(struct cgroup_ops *ops)
{
	int i;
	struct hierarchy **it;

	if (!ops->hierarchies) {
		TRACE("  No hierarchies found");
		return;
	}

	TRACE("  Hierarchies:");
	for (i = 0, it = ops->hierarchies; it && *it; it++, i++) {
		int j;
		char **cit;

		TRACE("  %d: base_cgroup: %s", i, (*it)->container_base_path ? (*it)->container_base_path : "(null)");
		TRACE("      mountpoint:  %s", (*it)->mountpoint ? (*it)->mountpoint : "(null)");
		TRACE("      controllers:");
		for (j = 0, cit = (*it)->controllers; cit && *cit; cit++, j++)
			TRACE("      %d: %s", j, *cit);
	}
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

static int cgroup_rmdir(struct hierarchy **hierarchies,
			const char *container_cgroup)
{
	if (!container_cgroup || !hierarchies)
		return 0;

	for (int i = 0; hierarchies[i]; i++) {
		struct hierarchy *h = hierarchies[i];
		int ret;

		if (!h->container_full_path)
			continue;

		ret = recursive_destroy(h->container_full_path);
		if (ret < 0)
			WARN("Failed to destroy \"%s\"", h->container_full_path);

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

static int cgroup_rmdir_wrapper(void *data)
{
	struct generic_userns_exec_data *arg = data;
	uid_t nsuid = (arg->conf->root_nsuid_map != NULL) ? 0 : arg->conf->init_uid;
	gid_t nsgid = (arg->conf->root_nsgid_map != NULL) ? 0 : arg->conf->init_gid;
	int ret;

	if (!lxc_setgroups(0, NULL) && errno != EPERM)
		return log_error_errno(-1, errno, "Failed to setgroups(0, NULL)");

	ret = setresgid(nsgid, nsgid, nsgid);
	if (ret < 0)
		return log_error_errno(-1, errno, "Failed to setresgid(%d, %d, %d)",
				       (int)nsgid, (int)nsgid, (int)nsgid);

	ret = setresuid(nsuid, nsuid, nsuid);
	if (ret < 0)
		return log_error_errno(-1, errno, "Failed to setresuid(%d, %d, %d)",
				       (int)nsuid, (int)nsuid, (int)nsuid);

	return cgroup_rmdir(arg->hierarchies, arg->container_cgroup);
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
	ret = bpf_program_cgroup_detach(handler->conf->cgroup2_devices);
	if (ret < 0)
		WARN("Failed to detach bpf program from cgroup");
#endif

	if (handler->conf && !lxc_list_empty(&handler->conf->id_map)) {
		struct generic_userns_exec_data wrap = {
			.conf			= handler->conf,
			.container_cgroup	= ops->container_cgroup,
			.hierarchies		= ops->hierarchies,
			.origuid		= 0,
		};
		ret = userns_exec_1(handler->conf, cgroup_rmdir_wrapper, &wrap,
				    "cgroup_rmdir_wrapper");
	} else {
		ret = cgroup_rmdir(ops->hierarchies, ops->container_cgroup);
	}
	if (ret < 0)
		SYSWARN("Failed to destroy cgroups");
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

	len = snprintf(pidstr, sizeof(pidstr), "%d", handler->monitor_pid);
	if (len < 0 || (size_t)len >= sizeof(pidstr))
		return;

	for (int i = 0; ops->hierarchies[i]; i++) {
		__do_free char *pivot_path = NULL;
		struct hierarchy *h = ops->hierarchies[i];
		int ret;

		if (!h->monitor_full_path)
			continue;

		if (conf && conf->cgroup_meta.dir)
			pivot_path = must_make_path(h->mountpoint,
						    h->container_base_path,
						    conf->cgroup_meta.dir,
						    CGROUP_PIVOT, NULL);
		else
			pivot_path = must_make_path(h->mountpoint,
						    h->container_base_path,
						    CGROUP_PIVOT, NULL);

		ret = mkdir_p(pivot_path, 0755);
		if (ret < 0 && errno != EEXIST) {
			ERROR("Failed to create %s", pivot_path);
			goto try_recursive_destroy;
		}

		ret = lxc_write_openat(pivot_path, "cgroup.procs", pidstr, len);
		if (ret != 0) {
			SYSWARN("Failed to move monitor %s to \"%s\"", pidstr, pivot_path);
			continue;
		}

try_recursive_destroy:
		ret = recursive_destroy(h->monitor_full_path);
		if (ret < 0)
			WARN("Failed to destroy \"%s\"", h->monitor_full_path);
	}
}

static int mkdir_eexist_on_last(const char *dir, mode_t mode)
{
	const char *tmp = dir;
	const char *orig = dir;
	size_t orig_len;

	orig_len = strlen(dir);
	do {
		__do_free char *makeme = NULL;
		int ret;
		size_t cur_len;

		dir = tmp + strspn(tmp, "/");
		tmp = dir + strcspn(dir, "/");

		cur_len = dir - orig;
		makeme = strndup(orig, cur_len);
		if (!makeme)
			return ret_set_errno(-1, ENOMEM);

		ret = mkdir(makeme, mode);
		if (ret < 0 && ((errno != EEXIST) || (orig_len == cur_len)))
			return log_error_errno(-1, errno, "Failed to create directory \"%s\"", makeme);
	} while (tmp != dir);

	return 0;
}

static bool create_cgroup_tree(struct hierarchy *h, const char *cgroup_tree,
			       const char *cgroup_leaf, bool payload)
{
	__do_free char *path = NULL;
	int ret, ret_cpuset;

	path = must_make_path(h->mountpoint, h->container_base_path, cgroup_leaf, NULL);
	if (dir_exists(path))
		return log_warn_errno(false, errno, "The %s cgroup already existed", path);

	ret_cpuset = cg_legacy_handle_cpuset_hierarchy(h, cgroup_leaf);
	if (ret_cpuset < 0)
		return log_error_errno(false, errno, "Failed to handle legacy cpuset controller");

	ret = mkdir_eexist_on_last(path, 0755);
	if (ret < 0) {
		/*
		 * This is the cpuset controller and
		 * cg_legacy_handle_cpuset_hierarchy() has created our target
		 * directory for us to ensure correct initialization.
		 */
		if (ret_cpuset != 1 || cgroup_tree)
			return log_error_errno(false, errno, "Failed to create %s cgroup", path);
	}

	if (payload) {
		h->cgfd_con = lxc_open_dirfd(path);
		if (h->cgfd_con < 0)
			return log_error_errno(false, errno, "Failed to open %s", path);
		h->container_full_path = move_ptr(path);
	} else {
		h->cgfd_mon = lxc_open_dirfd(path);
		if (h->cgfd_mon < 0)
			return log_error_errno(false, errno, "Failed to open %s", path);
		h->monitor_full_path = move_ptr(path);
	}

	return true;
}

static void cgroup_remove_leaf(struct hierarchy *h, bool payload)
{
	__do_free char *full_path = NULL;

	if (payload) {
		__lxc_unused __do_close int fd = move_fd(h->cgfd_con);
		full_path = move_ptr(h->container_full_path);
	} else {
		__lxc_unused __do_close int fd = move_fd(h->cgfd_mon);
		full_path = move_ptr(h->monitor_full_path);
	}

	if (full_path && rmdir(full_path))
		SYSWARN("Failed to rmdir(\"%s\") cgroup", full_path);
}

__cgfsng_ops static inline bool cgfsng_monitor_create(struct cgroup_ops *ops,
						      struct lxc_handler *handler)
{
	__do_free char *monitor_cgroup = NULL, *__cgroup_tree = NULL;
	const char *cgroup_tree;
	int idx = 0;
	int i;
	size_t len;
	char *suffix;
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

	if (conf->cgroup_meta.dir) {
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

	suffix = monitor_cgroup + len - CGROUP_CREATE_RETRY_LEN;
	*suffix = '\0';
	do {
		if (idx)
			sprintf(suffix, "-%d", idx);

		for (i = 0; ops->hierarchies[i]; i++) {
			if (create_cgroup_tree(ops->hierarchies[i], cgroup_tree, monitor_cgroup, false))
				continue;

			ERROR("Failed to create cgroup \"%s\"", ops->hierarchies[i]->monitor_full_path ?: "(null)");
			for (int j = 0; j < i; j++)
				cgroup_remove_leaf(ops->hierarchies[j], false);

			idx++;
			break;
		}
	} while (ops->hierarchies[i] && idx > 0 && idx < 1000);

	if (idx == 1000)
		return ret_set_errno(false, ERANGE);

	ops->monitor_cgroup = move_ptr(monitor_cgroup);
	return log_info(true, "The monitor process uses \"%s\" as cgroup", ops->monitor_cgroup);
}

/*
 * Try to create the same cgroup in all hierarchies. Start with cgroup_pattern;
 * next cgroup_pattern-1, -2, ..., -999.
 */
__cgfsng_ops static inline bool cgfsng_payload_create(struct cgroup_ops *ops,
						      struct lxc_handler *handler)
{
	__do_free char *container_cgroup = NULL, *__cgroup_tree = NULL;
	const char *cgroup_tree;
	int idx = 0;
	int i;
	size_t len;
	char *suffix;
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

	if (conf->cgroup_meta.dir) {
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

	suffix = container_cgroup + len - CGROUP_CREATE_RETRY_LEN;
	*suffix = '\0';
	do {
		if (idx)
			sprintf(suffix, "-%d", idx);

		for (i = 0; ops->hierarchies[i]; i++) {
			if (create_cgroup_tree(ops->hierarchies[i], cgroup_tree, container_cgroup, true))
				continue;

			ERROR("Failed to create cgroup \"%s\"", ops->hierarchies[i]->container_full_path ?: "(null)");
			for (int j = 0; j < i; j++)
				cgroup_remove_leaf(ops->hierarchies[j], true);

			idx++;
			break;
		}
	} while (ops->hierarchies[i] && idx > 0 && idx < 1000);

	if (idx == 1000)
		return ret_set_errno(false, ERANGE);

	ops->container_cgroup = move_ptr(container_cgroup);
	INFO("The container process uses \"%s\" as cgroup", ops->container_cgroup);
	return true;
}

__cgfsng_ops static bool cgfsng_monitor_enter(struct cgroup_ops *ops,
					      struct lxc_handler *handler)
{
	int monitor_len, transient_len;
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

	monitor_len = snprintf(monitor, sizeof(monitor), "%d", handler->monitor_pid);
	if (handler->transient_pid > 0)
		transient_len = snprintf(transient, sizeof(transient), "%d", handler->transient_pid);

	for (int i = 0; ops->hierarchies[i]; i++) {
		struct hierarchy *h = ops->hierarchies[i];
		int ret;

		ret = lxc_writeat(h->cgfd_mon, "cgroup.procs", monitor, monitor_len);
		if (ret)
			return log_error_errno(false, errno, "Failed to enter cgroup \"%s\"", h->monitor_full_path);

                if (handler->transient_pid < 0)
			return true;

		ret = lxc_writeat(h->cgfd_mon, "cgroup.procs", transient, transient_len);
		if (ret)
			return log_error_errno(false, errno, "Failed to enter cgroup \"%s\"", h->monitor_full_path);

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

	len = snprintf(pidstr, sizeof(pidstr), "%d", handler->pid);

	for (int i = 0; ops->hierarchies[i]; i++) {
		struct hierarchy *h = ops->hierarchies[i];
		int ret;

		ret = lxc_writeat(h->cgfd_con, "cgroup.procs", pidstr, len);
		if (ret != 0)
			return log_error_errno(false, errno, "Failed to enter cgroup \"%s\"", h->container_full_path);
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

	if (!lxc_setgroups(0, NULL) && errno != EPERM)
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

__cgfsng_ops void cgfsng_payload_finalize(struct cgroup_ops *ops)
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
}

/* cgroup-full:* is done, no need to create subdirs */
static inline bool cg_mount_needs_subdirs(int type)
{
	return !(type >= LXC_AUTO_CGROUP_FULL_RO);
}

/* After $rootfs/sys/fs/container/controller/the/cg/path has been created,
 * remount controller ro if needed and bindmount the cgroupfs onto
 * control/the/cg/path.
 */
static int cg_legacy_mount_controllers(int type, struct hierarchy *h,
				       char *controllerpath, char *cgpath,
				       const char *container_cgroup)
{
	__do_free char *sourcepath = NULL;
	int ret, remount_flags;
	int flags = MS_BIND;

	if (type == LXC_AUTO_CGROUP_RO || type == LXC_AUTO_CGROUP_MIXED) {
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
	if (type == LXC_AUTO_CGROUP_RO)
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

/* __cg_mount_direct
 *
 * Mount cgroup hierarchies directly without using bind-mounts. The main
 * uses-cases are mounting cgroup hierarchies in cgroup namespaces and mounting
 * cgroups for the LXC_AUTO_CGROUP_FULL option.
 */
static int __cg_mount_direct(int type, struct hierarchy *h,
			     const char *controllerpath)
{
	 __do_free char *controllers = NULL;
	 char *fstype = "cgroup2";
	 unsigned long flags = 0;
	 int ret;

	 flags |= MS_NOSUID;
	 flags |= MS_NOEXEC;
	 flags |= MS_NODEV;
	 flags |= MS_RELATIME;

	 if (type == LXC_AUTO_CGROUP_RO || type == LXC_AUTO_CGROUP_FULL_RO)
		 flags |= MS_RDONLY;

	 if (h->version != CGROUP2_SUPER_MAGIC) {
		 controllers = lxc_string_join(",", (const char **)h->controllers, false);
		 if (!controllers)
			 return -ENOMEM;
		 fstype = "cgroup";
	}

	ret = mount("cgroup", controllerpath, fstype, flags, controllers);
	if (ret < 0)
		return log_error_errno(-1, errno, "Failed to mount \"%s\" with cgroup filesystem type %s",
				       controllerpath, fstype);

	DEBUG("Mounted \"%s\" with cgroup filesystem type %s", controllerpath, fstype);
	return 0;
}

static inline int cg_mount_in_cgroup_namespace(int type, struct hierarchy *h,
					       const char *controllerpath)
{
	return __cg_mount_direct(type, h, controllerpath);
}

static inline int cg_mount_cgroup_full(int type, struct hierarchy *h,
				       const char *controllerpath)
{
	if (type < LXC_AUTO_CGROUP_FULL_RO || type > LXC_AUTO_CGROUP_FULL_MIXED)
		return 0;

	return __cg_mount_direct(type, h, controllerpath);
}

__cgfsng_ops static bool cgfsng_mount(struct cgroup_ops *ops,
				      struct lxc_handler *handler,
				      const char *root, int type)
{
	__do_free char *cgroup_root = NULL;
	bool has_cgns = false, wants_force_mount = false;
	int ret;

	if (!ops)
		return ret_set_errno(false, ENOENT);

	if (!ops->hierarchies)
		return true;

	if (!handler || !handler->conf)
		return ret_set_errno(false, EINVAL);

	if ((type & LXC_AUTO_CGROUP_MASK) == 0)
		return true;

	if (type & LXC_AUTO_CGROUP_FORCE) {
		type &= ~LXC_AUTO_CGROUP_FORCE;
		wants_force_mount = true;
	}

	if (!wants_force_mount){
		if (!lxc_list_empty(&handler->conf->keepcaps))
			wants_force_mount = !in_caplist(CAP_SYS_ADMIN, &handler->conf->keepcaps);
		else
			wants_force_mount = in_caplist(CAP_SYS_ADMIN, &handler->conf->caps);
	}

	has_cgns = cgns_supported();
	if (has_cgns && !wants_force_mount)
		return true;

	if (type == LXC_AUTO_CGROUP_NOSPEC)
		type = LXC_AUTO_CGROUP_MIXED;
	else if (type == LXC_AUTO_CGROUP_FULL_NOSPEC)
		type = LXC_AUTO_CGROUP_FULL_MIXED;

	cgroup_root = must_make_path(root, DEFAULT_CGROUP_MOUNTPOINT, NULL);
	if (ops->cgroup_layout == CGROUP_LAYOUT_UNIFIED) {
		if (has_cgns && wants_force_mount) {
			/*
			 * If cgroup namespaces are supported but the container
			 * will not have CAP_SYS_ADMIN after it has started we
			 * need to mount the cgroups manually.
			 */
			return cg_mount_in_cgroup_namespace(type, ops->unified, cgroup_root) == 0;
		}

		return cg_mount_cgroup_full(type, ops->unified, cgroup_root) == 0;
	}

	/* mount tmpfs */
	ret = safe_mount(NULL, cgroup_root, "tmpfs",
			 MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME,
			 "size=10240k,mode=755", root);
	if (ret < 0)
		return false;

	for (int i = 0; ops->hierarchies[i]; i++) {
		__do_free char *controllerpath = NULL, *path2 = NULL;
		struct hierarchy *h = ops->hierarchies[i];
		char *controller = strrchr(h->mountpoint, '/');

		if (!controller)
			continue;
		controller++;

		controllerpath = must_make_path(cgroup_root, controller, NULL);
		if (dir_exists(controllerpath))
			continue;

		ret = mkdir(controllerpath, 0755);
		if (ret < 0)
			return log_error_errno(false, errno, "Error creating cgroup path: %s", controllerpath);

		if (has_cgns && wants_force_mount) {
			/* If cgroup namespaces are supported but the container
			 * will not have CAP_SYS_ADMIN after it has started we
			 * need to mount the cgroups manually.
			 */
			ret = cg_mount_in_cgroup_namespace(type, h, controllerpath);
			if (ret < 0)
				return false;

			continue;
		}

		ret = cg_mount_cgroup_full(type, h, controllerpath);
		if (ret < 0)
			return false;

		if (!cg_mount_needs_subdirs(type))
			continue;

		path2 = must_make_path(controllerpath, h->container_base_path,
				       ops->container_cgroup, NULL);
		ret = mkdir_p(path2, 0755);
		if (ret < 0)
			return false;

		ret = cg_legacy_mount_controllers(type, h, controllerpath,
						  path2, ops->container_cgroup);
		if (ret < 0)
			return false;
	}

	return true;
}

/* Only root needs to escape to the cgroup of its init. */
__cgfsng_ops static bool cgfsng_escape(const struct cgroup_ops *ops,
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

__cgfsng_ops static int cgfsng_num_hierarchies(struct cgroup_ops *ops)
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

__cgfsng_ops static bool cgfsng_get_hierarchies(struct cgroup_ops *ops, int n,
						char ***out)
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
	__do_close int duped_fd = -EBADF;
	__do_free char *line = NULL;
	__do_fclose FILE *f = NULL;
	int state = PTR_TO_INT(cbdata);
	size_t len;
	const char *state_string;

	duped_fd = dup(fd);
	if (duped_fd < 0)
		return LXC_MAINLOOP_ERROR;

	if (lseek(duped_fd, 0, SEEK_SET) < (off_t)-1)
		return LXC_MAINLOOP_ERROR;

	f = fdopen(duped_fd, "re");
	if (!f)
		return LXC_MAINLOOP_ERROR;
	move_fd(duped_fd);

	if (state == 1)
		state_string = "frozen 1";
	else
		state_string = "frozen 0";

	while (getline(&line, &len, f) != -1)
		if (strncmp(line, state_string, STRLITERALLEN("frozen") + 2) == 0)
			return LXC_MAINLOOP_CLOSE;

	return LXC_MAINLOOP_CONTINUE;
}

static int cg_unified_freeze(struct cgroup_ops *ops, int timeout)
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
			return log_error_errno(-1, errno, "Failed to create epoll instance to wait for container freeze");

		/* automatically cleaned up now */
		descr_ptr = &descr;

		ret = lxc_mainloop_add_handler(&descr, fd, freezer_cgroup_events_cb, INT_TO_PTR((int){1}));
		if (ret < 0)
			return log_error_errno(-1, errno, "Failed to add cgroup.events fd handler to mainloop");
	}

	ret = lxc_write_openat(h->container_full_path, "cgroup.freeze", "1", 1);
	if (ret < 0)
		return log_error_errno(-1, errno, "Failed to open cgroup.freeze file");

	if (timeout != 0 && lxc_mainloop(&descr, timeout))
		return log_error_errno(-1, errno, "Failed to wait for container to be frozen");

	return 0;
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
	__do_close int fd = -EBADF;
	call_cleaner(lxc_mainloop_close)struct lxc_epoll_descr *descr_ptr = NULL;
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
			return log_error_errno(-1, errno, "Failed to create epoll instance to wait for container unfreeze");

		/* automatically cleaned up now */
		descr_ptr = &descr;

		ret = lxc_mainloop_add_handler(&descr, fd, freezer_cgroup_events_cb, INT_TO_PTR((int){0}));
		if (ret < 0)
			return log_error_errno(-1, errno, "Failed to add cgroup.events fd handler to mainloop");
	}

	ret = lxc_write_openat(h->container_full_path, "cgroup.freeze", "0", 1);
	if (ret < 0)
		return log_error_errno(-1, errno, "Failed to open cgroup.freeze file");

	if (timeout != 0 && lxc_mainloop(&descr, timeout))
		return log_error_errno(-1, errno, "Failed to wait for container to be unfrozen");

	return 0;
}

__cgfsng_ops static int cgfsng_unfreeze(struct cgroup_ops *ops, int timeout)
{
	if (!ops->hierarchies)
		return ret_set_errno(-1, ENOENT);

	if (ops->cgroup_layout != CGROUP_LAYOUT_UNIFIED)
		return cg_legacy_unfreeze(ops);

	return cg_unified_unfreeze(ops, timeout);
}

__cgfsng_ops static const char *cgfsng_get_cgroup(struct cgroup_ops *ops,
						  const char *controller)
{
	struct hierarchy *h;

	h = get_hierarchy(ops, controller);
	if (!h)
		return log_warn_errno(NULL, ENOENT, "Failed to find hierarchy for controller \"%s\"",
				      controller ? controller : "(null)");

	return h->container_full_path
		   ? h->container_full_path + strlen(h->mountpoint)
		   : NULL;
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
	size_t pidstr_len;

	/* Create leaf cgroup. */
	ret = mkdirat(unified_fd, "lxc", 0755);
	if (ret < 0 && errno != EEXIST)
		return log_error_errno(-1, errno, "Failed to create leaf cgroup \"lxc\"");

	pidstr_len = sprintf(pidstr, INT64_FMT, (int64_t)pid);
	ret = lxc_writeat(unified_fd, "lxc/cgroup.procs", pidstr, pidstr_len);
	if (ret < 0)
		ret = lxc_writeat(unified_fd, "cgroup.procs", pidstr, pidstr_len);
	if (ret == 0)
		return 0;

	/* this is a non-leaf node */
	if (errno != EBUSY)
		return log_error_errno(-1, errno, "Failed to attach to unified cgroup");

	do {
		bool rm = false;
		char attach_cgroup[STRLITERALLEN("lxc-1000/cgroup.procs") + 1];
		char *slash;

		sprintf(attach_cgroup, "lxc-%d/cgroup.procs", idx);
		slash = &attach_cgroup[ret] - STRLITERALLEN("/cgroup.procs");
		*slash = '\0';

		ret = mkdirat(unified_fd, attach_cgroup, 0755);
		if (ret < 0 && errno != EEXIST)
			return log_error_errno(-1, errno, "Failed to create cgroup %s", attach_cgroup);
		if (ret == 0)
			rm = true;

		*slash = '/';

		ret = lxc_writeat(unified_fd, attach_cgroup, pidstr, pidstr_len);
		if (ret == 0)
			return 0;

		if (rm && unlinkat(unified_fd, attach_cgroup, AT_REMOVEDIR))
			SYSERROR("Failed to remove cgroup \"%d(%s)\"", unified_fd, attach_cgroup);

		/* this is a non-leaf node */
		if (errno != EBUSY)
			return log_error_errno(-1, errno, "Failed to attach to unified cgroup");

		idx++;
	} while (idx < 1000);

	return log_error_errno(-1, errno, "Failed to attach to unified cgroup");
}

struct userns_exec_unified_attach_data {
	const struct lxc_conf *conf;
	int unified_fd;
	pid_t pid;
};

static int cgroup_unified_attach_wrapper(void *data)
{
	struct userns_exec_unified_attach_data *args = data;

	if (!args->conf || args->unified_fd < 0 || args->pid <= 0)
		return ret_errno(EINVAL);

	return cgroup_attach_leaf(args->conf, args->unified_fd, args->pid);
}

int cgroup_attach(const struct lxc_conf *conf, const char *name,
		  const char *lxcpath, pid_t pid)
{
	__do_close int unified_fd = -EBADF;
	int ret;

	if (!conf || !name || !lxcpath || pid <= 0)
		return ret_errno(EINVAL);

	unified_fd = lxc_cmd_get_cgroup2_fd(name, lxcpath);
	if (unified_fd < 0)
		return ret_errno(EBADF);

	if (!lxc_list_empty(&conf->id_map)) {
		struct userns_exec_unified_attach_data args = {
			.conf		= conf,
			.unified_fd	= unified_fd,
			.pid		= pid,
		};

		ret = userns_exec_minimal(conf, cgroup_unified_attach_wrapper, &args);
	} else {
		ret = cgroup_attach_leaf(conf, unified_fd, pid);
	}

	return ret;
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
	if (ret != -EBADF)
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

		ret = userns_exec_minimal(conf, cgroup_unified_attach_wrapper, &args);
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

	len = snprintf(pidstr, sizeof(pidstr), "%d", pid);
	if (len < 0 || (size_t)len >= sizeof(pidstr))
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

	path = lxc_cmd_get_cgroup_path(name, lxcpath, controller);
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

	if (strcmp("devices.allow", key) == 0)
		device->allow = 1;
	else
		device->allow = 0;

	if (strcmp(val, "a") == 0) {
		/* global rule */
		device->type = 'a';
		device->major = -1;
		device->minor = -1;
		device->global_rule = device->allow
					  ? LXC_BPF_DEVICE_CGROUP_BLACKLIST
					  : LXC_BPF_DEVICE_CGROUP_WHITELIST;
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

	if (!ops)
		return ret_set_errno(-1, ENOENT);

	controller = must_copy_string(key);
	p = strchr(controller, '.');
	if (p)
		*p = '\0';

	if (pure_unified_layout(ops) && strcmp(controller, "devices") == 0) {
		struct device_item device = {0};

		ret = device_cgroup_rule_parse(&device, key, value);
		if (ret < 0)
			return log_error_errno(-1, EINVAL, "Failed to parse device string %s=%s",
					       key, value);

		ret = lxc_cmd_add_bpf_device_cgroup(name, lxcpath, &device);
		if (ret < 0)
			return -1;

		return 0;
	}

	path = lxc_cmd_get_cgroup_path(name, lxcpath, controller);
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

	if (device_cgroup_parse_access(device, mode) < 0)
		return -1;

	if (n_parts == 1)
		return ret_set_errno(-1, EINVAL);

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
	struct device_item device = {0};
	int ret;

	ret = device_cgroup_rule_parse_devpath(&device, invalue);
	if (ret < 0)
		return -1;

	ret = snprintf(dest, 50, "%c %d:%d %s", device.type, device.major,
		       device.minor, device.access);
	if (ret < 0 || ret >= 50)
		return log_error_errno(-1, ENAMETOOLONG, "Error on configuration value \"%c %d:%d %s\" (max 50 chars)",
				       device.type, device.major, device.minor, device.access);

	return 0;
}

/* Called from setup_limits - here we have the container's cgroup_data because
 * we created the cgroups.
 */
static int cg_legacy_set_data(struct cgroup_ops *ops, const char *filename,
			      const char *value)
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

	if (strcmp("devices.allow", filename) == 0 && value[0] == '/') {
		int ret;

		ret = convert_devpath(value, converted_value);
		if (ret < 0)
			return ret;
		value = converted_value;
	}

	h = get_hierarchy(ops, controller);
	if (!h)
		return log_error_errno(-ENOENT, ENOENT, "Failed to setup limits for the \"%s\" controller. The controller seems to be unused by \"cgfsng\" cgroup driver or not enabled on the cgroup hierarchy", controller);

	return lxc_write_openat(h->container_full_path, filename, value, strlen(value));
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

	sorted_cgroup_settings = sort_cgroup_settings(cgroup_settings);
	if (!sorted_cgroup_settings)
		return false;

	lxc_list_for_each(iterator, sorted_cgroup_settings) {
		cg = iterator->elem;

		if (do_devices == !strncmp("devices", cg->subsystem, 7)) {
			if (cg_legacy_set_data(ops, cg->subsystem, cg->value)) {
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
	struct device_item device_item = {0};
	int ret;

	if (strcmp("devices.allow", key) == 0 && *val == '/')
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

	if (lxc_list_empty(&conf->cgroup2))
		return true;
	cgroup_settings = &conf->cgroup2;

	if (!ops->unified)
		return false;
	h = ops->unified;

	lxc_list_for_each (iterator, cgroup_settings) {
		struct lxc_cgroup *cg = iterator->elem;
		int ret;

		if (strncmp("devices", cg->subsystem, 7) == 0) {
			ret = bpf_device_cgroup_prepare(ops, conf, cg->subsystem,
							cg->value);
		} else {
			ret = lxc_write_openat(h->container_full_path,
					       cg->subsystem, cg->value,
					       strlen(cg->value));
			if (ret < 0)
				return log_error_errno(false, errno, "Failed to set \"%s\" to \"%s\"",
						       cg->subsystem, cg->value);
		}
		TRACE("Set \"%s\" to \"%s\"", cg->subsystem, cg->value);
	}

	return log_info(true, "Limits for the unified cgroup hierarchy have been setup");
}

__cgfsng_ops bool cgfsng_devices_activate(struct cgroup_ops *ops,
					  struct lxc_handler *handler)
{
#ifdef HAVE_STRUCT_BPF_CGROUP_DEV_CTX
	__do_bpf_program_free struct bpf_program *devices = NULL;
	int ret;
	struct lxc_conf *conf;
	struct hierarchy *unified;
	struct lxc_list *it;
	struct bpf_program *devices_old;

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

	devices = bpf_program_new(BPF_PROG_TYPE_CGROUP_DEVICE);
	if (!devices)
		return log_error_errno(false, ENOMEM, "Failed to create new bpf program");

	ret = bpf_program_init(devices);
	if (ret)
		return log_error_errno(false, ENOMEM, "Failed to initialize bpf program");

	lxc_list_for_each(it, &conf->devices) {
		struct device_item *cur = it->elem;

		ret = bpf_program_append_device(devices, cur);
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

	ret = bpf_program_finalize(devices);
	if (ret)
		return log_error_errno(false, ENOMEM, "Failed to finalize bpf program");

	ret = bpf_program_cgroup_attach(devices, BPF_CGROUP_DEVICE,
					unified->container_full_path,
					BPF_F_ALLOW_MULTI);
	if (ret)
		return log_error_errno(false, ENOMEM, "Failed to attach bpf program");

	/* Replace old bpf program. */
	devices_old = move_ptr(conf->cgroup2_devices);
	conf->cgroup2_devices = move_ptr(devices);
	devices = move_ptr(devices_old);
#endif
	return true;
}

bool __cgfsng_delegate_controllers(struct cgroup_ops *ops, const char *cgroup)
{
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

	parts = lxc_string_split(cgroup, '/');
	if (!parts)
		return false;

	parts_len = lxc_array_len((void **)parts);
	if (parts_len > 0)
		parts_len--;

	base_path = must_make_path(unified->mountpoint, unified->container_base_path, NULL);
	for (ssize_t i = -1; i < parts_len; i++) {
		int ret;
		__do_free char *target = NULL;

		if (i >= 0)
			base_path = must_append_path(base_path, parts[i], NULL);
		target = must_make_path(base_path, "cgroup.subtree_control", NULL);
		ret = lxc_writeat(-1, target, add_controllers, full_len);
		if (ret < 0)
			return log_error_errno(false, errno, "Could not enable \"%s\" controllers in the unified cgroup \"%s\"",
					       add_controllers, target);
		TRACE("Enable \"%s\" controllers in the unified cgroup \"%s\"", add_controllers, target);
	}

	return true;
}

__cgfsng_ops bool cgfsng_monitor_delegate_controllers(struct cgroup_ops *ops)
{
	if (!ops)
		return ret_set_errno(false, ENOENT);

	return __cgfsng_delegate_controllers(ops, ops->monitor_cgroup);
}

__cgfsng_ops bool cgfsng_payload_delegate_controllers(struct cgroup_ops *ops)
{
	if (!ops)
		return ret_set_errno(false, ENOENT);

	return __cgfsng_delegate_controllers(ops, ops->container_cgroup);
}

static bool cgroup_use_wants_controllers(const struct cgroup_ops *ops,
				       char **controllers)
{
	if (!ops->cgroup_use)
		return true;

	for (char **cur_ctrl = controllers; cur_ctrl && *cur_ctrl; cur_ctrl++) {
		bool found = false;

		for (char **cur_use = ops->cgroup_use; cur_use && *cur_use; cur_use++) {
			if (strcmp(*cur_use, *cur_ctrl) != 0)
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

static void cg_unified_delegate(char ***delegate)
{
	__do_free char *buf = NULL;
	char *standard[] = {"cgroup.subtree_control", "cgroup.threads", NULL};
	char *token;
	int idx;

	buf = read_file("/sys/kernel/cgroup/delegate");
	if (!buf) {
		for (char **p = standard; p && *p; p++) {
			idx = append_null_to_list((void ***)delegate);
			(*delegate)[idx] = must_copy_string(*p);
		}
		SYSWARN("Failed to read /sys/kernel/cgroup/delegate");
		return;
	}

	lxc_iterate_parts (token, buf, " \t\n") {
		/*
		 * We always need to chown this for both cgroup and
		 * cgroup2.
		 */
		if (strcmp(token, "cgroup.procs") == 0)
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
		basecginfo = read_file("/proc/1/cgroup");
	else
		basecginfo = read_file("/proc/self/cgroup");
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
		struct hierarchy *new;

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
			ERROR("Failed parsing mountpoint from \"%s\"", line);
			continue;
		}

		if (type == CGROUP_SUPER_MAGIC)
			base_cgroup = cg_hybrid_get_current_cgroup(basecginfo, controller_list[0], CGROUP_SUPER_MAGIC);
		else
			base_cgroup = cg_hybrid_get_current_cgroup(basecginfo, NULL, CGROUP2_SUPER_MAGIC);
		if (!base_cgroup) {
			ERROR("Failed to find current cgroup");
			continue;
		}

		trim(base_cgroup);
		prune_init_scope(base_cgroup);
		if (type == CGROUP2_SUPER_MAGIC)
			writeable = test_writeable_v2(mountpoint, base_cgroup);
		else
			writeable = test_writeable_v1(mountpoint, base_cgroup);
		if (!writeable) {
			TRACE("The %s group is not writeable", base_cgroup);
			continue;
		}

		if (type == CGROUP2_SUPER_MAGIC) {
			char *cgv2_ctrl_path;

			cgv2_ctrl_path = must_make_path(mountpoint, base_cgroup,
							"cgroup.controllers",
							NULL);

			controller_list = cg_unified_get_controllers(cgv2_ctrl_path);
			free(cgv2_ctrl_path);
			if (!controller_list) {
				controller_list = cg_unified_make_empty_controller();
				TRACE("No controllers are enabled for "
				      "delegation in the unified hierarchy");
			}
		}

		/* Exclude all controllers that cgroup use does not want. */
		if (!cgroup_use_wants_controllers(ops, controller_list)) {
			TRACE("Skipping controller");
			continue;
		}

		new = add_hierarchy(&ops->hierarchies, move_ptr(controller_list), move_ptr(mountpoint), move_ptr(base_cgroup), type);
		if (type == CGROUP2_SUPER_MAGIC && !ops->unified) {
			if (unprivileged)
				cg_unified_delegate(&new->cgroup2_chown);
			ops->unified = new;
		}
	}

	TRACE("Writable cgroup hierarchies:");
	lxc_cgfsng_print_hierarchies(ops);

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
	__do_free char *basecginfo = NULL;
	char *copy;
	char *base_cgroup;

	if (!relative && (geteuid() == 0))
		basecginfo = read_file("/proc/1/cgroup");
	else
		basecginfo = read_file("/proc/self/cgroup");
	if (!basecginfo)
		return NULL;

	base_cgroup = strstr(basecginfo, "0::/");
	if (!base_cgroup)
		return NULL;

	base_cgroup = base_cgroup + 3;
	copy = copy_to_eol(base_cgroup);
	if (!copy)
		return NULL;

	return trim(copy);
}

static int cg_unified_init(struct cgroup_ops *ops, bool relative,
			   bool unprivileged)
{
	__do_free char *subtree_path = NULL;
	int ret;
	char *mountpoint;
	char **delegatable;
	struct hierarchy *new;
	char *base_cgroup = NULL;

	ret = unified_cgroup_hierarchy();
	if (ret == -ENOMEDIUM)
		return ret_errno(ENOMEDIUM);

	if (ret != CGROUP2_SUPER_MAGIC)
		return 0;

	base_cgroup = cg_unified_get_current_cgroup(relative);
	if (!base_cgroup)
		return ret_errno(EINVAL);
	if (!relative)
		prune_init_scope(base_cgroup);

	/*
	 * We assume that the cgroup we're currently in has been delegated to
	 * us and we are free to further delege all of the controllers listed
	 * in cgroup.controllers further down the hierarchy.
	 */
	mountpoint = must_copy_string(DEFAULT_CGROUP_MOUNTPOINT);
	subtree_path = must_make_path(mountpoint, base_cgroup, "cgroup.controllers", NULL);
	delegatable = cg_unified_get_controllers(subtree_path);
	if (!delegatable)
		delegatable = cg_unified_make_empty_controller();
	if (!delegatable[0])
		TRACE("No controllers are enabled for delegation");

	/* TODO: If the user requested specific controllers via lxc.cgroup.use
	 * we should verify here. The reason I'm not doing it right is that I'm
	 * not convinced that lxc.cgroup.use will be the future since it is a
	 * global property. I much rather have an option that lets you request
	 * controllers per container.
	 */

	new = add_hierarchy(&ops->hierarchies, delegatable, mountpoint, base_cgroup, CGROUP2_SUPER_MAGIC);
	if (unprivileged)
		cg_unified_delegate(&new->cgroup2_chown);

	if (bpf_devices_cgroup_supported())
		new->bpf_device_controller = 1;

	ops->cgroup_layout = CGROUP_LAYOUT_UNIFIED;
	ops->unified = new;

	return CGROUP2_SUPER_MAGIC;
}

static int cg_init(struct cgroup_ops *ops, struct lxc_conf *conf)
{
	int ret;
	const char *tmp;
	bool relative = conf->cgroup_meta.relative;

	tmp = lxc_global_config_value("lxc.cgroup.use");
	if (tmp) {
		__do_free char *pin = NULL;
		char *chop, *cur;

		pin = must_copy_string(tmp);
		chop = pin;

		lxc_iterate_parts(cur, chop, ",")
			must_append_string(&ops->cgroup_use, cur);
	}

	ret = cg_unified_init(ops, relative, !lxc_list_empty(&conf->id_map));
	if (ret < 0)
		return -1;

	if (ret == CGROUP2_SUPER_MAGIC)
		return 0;

	return cg_hybrid_init(ops, relative, !lxc_list_empty(&conf->id_map));
}

__cgfsng_ops static int cgfsng_data_init(struct cgroup_ops *ops)
{
	const char *cgroup_pattern;

	if (!ops)
		return ret_set_errno(-1, ENOENT);

	/* copy system-wide cgroup information */
	cgroup_pattern = lxc_global_config_value("lxc.cgroup.pattern");
	if (cgroup_pattern && strcmp(cgroup_pattern, "") != 0)
		ops->cgroup_pattern = must_copy_string(cgroup_pattern);

	return 0;
}

struct cgroup_ops *cgfsng_ops_init(struct lxc_conf *conf)
{
	__do_free struct cgroup_ops *cgfsng_ops = NULL;

	cgfsng_ops = malloc(sizeof(struct cgroup_ops));
	if (!cgfsng_ops)
		return ret_set_errno(NULL, ENOMEM);

	memset(cgfsng_ops, 0, sizeof(struct cgroup_ops));
	cgfsng_ops->cgroup_layout = CGROUP_LAYOUT_UNKNOWN;

	if (cg_init(cgfsng_ops, conf))
		return NULL;

	cgfsng_ops->data_init = cgfsng_data_init;
	cgfsng_ops->payload_destroy = cgfsng_payload_destroy;
	cgfsng_ops->monitor_destroy = cgfsng_monitor_destroy;
	cgfsng_ops->monitor_create = cgfsng_monitor_create;
	cgfsng_ops->monitor_enter = cgfsng_monitor_enter;
	cgfsng_ops->monitor_delegate_controllers = cgfsng_monitor_delegate_controllers;
	cgfsng_ops->payload_delegate_controllers = cgfsng_payload_delegate_controllers;
	cgfsng_ops->payload_create = cgfsng_payload_create;
	cgfsng_ops->payload_enter = cgfsng_payload_enter;
	cgfsng_ops->payload_finalize = cgfsng_payload_finalize;
	cgfsng_ops->escape = cgfsng_escape;
	cgfsng_ops->num_hierarchies = cgfsng_num_hierarchies;
	cgfsng_ops->get_hierarchies = cgfsng_get_hierarchies;
	cgfsng_ops->get_cgroup = cgfsng_get_cgroup;
	cgfsng_ops->get = cgfsng_get;
	cgfsng_ops->set = cgfsng_set;
	cgfsng_ops->freeze = cgfsng_freeze;
	cgfsng_ops->unfreeze = cgfsng_unfreeze;
	cgfsng_ops->setup_limits_legacy = cgfsng_setup_limits_legacy;
	cgfsng_ops->setup_limits = cgfsng_setup_limits;
	cgfsng_ops->driver = "cgfsng";
	cgfsng_ops->version = "1.0.0";
	cgfsng_ops->attach = cgfsng_attach;
	cgfsng_ops->chown = cgfsng_chown;
	cgfsng_ops->mount = cgfsng_mount;
	cgfsng_ops->devices_activate = cgfsng_devices_activate;

	return move_ptr(cgfsng_ops);
}
