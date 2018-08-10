/*
 * lxc: linux Container library
 *
 * Copyright © 2016 Canonical Ltd.
 *
 * Authors:
 * Serge Hallyn <serge.hallyn@ubuntu.com>
 * Christian Brauner <christian.brauner@ubuntu.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/*
 * cgfs-ng.c: this is a new, simplified implementation of a filesystem
 * cgroup backend.  The original cgfs.c was designed to be as flexible
 * as possible.  It would try to find cgroup filesystems no matter where
 * or how you had them mounted, and deduce the most usable mount for
 * each controller.
 *
 * This new implementation assumes that cgroup filesystems are mounted
 * under /sys/fs/cgroup/clist where clist is either the controller, or
 * a comman-separated list of controllers.
 */

#include "config.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <grp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/kdev_t.h>
#include <linux/types.h>
#include <sys/types.h>

#include "caps.h"
#include "cgroup.h"
#include "cgroup_utils.h"
#include "commands.h"
#include "conf.h"
#include "log.h"
#include "storage/storage.h"
#include "utils.h"

#ifndef HAVE_STRLCPY
#include "include/strlcpy.h"
#endif

#ifndef HAVE_STRLCAT
#include "include/strlcat.h"
#endif

lxc_log_define(cgfsng, cgroup);

static void free_string_list(char **clist)
{
	int i;

	if (!clist)
		return;

	for (i = 0; clist[i]; i++)
		free(clist[i]);

	free(clist);
}

/* Allocate a pointer, do not fail. */
static void *must_alloc(size_t sz)
{
	return must_realloc(NULL, sz);
}

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
	int i;

	if (!list)
		return false;

	for (i = 0; list[i]; i++)
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
	prefixed = must_alloc(len + 6);

	memcpy(prefixed, "name=", sizeof("name=") - 1);
	memcpy(prefixed + sizeof("name=") - 1, entry, len);
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
struct hierarchy *get_hierarchy(struct cgroup_ops *ops, const char *c)
{
	int i;

	if (!ops->hierarchies)
		return NULL;

	for (i = 0; ops->hierarchies[i]; i++) {
		if (!c) {
			/* This is the empty unified hierarchy. */
			if (ops->hierarchies[i]->controllers &&
			    !ops->hierarchies[i]->controllers[0])
				return ops->hierarchies[i];

			continue;
		}

		if (string_in_list(ops->hierarchies[i]->controllers, c))
			return ops->hierarchies[i];
	}

	return NULL;
}

#define BATCH_SIZE 50
static void batch_realloc(char **mem, size_t oldlen, size_t newlen)
{
	int newbatches = (newlen / BATCH_SIZE) + 1;
	int oldbatches = (oldlen / BATCH_SIZE) + 1;

	if (!*mem || newbatches > oldbatches) {
		*mem = must_realloc(*mem, newbatches * BATCH_SIZE);
	}
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
	FILE *f;
	char *line = NULL, *buf = NULL;
	size_t len = 0, fulllen = 0;
	int linelen;

	f = fopen(fnam, "r");
	if (!f)
		return NULL;
	while ((linelen = getline(&line, &len, f)) != -1) {
		append_line(&buf, fulllen, line, linelen);
		fulllen += linelen;
	}
	fclose(f);
	free(line);
	return buf;
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
	char *token;
	size_t arrlen;
	uint32_t *bitarr;

	arrlen = BITS_TO_LONGS(nbits);
	bitarr = calloc(arrlen, sizeof(uint32_t));
	if (!bitarr)
		return NULL;

	lxc_iterate_parts(token, buf, ",") {
		errno = 0;
		unsigned end, start;
		char *range;

		start = strtoul(token, NULL, 0);
		end = start;
		range = strchr(token, '-');
		if (range)
			end = strtoul(range + 1, NULL, 0);

		if (!(start <= end)) {
			free(bitarr);
			return NULL;
		}

		if (end >= nbits) {
			free(bitarr);
			return NULL;
		}

		while (start <= end)
			set_bit(start++, bitarr);
	}

	return bitarr;
}

/* Turn cpumask into simple, comma-separated cpulist. */
static char *lxc_cpumask_to_cpulist(uint32_t *bitarr, size_t nbits)
{
	int ret;
	size_t i;
	char **cpulist = NULL;
	char numstr[LXC_NUMSTRLEN64] = {0};

	for (i = 0; i <= nbits; i++) {
		if (!is_set(i, bitarr))
			continue;

		ret = snprintf(numstr, LXC_NUMSTRLEN64, "%zu", i);
		if (ret < 0 || (size_t)ret >= LXC_NUMSTRLEN64) {
			lxc_free_array((void **)cpulist, free);
			return NULL;
		}

		ret = lxc_append_string(&cpulist, numstr);
		if (ret < 0) {
			lxc_free_array((void **)cpulist, free);
			return NULL;
		}
	}

	if (!cpulist)
		return NULL;

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
static bool cg_legacy_filter_and_set_cpus(char *path, bool am_initialized)
{
	int ret;
	ssize_t i;
	char *lastslash, *fpath, oldv;
	ssize_t maxisol = 0, maxposs = 0;
	char *cpulist = NULL, *isolcpus = NULL, *posscpus = NULL;
	uint32_t *isolmask = NULL, *possmask = NULL;
	bool bret = false, flipped_bit = false;

	lastslash = strrchr(path, '/');
	if (!lastslash) {
		ERROR("Failed to detect \"/\" in \"%s\"", path);
		return bret;
	}
	oldv = *lastslash;
	*lastslash = '\0';
	fpath = must_make_path(path, "cpuset.cpus", NULL);
	posscpus = read_file(fpath);
	if (!posscpus) {
		SYSERROR("Failed to read file \"%s\"", fpath);
		goto on_error;
	}

	/* Get maximum number of cpus found in possible cpuset. */
	maxposs = get_max_cpus(posscpus);
	if (maxposs < 0 || maxposs >= INT_MAX - 1)
		goto on_error;

	if (!file_exists(__ISOL_CPUS)) {
		/* This system doesn't expose isolated cpus. */
		DEBUG("The path \""__ISOL_CPUS"\" to read isolated cpus from does not exist");
		cpulist = posscpus;
		/* No isolated cpus but we weren't already initialized by
		 * someone. We should simply copy the parents cpuset.cpus
		 * values.
		 */
		if (!am_initialized) {
			DEBUG("Copying cpu settings of parent cgroup");
			goto copy_parent;
		}
		/* No isolated cpus but we were already initialized by someone.
		 * Nothing more to do for us.
		 */
		goto on_success;
	}

	isolcpus = read_file(__ISOL_CPUS);
	if (!isolcpus) {
		SYSERROR("Failed to read file \""__ISOL_CPUS"\"");
		goto on_error;
	}
	if (!isdigit(isolcpus[0])) {
		TRACE("No isolated cpus detected");
		cpulist = posscpus;
		/* No isolated cpus but we weren't already initialized by
		 * someone. We should simply copy the parents cpuset.cpus
		 * values.
		 */
		if (!am_initialized) {
			DEBUG("Copying cpu settings of parent cgroup");
			goto copy_parent;
		}
		/* No isolated cpus but we were already initialized by someone.
		 * Nothing more to do for us.
		 */
		goto on_success;
	}

	/* Get maximum number of cpus found in isolated cpuset. */
	maxisol = get_max_cpus(isolcpus);
	if (maxisol < 0 || maxisol >= INT_MAX - 1)
		goto on_error;

	if (maxposs < maxisol)
		maxposs = maxisol;
	maxposs++;

	possmask = lxc_cpumask(posscpus, maxposs);
	if (!possmask) {
		ERROR("Failed to create cpumask for possible cpus");
		goto on_error;
	}

	isolmask = lxc_cpumask(isolcpus, maxposs);
	if (!isolmask) {
		ERROR("Failed to create cpumask for isolated cpus");
		goto on_error;
	}

	for (i = 0; i <= maxposs; i++) {
		if (!is_set(i, isolmask) || !is_set(i, possmask))
			continue;

		flipped_bit = true;
		clear_bit(i, possmask);
	}

	if (!flipped_bit) {
		DEBUG("No isolated cpus present in cpuset");
		goto on_success;
	}
	DEBUG("Removed isolated cpus from cpuset");

	cpulist = lxc_cpumask_to_cpulist(possmask, maxposs);
	if (!cpulist) {
		ERROR("Failed to create cpu list");
		goto on_error;
	}

copy_parent:
	*lastslash = oldv;
	free(fpath);
	fpath = must_make_path(path, "cpuset.cpus", NULL);
	ret = lxc_write_to_file(fpath, cpulist, strlen(cpulist), false, 0666);
	if (ret < 0) {
		SYSERROR("Failed to write cpu list to \"%s\"", fpath);
		goto on_error;
	}

on_success:
	bret = true;

on_error:
	free(fpath);

	free(isolcpus);
	free(isolmask);

	if (posscpus != cpulist)
		free(posscpus);
	free(possmask);

	free(cpulist);
	return bret;
}

/* Copy contents of parent(@path)/@file to @path/@file */
static bool copy_parent_file(char *path, char *file)
{
	int ret;
	char *fpath, *lastslash, oldv;
	int len = 0;
	char *value = NULL;

	lastslash = strrchr(path, '/');
	if (!lastslash) {
		ERROR("Failed to detect \"/\" in \"%s\"", path);
		return false;
	}
	oldv = *lastslash;
	*lastslash = '\0';
	fpath = must_make_path(path, file, NULL);
	len = lxc_read_from_file(fpath, NULL, 0);
	if (len <= 0)
		goto on_error;

	value = must_alloc(len + 1);
	ret = lxc_read_from_file(fpath, value, len);
	if (ret != len)
		goto on_error;
	free(fpath);

	*lastslash = oldv;
	fpath = must_make_path(path, file, NULL);
	ret = lxc_write_to_file(fpath, value, len, false, 0666);
	if (ret < 0)
		SYSERROR("Failed to write \"%s\" to file \"%s\"", value, fpath);
	free(fpath);
	free(value);
	return ret >= 0;

on_error:
	SYSERROR("Failed to read file \"%s\"", fpath);
	free(fpath);
	free(value);
	return false;
}

/* Initialize the cpuset hierarchy in first directory of @gname and set
 * cgroup.clone_children so that children inherit settings. Since the
 * h->base_path is populated by init or ourselves, we know it is already
 * initialized.
 */
static bool cg_legacy_handle_cpuset_hierarchy(struct hierarchy *h, char *cgname)
{
	int ret;
	char v;
	char *cgpath, *clonechildrenpath, *slash;

	if (!string_in_list(h->controllers, "cpuset"))
		return true;

	if (*cgname == '/')
		cgname++;
	slash = strchr(cgname, '/');
	if (slash)
		*slash = '\0';

	cgpath = must_make_path(h->mountpoint, h->base_cgroup, cgname, NULL);
	if (slash)
		*slash = '/';

	ret = mkdir(cgpath, 0755);
	if (ret < 0) {
		if (errno != EEXIST) {
			SYSERROR("Failed to create directory \"%s\"", cgpath);
			free(cgpath);
			return false;
		}
	}

	clonechildrenpath =
	    must_make_path(cgpath, "cgroup.clone_children", NULL);
	/* unified hierarchy doesn't have clone_children */
	if (!file_exists(clonechildrenpath)) {
		free(clonechildrenpath);
		free(cgpath);
		return true;
	}

	ret = lxc_read_from_file(clonechildrenpath, &v, 1);
	if (ret < 0) {
		SYSERROR("Failed to read file \"%s\"", clonechildrenpath);
		free(clonechildrenpath);
		free(cgpath);
		return false;
	}

	/* Make sure any isolated cpus are removed from cpuset.cpus. */
	if (!cg_legacy_filter_and_set_cpus(cgpath, v == '1')) {
		SYSERROR("Failed to remove isolated cpus");
		free(clonechildrenpath);
		free(cgpath);
		return false;
	}

	/* Already set for us by someone else. */
	if (v == '1') {
		DEBUG("\"cgroup.clone_children\" was already set to \"1\"");
		free(clonechildrenpath);
		free(cgpath);
		return true;
	}

	/* copy parent's settings */
	if (!copy_parent_file(cgpath, "cpuset.mems")) {
		SYSERROR("Failed to copy \"cpuset.mems\" settings");
		free(cgpath);
		free(clonechildrenpath);
		return false;
	}
	free(cgpath);

	ret = lxc_write_to_file(clonechildrenpath, "1", 1, false, 0666);
	if (ret < 0) {
		/* Set clone_children so children inherit our settings */
		SYSERROR("Failed to write 1 to \"%s\"", clonechildrenpath);
		free(clonechildrenpath);
		return false;
	}
	free(clonechildrenpath);
	return true;
}

/* Given two null-terminated lists of strings, return true if any string is in
 * both.
 */
static bool controller_lists_intersect(char **l1, char **l2)
{
	int i;

	if (!l1 || !l2)
		return false;

	for (i = 0; l1[i]; i++) {
		if (string_in_list(l2, l1[i]))
			return true;
	}

	return false;
}

/* For a null-terminated list of controllers @clist, return true if any of those
 * controllers is already listed the null-terminated list of hierarchies @hlist.
 * Realistically, if one is present, all must be present.
 */
static bool controller_list_is_dup(struct hierarchy **hlist, char **clist)
{
	int i;

	if (!hlist)
		return false;

	for (i = 0; hlist[i]; i++)
		if (controller_lists_intersect(hlist[i]->controllers, clist))
			return true;

	return false;
}

/* Return true if the controller @entry is found in the null-terminated list of
 * hierarchies @hlist.
 */
static bool controller_found(struct hierarchy **hlist, char *entry)
{
	int i;

	if (!hlist)
		return false;

	for (i = 0; hlist[i]; i++)
		if (string_in_list(hlist[i]->controllers, entry))
			return true;

	return false;
}

/* Return true if all of the controllers which we require have been found.  The
 * required list is  freezer and anything in lxc.cgroup.use.
 */
static bool all_controllers_found(struct cgroup_ops *ops)
{
	char **cur;
	struct hierarchy **hlist = ops->hierarchies;

	if (!controller_found(hlist, "freezer")) {
		ERROR("No freezer controller mountpoint found");
		return false;
	}

	if (!ops->cgroup_use)
		return true;

	for (cur = ops->cgroup_use; cur && *cur; cur++)
		if (!controller_found(hlist, *cur)) {
			ERROR("No %s controller mountpoint found", *cur);
			return false;
		}

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
	int i;
	char *dup, *p2, *tok;
	char *p = line, *sep = ",";
	char **aret = NULL;

	for (i = 0; i < 4; i++) {
		p = strchr(p, ' ');
		if (!p)
			return NULL;
		p++;
	}

	/* Note, if we change how mountinfo works, then our caller will need to
	 * verify /sys/fs/cgroup/ in this field.
	 */
	if (strncmp(p, "/sys/fs/cgroup/", 15) != 0) {
		ERROR("Found hierarchy not under /sys/fs/cgroup: \"%s\"", p);
		return NULL;
	}

	p += 15;
	p2 = strchr(p, ' ');
	if (!p2) {
		ERROR("Corrupt mountinfo");
		return NULL;
	}
	*p2 = '\0';

	if (type == CGROUP_SUPER_MAGIC) {
		/* strdup() here for v1 hierarchies. Otherwise
		 * lxc_iterate_parts() will destroy mountpoints such as
		 * "/sys/fs/cgroup/cpu,cpuacct".
		 */
		dup = strdup(p);
		if (!dup)
			return NULL;

		lxc_iterate_parts(tok, dup, sep) {
			must_append_controller(klist, nlist, &aret, tok);
		}

		free(dup);
	}
	*p2 = ' ';

	return aret;
}

static char **cg_unified_make_empty_controller(void)
{
	int newentry;
	char **aret = NULL;

	newentry = append_null_to_list((void ***)&aret);
	aret[newentry] = NULL;
	return aret;
}

static char **cg_unified_get_controllers(const char *file)
{
	char *buf, *tok;
	char *sep = " \t\n";
	char **aret = NULL;

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

	free(buf);
	return aret;
}

static struct hierarchy *add_hierarchy(struct hierarchy ***h, char **clist, char *mountpoint,
				       char *base_cgroup, int type)
{
	struct hierarchy *new;
	int newentry;

	new = must_alloc(sizeof(*new));
	new->controllers = clist;
	new->mountpoint = mountpoint;
	new->base_cgroup = base_cgroup;
	new->fullcgpath = NULL;
	new->version = type;

	newentry = append_null_to_list((void ***)h);
	(*h)[newentry] = new;
	return new;
}

/* Get a copy of the mountpoint from @line, which is a line from
 * /proc/self/mountinfo.
 */
static char *cg_hybrid_get_mountpoint(char *line)
{
	int i;
	size_t len;
	char *p2;
	char *p = line, *sret = NULL;

	for (i = 0; i < 4; i++) {
		p = strchr(p, ' ');
		if (!p)
			return NULL;
		p++;
	}

	if (strncmp(p, "/sys/fs/cgroup/", 15) != 0)
		return NULL;

	p2 = strchr(p + 15, ' ');
	if (!p2)
		return NULL;
	*p2 = '\0';

	len = strlen(p);
	sret = must_alloc(len + 1);
	memcpy(sret, p, len);
	sret[len] = '\0';
	return sret;
}

/* Given a multi-line string, return a null-terminated copy of the current line. */
static char *copy_to_eol(char *p)
{
	char *p2 = strchr(p, '\n'), *sret;
	size_t len;

	if (!p2)
		return NULL;

	len = p2 - p;
	sret = must_alloc(len + 1);
	memcpy(sret, p, len);
	sret[len] = '\0';
	return sret;
}

/* cgline: pointer to character after the first ':' in a line in a \n-terminated
 * /proc/self/cgroup file. Check whether controller c is present.
 */
static bool controller_in_clist(char *cgline, char *c)
{
	char *tok, *eol, *tmp;
	size_t len;

	eol = strchr(cgline, ':');
	if (!eol)
		return false;

	len = eol - cgline;
	tmp = alloca(len + 1);
	memcpy(tmp, cgline, len);
	tmp[len] = '\0';

	lxc_iterate_parts(tok, tmp, ",") {
		if (strcmp(tok, c) == 0)
			return true;
	}

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
	FILE *f;
	char *line = NULL;
	size_t len = 0;

	f = fopen("/proc/self/cgroup", "r");
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

	free(line);
	fclose(f);
	return 0;
}

static void trim(char *s)
{
	size_t len;

	len = strlen(s);
	while ((len > 1) && (s[len - 1] == '\n'))
		s[--len] = '\0';
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

		TRACE("  %d: base_cgroup: %s", i, (*it)->base_cgroup ? (*it)->base_cgroup : "(null)");
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
	int i;

	if (!container_cgroup || !hierarchies)
		return 0;

	for (i = 0; hierarchies[i]; i++) {
		int ret;
		struct hierarchy *h = hierarchies[i];

		if (!h->fullcgpath)
			continue;

		ret = recursive_destroy(h->fullcgpath);
		if (ret < 0)
			WARN("Failed to destroy \"%s\"", h->fullcgpath);

		free(h->fullcgpath);
		h->fullcgpath = NULL;
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
	int ret;
	struct generic_userns_exec_data *arg = data;
	uid_t nsuid = (arg->conf->root_nsuid_map != NULL) ? 0 : arg->conf->init_uid;
	gid_t nsgid = (arg->conf->root_nsgid_map != NULL) ? 0 : arg->conf->init_gid;

	ret = setresgid(nsgid, nsgid, nsgid);
	if (ret < 0) {
		SYSERROR("Failed to setresgid(%d, %d, %d)", (int)nsgid,
			 (int)nsgid, (int)nsgid);
		return -1;
	}

	ret = setresuid(nsuid, nsuid, nsuid);
	if (ret < 0) {
		SYSERROR("Failed to setresuid(%d, %d, %d)", (int)nsuid,
			 (int)nsuid, (int)nsuid);
		return -1;
	}

	ret = setgroups(0, NULL);
	if (ret < 0 && errno != EPERM) {
		SYSERROR("Failed to setgroups(0, NULL)");
		return -1;
	}

	return cgroup_rmdir(arg->hierarchies, arg->container_cgroup);
}

static void cgfsng_destroy(struct cgroup_ops *ops, struct lxc_handler *handler)
{
	int ret;
	struct generic_userns_exec_data wrap;

	wrap.origuid = 0;
	wrap.container_cgroup = ops->container_cgroup;
	wrap.hierarchies = ops->hierarchies;
	wrap.conf = handler->conf;

	if (handler->conf && !lxc_list_empty(&handler->conf->id_map))
		ret = userns_exec_1(handler->conf, cgroup_rmdir_wrapper, &wrap,
				    "cgroup_rmdir_wrapper");
	else
		ret = cgroup_rmdir(ops->hierarchies, ops->container_cgroup);
	if (ret < 0) {
		WARN("Failed to destroy cgroups");
		return;
	}
}

static bool cg_unified_create_cgroup(struct hierarchy *h, char *cgname)
{
	size_t i, parts_len;
	char **it;
	size_t full_len = 0;
	char *add_controllers = NULL, *cgroup = NULL;
	char **parts = NULL;
	bool bret = false;

	if (h->version != CGROUP2_SUPER_MAGIC)
		return true;

	if (!h->controllers)
		return true;

	/* For now we simply enable all controllers that we have detected by
	 * creating a string like "+memory +pids +cpu +io".
	 * TODO: In the near future we might want to support "-<controller>"
	 * etc. but whether supporting semantics like this make sense will need
	 * some thinking.
	 */
	for (it = h->controllers; it && *it; it++) {
		full_len += strlen(*it) + 2;
		add_controllers = must_realloc(add_controllers, full_len + 1);

		if (h->controllers[0] == *it)
			add_controllers[0] = '\0';

		(void)strlcat(add_controllers, "+", full_len + 1);
		(void)strlcat(add_controllers, *it, full_len + 1);

		if ((it + 1) && *(it + 1))
			(void)strlcat(add_controllers, " ", full_len + 1);
	}

	parts = lxc_string_split(cgname, '/');
	if (!parts)
		goto on_error;

	parts_len = lxc_array_len((void **)parts);
	if (parts_len > 0)
		parts_len--;

	cgroup = must_make_path(h->mountpoint, h->base_cgroup, NULL);
	for (i = 0; i < parts_len; i++) {
		int ret;
		char *target;

		cgroup = must_append_path(cgroup, parts[i], NULL);
		target = must_make_path(cgroup, "cgroup.subtree_control", NULL);
		ret = lxc_write_to_file(target, add_controllers, full_len, false, 0666);
		free(target);
		if (ret < 0) {
			SYSERROR("Could not enable \"%s\" controllers in the "
				 "unified cgroup \"%s\"", add_controllers, cgroup);
			goto on_error;
		}
	}

	bret = true;

on_error:
	lxc_free_array((void **)parts, free);
	free(add_controllers);
	free(cgroup);
	return bret;
}

static bool create_path_for_hierarchy(struct hierarchy *h, char *cgname)
{
	int ret;

	h->fullcgpath = must_make_path(h->mountpoint, h->base_cgroup, cgname, NULL);
	if (dir_exists(h->fullcgpath)) {
		ERROR("The cgroup \"%s\" already existed", h->fullcgpath);
		return false;
	}

	if (!cg_legacy_handle_cpuset_hierarchy(h, cgname)) {
		ERROR("Failed to handle legacy cpuset controller");
		return false;
	}

	ret = mkdir_p(h->fullcgpath, 0755);
	if (ret < 0) {
		ERROR("Failed to create cgroup \"%s\"", h->fullcgpath);
		return false;
	}

	return cg_unified_create_cgroup(h, cgname);
}

static void remove_path_for_hierarchy(struct hierarchy *h, char *cgname)
{
	int ret;

	ret = rmdir(h->fullcgpath);
	if (ret < 0)
		SYSERROR("Failed to rmdir(\"%s\") from failed creation attempt", h->fullcgpath);

	free(h->fullcgpath);
	h->fullcgpath = NULL;
}

/* Try to create the same cgroup in all hierarchies. Start with cgroup_pattern;
 * next cgroup_pattern-1, -2, ..., -999.
 */
static inline bool cgfsng_create(struct cgroup_ops *ops,
				 struct lxc_handler *handler)
{
	int i;
	size_t len;
	char *container_cgroup, *offset, *tmp;
	int idx = 0;
	struct lxc_conf *conf = handler->conf;

	if (ops->container_cgroup) {
		WARN("cgfsng_create called a second time: %s", ops->container_cgroup);
		return false;
	}

	if (!conf)
		return false;

	if (conf->cgroup_meta.dir)
		tmp = lxc_string_join("/", (const char *[]){conf->cgroup_meta.dir, handler->name, NULL}, false);
	else
		tmp = lxc_string_replace("%n", handler->name, ops->cgroup_pattern);
	if (!tmp) {
		ERROR("Failed expanding cgroup name pattern");
		return false;
	}

	len = strlen(tmp) + 5; /* leave room for -NNN\0 */
	container_cgroup = must_alloc(len);
	(void)strlcpy(container_cgroup, tmp, len);
	free(tmp);
	offset = container_cgroup + len - 5;

again:
	if (idx == 1000) {
		ERROR("Too many conflicting cgroup names");
		goto out_free;
	}

	if (idx) {
		int ret;

		ret = snprintf(offset, 5, "-%d", idx);
		if (ret < 0 || (size_t)ret >= 5) {
			FILE *f = fopen("/dev/null", "w");
			if (f) {
				fprintf(f, "Workaround for GCC7 bug: "
					   "https://gcc.gnu.org/bugzilla/"
					   "show_bug.cgi?id=78969");
				fclose(f);
			}
		}
	}

	for (i = 0; ops->hierarchies[i]; i++) {
		if (!create_path_for_hierarchy(ops->hierarchies[i], container_cgroup)) {
			int j;
			ERROR("Failed to create cgroup \"%s\"", ops->hierarchies[i]->fullcgpath);
			free(ops->hierarchies[i]->fullcgpath);
			ops->hierarchies[i]->fullcgpath = NULL;
			for (j = 0; j < i; j++)
				remove_path_for_hierarchy(ops->hierarchies[j], container_cgroup);
			idx++;
			goto again;
		}
	}

	ops->container_cgroup = container_cgroup;

	return true;

out_free:
	free(container_cgroup);

	return false;
}

static bool cgfsng_enter(struct cgroup_ops *ops, pid_t pid)
{
	int i, len;
	char pidstr[25];

	len = snprintf(pidstr, 25, "%d", pid);
	if (len < 0 || len >= 25)
		return false;

	for (i = 0; ops->hierarchies[i]; i++) {
		int ret;
		char *fullpath;

		fullpath = must_make_path(ops->hierarchies[i]->fullcgpath,
					  "cgroup.procs", NULL);
		ret = lxc_write_to_file(fullpath, pidstr, len, false, 0666);
		if (ret != 0) {
			SYSERROR("Failed to enter cgroup \"%s\"", fullpath);
			free(fullpath);
			return false;
		}
		free(fullpath);
	}

	return true;
}

static int chowmod(char *path, uid_t chown_uid, gid_t chown_gid,
		   mode_t chmod_mode)
{
	int ret;

	ret = chown(path, chown_uid, chown_gid);
	if (ret < 0) {
		SYSWARN("Failed to chown(%s, %d, %d)", path, (int)chown_uid, (int)chown_gid);
		return -1;
	}

	ret = chmod(path, chmod_mode);
	if (ret < 0) {
		SYSWARN("Failed to chmod(%s, %d)", path, (int)chmod_mode);
		return -1;
	}

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
	int i, ret;
	uid_t destuid;
	struct generic_userns_exec_data *arg = data;
	uid_t nsuid = (arg->conf->root_nsuid_map != NULL) ? 0 : arg->conf->init_uid;
	gid_t nsgid = (arg->conf->root_nsgid_map != NULL) ? 0 : arg->conf->init_gid;

	ret = setresgid(nsgid, nsgid, nsgid);
	if (ret < 0) {
		SYSERROR("Failed to setresgid(%d, %d, %d)",
			 (int)nsgid, (int)nsgid, (int)nsgid);
		return -1;
	}

	ret = setresuid(nsuid, nsuid, nsuid);
	if (ret < 0) {
		SYSERROR("Failed to setresuid(%d, %d, %d)",
			 (int)nsuid, (int)nsuid, (int)nsuid);
		return -1;
	}

	ret = setgroups(0, NULL);
	if (ret < 0 && errno != EPERM) {
		SYSERROR("Failed to setgroups(0, NULL)");
		return -1;
	}

	destuid = get_ns_uid(arg->origuid);

	for (i = 0; arg->hierarchies[i]; i++) {
		char *fullpath;
		char *path = arg->hierarchies[i]->fullcgpath;

		ret = chowmod(path, destuid, nsgid, 0775);
		if (ret < 0)
			return -1;

		/* Failures to chown() these are inconvenient but not
		 * detrimental We leave these owned by the container launcher,
		 * so that container root can write to the files to attach.  We
		 * chmod() them 664 so that container systemd can write to the
		 * files (which systemd in wily insists on doing).
		 */

		if (arg->hierarchies[i]->version == CGROUP_SUPER_MAGIC) {
			fullpath = must_make_path(path, "tasks", NULL);
			(void)chowmod(fullpath, destuid, nsgid, 0664);
			free(fullpath);
		}

		fullpath = must_make_path(path, "cgroup.procs", NULL);
		(void)chowmod(fullpath, destuid, nsgid, 0664);
		free(fullpath);

		if (arg->hierarchies[i]->version != CGROUP2_SUPER_MAGIC)
			continue;

		fullpath = must_make_path(path, "cgroup.subtree_control", NULL);
		(void)chowmod(fullpath, destuid, nsgid, 0664);
		free(fullpath);

		fullpath = must_make_path(path, "cgroup.threads", NULL);
		(void)chowmod(fullpath, destuid, nsgid, 0664);
		free(fullpath);
	}

	return 0;
}

static bool cgfsng_chown(struct cgroup_ops *ops, struct lxc_conf *conf)
{
	struct generic_userns_exec_data wrap;

	if (lxc_list_empty(&conf->id_map))
		return true;

	wrap.origuid = geteuid();
	wrap.path = NULL;
	wrap.hierarchies = ops->hierarchies;
	wrap.conf = conf;

	if (userns_exec_1(conf, chown_cgroup_wrapper, &wrap,
			  "chown_cgroup_wrapper") < 0) {
		ERROR("Error requesting cgroup chown in new user namespace");
		return false;
	}

	return true;
}

/* cgroup-full:* is done, no need to create subdirs */
static bool cg_mount_needs_subdirs(int type)
{
	if (type >= LXC_AUTO_CGROUP_FULL_RO)
		return false;

	return true;
}

/* After $rootfs/sys/fs/container/controller/the/cg/path has been created,
 * remount controller ro if needed and bindmount the cgroupfs onto
 * controll/the/cg/path.
 */
static int cg_legacy_mount_controllers(int type, struct hierarchy *h,
				       char *controllerpath, char *cgpath,
				       const char *container_cgroup)
{
	int ret, remount_flags;
	char *sourcepath;
	int flags = MS_BIND;

	if (type == LXC_AUTO_CGROUP_RO || type == LXC_AUTO_CGROUP_MIXED) {
		ret = mount(controllerpath, controllerpath, "cgroup", MS_BIND, NULL);
		if (ret < 0) {
			SYSERROR("Failed to bind mount \"%s\" onto \"%s\"",
				 controllerpath, controllerpath);
			return -1;
		}

		remount_flags = add_required_remount_flags(controllerpath,
							   controllerpath,
							   flags | MS_REMOUNT);
		ret = mount(controllerpath, controllerpath, "cgroup",
			    remount_flags | MS_REMOUNT | MS_BIND | MS_RDONLY,
			    NULL);
		if (ret < 0) {
			SYSERROR("Failed to remount \"%s\" ro", controllerpath);
			return -1;
		}

		INFO("Remounted %s read-only", controllerpath);
	}

	sourcepath = must_make_path(h->mountpoint, h->base_cgroup,
				    container_cgroup, NULL);
	if (type == LXC_AUTO_CGROUP_RO)
		flags |= MS_RDONLY;

	ret = mount(sourcepath, cgpath, "cgroup", flags, NULL);
	if (ret < 0) {
		SYSERROR("Failed to mount \"%s\" onto \"%s\"", h->controllers[0], cgpath);
		free(sourcepath);
		return -1;
	}
	INFO("Mounted \"%s\" onto \"%s\"", h->controllers[0], cgpath);

	if (flags & MS_RDONLY) {
		remount_flags = add_required_remount_flags(sourcepath, cgpath,
							   flags | MS_REMOUNT);
		ret = mount(sourcepath, cgpath, "cgroup", remount_flags, NULL);
		if (ret < 0) {
			SYSERROR("Failed to remount \"%s\" ro", cgpath);
			free(sourcepath);
			return -1;
		}
		INFO("Remounted %s read-only", cgpath);
	}

	free(sourcepath);
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
	 int ret;
	 char *controllers = NULL;
	 char *fstype = "cgroup2";
	 unsigned long flags = 0;

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
	free(controllers);
	if (ret < 0) {
		SYSERROR("Failed to mount \"%s\" with cgroup filesystem type %s", controllerpath, fstype);
		return -1;
	}

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

static bool cgfsng_mount(struct cgroup_ops *ops, struct lxc_handler *handler,
			 const char *root, int type)
{
	int i, ret;
	char *tmpfspath = NULL;
	bool has_cgns = false, retval = false, wants_force_mount = false;

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

	/* Mount tmpfs */
	tmpfspath = must_make_path(root, "/sys/fs/cgroup", NULL);
	ret = safe_mount(NULL, tmpfspath, "tmpfs",
			 MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME,
			 "size=10240k,mode=755", root);
	if (ret < 0)
		goto on_error;

	for (i = 0; ops->hierarchies[i]; i++) {
		char *controllerpath, *path2;
		struct hierarchy *h = ops->hierarchies[i];
		char *controller = strrchr(h->mountpoint, '/');

		if (!controller)
			continue;
		controller++;

		controllerpath = must_make_path(tmpfspath, controller, NULL);
		if (dir_exists(controllerpath)) {
			free(controllerpath);
			continue;
		}

		ret = mkdir(controllerpath, 0755);
		if (ret < 0) {
			SYSERROR("Error creating cgroup path: %s", controllerpath);
			free(controllerpath);
			goto on_error;
		}

		if (has_cgns && wants_force_mount) {
			/* If cgroup namespaces are supported but the container
			 * will not have CAP_SYS_ADMIN after it has started we
			 * need to mount the cgroups manually.
			 */
			ret = cg_mount_in_cgroup_namespace(type, h, controllerpath);
			free(controllerpath);
			if (ret < 0)
				goto on_error;

			continue;
		}

		ret = cg_mount_cgroup_full(type, h, controllerpath);
		if (ret < 0) {
			free(controllerpath);
			goto on_error;
		}

		if (!cg_mount_needs_subdirs(type)) {
			free(controllerpath);
			continue;
		}

		path2 = must_make_path(controllerpath, h->base_cgroup,
				       ops->container_cgroup, NULL);
		ret = mkdir_p(path2, 0755);
		if (ret < 0) {
			free(controllerpath);
			free(path2);
			goto on_error;
		}

		ret = cg_legacy_mount_controllers(type, h, controllerpath,
						  path2, ops->container_cgroup);
		free(controllerpath);
		free(path2);
		if (ret < 0)
			goto on_error;
	}
	retval = true;

on_error:
	free(tmpfspath);
	return retval;
}

static int recursive_count_nrtasks(char *dirname)
{
	struct dirent *direntp;
	DIR *dir;
	int count = 0, ret;
	char *path;

	dir = opendir(dirname);
	if (!dir)
		return 0;

	while ((direntp = readdir(dir))) {
		struct stat mystat;

		if (!strcmp(direntp->d_name, ".") ||
		    !strcmp(direntp->d_name, ".."))
			continue;

		path = must_make_path(dirname, direntp->d_name, NULL);

		if (lstat(path, &mystat))
			goto next;

		if (!S_ISDIR(mystat.st_mode))
			goto next;

		count += recursive_count_nrtasks(path);
	next:
		free(path);
	}

	path = must_make_path(dirname, "cgroup.procs", NULL);
	ret = lxc_count_file_lines(path);
	if (ret != -1)
		count += ret;
	free(path);

	(void)closedir(dir);

	return count;
}

static int cgfsng_nrtasks(struct cgroup_ops *ops)
{
	int count;
	char *path;

	if (!ops->container_cgroup || !ops->hierarchies)
		return -1;

	path = must_make_path(ops->hierarchies[0]->fullcgpath, NULL);
	count = recursive_count_nrtasks(path);
	free(path);
	return count;
}

/* Only root needs to escape to the cgroup of its init. */
static bool cgfsng_escape(const struct cgroup_ops *ops)
{
	int i;

	if (geteuid())
		return true;

	for (i = 0; ops->hierarchies[i]; i++) {
		int ret;
		char *fullpath;

		fullpath = must_make_path(ops->hierarchies[i]->mountpoint,
					  ops->hierarchies[i]->base_cgroup,
					  "cgroup.procs", NULL);
		ret = lxc_write_to_file(fullpath, "0", 2, false, 0666);
		if (ret != 0) {
			SYSERROR("Failed to escape to cgroup \"%s\"", fullpath);
			free(fullpath);
			return false;
		}
		free(fullpath);
	}

	return true;
}

static int cgfsng_num_hierarchies(struct cgroup_ops *ops)
{
	int i;

	for (i = 0; ops->hierarchies[i]; i++)
		;

	return i;
}

static bool cgfsng_get_hierarchies(struct cgroup_ops *ops, int n, char ***out)
{
	int i;

	/* sanity check n */
	for (i = 0; i < n; i++)
		if (!ops->hierarchies[i])
			return false;

	*out = ops->hierarchies[i]->controllers;

	return true;
}

#define THAWED "THAWED"
#define THAWED_LEN (strlen(THAWED))

/* TODO: If the unified cgroup hierarchy grows a freezer controller this needs
 * to be adapted.
 */
static bool cgfsng_unfreeze(struct cgroup_ops *ops)
{
	int ret;
	char *fullpath;
	struct hierarchy *h;

	h = get_hierarchy(ops, "freezer");
	if (!h)
		return false;

	fullpath = must_make_path(h->fullcgpath, "freezer.state", NULL);
	ret = lxc_write_to_file(fullpath, THAWED, THAWED_LEN, false, 0666);
	free(fullpath);
	if (ret < 0)
		return false;

	return true;
}

static const char *cgfsng_get_cgroup(struct cgroup_ops *ops,
				     const char *controller)
{
	struct hierarchy *h;

	h = get_hierarchy(ops, controller);
	if (!h) {
		WARN("Failed to find hierarchy for controller \"%s\"",
		     controller ? controller : "(null)");
		return NULL;
	}

	return h->fullcgpath ? h->fullcgpath + strlen(h->mountpoint) : NULL;
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

/* Technically, we're always at a delegation boundary here (This is especially
 * true when cgroup namespaces are available.). The reasoning is that in order
 * for us to have been able to start a container in the first place the root
 * cgroup must have been a leaf node. Now, either the container's init system
 * has populated the cgroup and kept it as a leaf node or it has created
 * subtrees. In the former case we will simply attach to the leaf node we
 * created when we started the container in the latter case we create our own
 * cgroup for the attaching process.
 */
static int __cg_unified_attach(const struct hierarchy *h, const char *name,
			       const char *lxcpath, const char *pidstr,
			       size_t pidstr_len, const char *controller)
{
	int ret;
	size_t len;
	int fret = -1, idx = 0;
	char *base_path = NULL, *container_cgroup = NULL, *full_path = NULL;

	container_cgroup = lxc_cmd_get_cgroup_path(name, lxcpath, controller);
	/* not running */
	if (!container_cgroup)
		return 0;

	base_path = must_make_path(h->mountpoint, container_cgroup, NULL);
	full_path = must_make_path(base_path, "cgroup.procs", NULL);
	/* cgroup is populated */
	ret = lxc_write_to_file(full_path, pidstr, pidstr_len, false, 0666);
	if (ret < 0 && errno != EBUSY)
		goto on_error;

	if (ret == 0)
		goto on_success;

	free(full_path);

	len = strlen(base_path) + sizeof("/lxc-1000") - 1 +
	      sizeof("/cgroup-procs") - 1;
	full_path = must_alloc(len + 1);
	do {
		if (idx)
			ret = snprintf(full_path, len + 1, "%s/lxc-%d",
				       base_path, idx);
		else
			ret = snprintf(full_path, len + 1, "%s/lxc", base_path);
		if (ret < 0 || (size_t)ret >= len + 1)
			goto on_error;

		ret = mkdir_p(full_path, 0755);
		if (ret < 0 && errno != EEXIST)
			goto on_error;

		(void)strlcat(full_path, "/cgroup.procs", len + 1);
		ret = lxc_write_to_file(full_path, pidstr, len, false, 0666);
		if (ret == 0)
			goto on_success;

		/* this is a non-leaf node */
		if (errno != EBUSY)
			goto on_error;

	} while (++idx > 0 && idx < 1000);

on_success:
	if (idx < 1000)
		fret = 0;

on_error:
	free(base_path);
	free(container_cgroup);
	free(full_path);

	return fret;
}

static bool cgfsng_attach(struct cgroup_ops *ops, const char *name,
			  const char *lxcpath, pid_t pid)
{
	int i, len, ret;
	char pidstr[25];

	len = snprintf(pidstr, 25, "%d", pid);
	if (len < 0 || len >= 25)
		return false;

	for (i = 0; ops->hierarchies[i]; i++) {
		char *path;
		char *fullpath = NULL;
		struct hierarchy *h = ops->hierarchies[i];

		if (h->version == CGROUP2_SUPER_MAGIC) {
			ret = __cg_unified_attach(h, name, lxcpath, pidstr, len,
						  h->controllers[0]);
			if (ret < 0)
				return false;

			continue;
		}

		path = lxc_cmd_get_cgroup_path(name, lxcpath, h->controllers[0]);
		/* not running */
		if (!path)
			continue;

		fullpath = build_full_cgpath_from_monitorpath(h, path, "cgroup.procs");
		free(path);
		ret = lxc_write_to_file(fullpath, pidstr, len, false, 0666);
		if (ret < 0) {
			SYSERROR("Failed to attach %d to %s", (int)pid, fullpath);
			free(fullpath);
			return false;
		}
		free(fullpath);
	}

	return true;
}

/* Called externally (i.e. from 'lxc-cgroup') to query cgroup limits.  Here we
 * don't have a cgroup_data set up, so we ask the running container through the
 * commands API for the cgroup path.
 */
static int cgfsng_get(struct cgroup_ops *ops, const char *filename, char *value,
		      size_t len, const char *name, const char *lxcpath)
{
	int ret = -1;
	size_t controller_len;
	char *controller, *p, *path;
	struct hierarchy *h;

	controller_len = strlen(filename);
	controller = alloca(controller_len + 1);
	(void)strlcpy(controller, filename, controller_len + 1);

	p = strchr(controller, '.');
	if (p)
		*p = '\0';

	path = lxc_cmd_get_cgroup_path(name, lxcpath, controller);
	/* not running */
	if (!path)
		return -1;

	h = get_hierarchy(ops, controller);
	if (h) {
		char *fullpath;

		fullpath = build_full_cgpath_from_monitorpath(h, path, filename);
		ret = lxc_read_from_file(fullpath, value, len);
		free(fullpath);
	}
	free(path);

	return ret;
}

/* Called externally (i.e. from 'lxc-cgroup') to set new cgroup limits.  Here we
 * don't have a cgroup_data set up, so we ask the running container through the
 * commands API for the cgroup path.
 */
static int cgfsng_set(struct cgroup_ops *ops, const char *filename,
		      const char *value, const char *name, const char *lxcpath)
{
	int ret = -1;
	size_t controller_len;
	char *controller, *p, *path;
	struct hierarchy *h;

	controller_len = strlen(filename);
	controller = alloca(controller_len + 1);
	(void)strlcpy(controller, filename, controller_len + 1);

	p = strchr(controller, '.');
	if (p)
		*p = '\0';

	path = lxc_cmd_get_cgroup_path(name, lxcpath, controller);
	/* not running */
	if (!path)
		return -1;

	h = get_hierarchy(ops, controller);
	if (h) {
		char *fullpath;

		fullpath = build_full_cgpath_from_monitorpath(h, path, filename);
		ret = lxc_write_to_file(fullpath, value, strlen(value), false, 0666);
		free(fullpath);
	}
	free(path);

	return ret;
}

/* take devices cgroup line
 *    /dev/foo rwx
 * and convert it to a valid
 *    type major:minor mode
 * line. Return <0 on error. Dest is a preallocated buffer long enough to hold
 * the output.
 */
static int convert_devpath(const char *invalue, char *dest)
{
	int n_parts;
	char *p, *path, type;
	unsigned long minor, major;
	struct stat sb;
	int ret = -EINVAL;
	char *mode = NULL;

	path = must_copy_string(invalue);

	/* Read path followed by mode. Ignore any trailing text.
	 * A '    # comment' would be legal. Technically other text is not
	 * legal, we could check for that if we cared to.
	 */
	for (n_parts = 1, p = path; *p && n_parts < 3; p++) {
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
			goto out;
	}

	if (n_parts == 1)
		goto out;

	ret = stat(path, &sb);
	if (ret < 0)
		goto out;

	mode_t m = sb.st_mode & S_IFMT;
	switch (m) {
	case S_IFBLK:
		type = 'b';
		break;
	case S_IFCHR:
		type = 'c';
		break;
	default:
		ERROR("Unsupported device type %i for \"%s\"", m, path);
		ret = -EINVAL;
		goto out;
	}

	major = MAJOR(sb.st_rdev);
	minor = MINOR(sb.st_rdev);
	ret = snprintf(dest, 50, "%c %lu:%lu %s", type, major, minor, mode);
	if (ret < 0 || ret >= 50) {
		ERROR("Error on configuration value \"%c %lu:%lu %s\" (max 50 "
		      "chars)", type, major, minor, mode);
		ret = -ENAMETOOLONG;
		goto out;
	}
	ret = 0;

out:
	free(path);
	return ret;
}

/* Called from setup_limits - here we have the container's cgroup_data because
 * we created the cgroups.
 */
static int cg_legacy_set_data(struct cgroup_ops *ops, const char *filename,
			      const char *value)
{
	size_t len;
	char *fullpath, *p;
	/* "b|c <2^64-1>:<2^64-1> r|w|m" = 47 chars max */
	char converted_value[50];
	struct hierarchy *h;
	int ret = 0;
	char *controller = NULL;

	len = strlen(filename);
	controller = alloca(len + 1);
	(void)strlcpy(controller, filename, len + 1);

	p = strchr(controller, '.');
	if (p)
		*p = '\0';

	if (strcmp("devices.allow", filename) == 0 && value[0] == '/') {
		ret = convert_devpath(value, converted_value);
		if (ret < 0)
			return ret;
		value = converted_value;
	}

	h = get_hierarchy(ops, controller);
	if (!h) {
		ERROR("Failed to setup limits for the \"%s\" controller. "
		      "The controller seems to be unused by \"cgfsng\" cgroup "
		      "driver or not enabled on the cgroup hierarchy",
		      controller);
		errno = ENOENT;
		return -ENOENT;
	}

	fullpath = must_make_path(h->fullcgpath, filename, NULL);
	ret = lxc_write_to_file(fullpath, value, strlen(value), false, 0666);
	free(fullpath);
	return ret;
}

static bool __cg_legacy_setup_limits(struct cgroup_ops *ops,
				     struct lxc_list *cgroup_settings,
				     bool do_devices)
{
	struct lxc_list *iterator, *next, *sorted_cgroup_settings;
	struct lxc_cgroup *cg;
	bool ret = false;

	if (lxc_list_empty(cgroup_settings))
		return true;

	sorted_cgroup_settings = sort_cgroup_settings(cgroup_settings);
	if (!sorted_cgroup_settings)
		return false;

	lxc_list_for_each(iterator, sorted_cgroup_settings) {
		cg = iterator->elem;

		if (do_devices == !strncmp("devices", cg->subsystem, 7)) {
			if (cg_legacy_set_data(ops, cg->subsystem, cg->value)) {
				if (do_devices && (errno == EACCES || errno == EPERM)) {
					WARN("Failed to set \"%s\" to \"%s\"",
					     cg->subsystem, cg->value);
					continue;
				}
				WARN("Failed to set \"%s\" to \"%s\"",
				     cg->subsystem, cg->value);
				goto out;
			}
			DEBUG("Set controller \"%s\" set to \"%s\"",
			      cg->subsystem, cg->value);
		}
	}

	ret = true;
	INFO("Limits for the legacy cgroup hierarchies have been setup");
out:
	lxc_list_for_each_safe(iterator, sorted_cgroup_settings, next) {
		lxc_list_del(iterator);
		free(iterator);
	}
	free(sorted_cgroup_settings);
	return ret;
}

static bool __cg_unified_setup_limits(struct cgroup_ops *ops,
				      struct lxc_list *cgroup_settings)
{
	struct lxc_list *iterator;
	struct hierarchy *h = ops->unified;

	if (lxc_list_empty(cgroup_settings))
		return true;

	if (!h)
		return false;

	lxc_list_for_each(iterator, cgroup_settings) {
		int ret;
		char *fullpath;
		struct lxc_cgroup *cg = iterator->elem;

		fullpath = must_make_path(h->fullcgpath, cg->subsystem, NULL);
		ret = lxc_write_to_file(fullpath, cg->value, strlen(cg->value), false, 0666);
		free(fullpath);
		if (ret < 0) {
			SYSERROR("Failed to set \"%s\" to \"%s\"",
				 cg->subsystem, cg->value);
			return false;
		}
		TRACE("Set \"%s\" to \"%s\"", cg->subsystem, cg->value);
	}

	INFO("Limits for the unified cgroup hierarchy have been setup");
	return true;
}

static bool cgfsng_setup_limits(struct cgroup_ops *ops, struct lxc_conf *conf,
				bool do_devices)
{
	bool bret;

	bret = __cg_legacy_setup_limits(ops, &conf->cgroup, do_devices);
	if (!bret)
		return false;

	return __cg_unified_setup_limits(ops, &conf->cgroup2);
}

static bool cgroup_use_wants_controllers(const struct cgroup_ops *ops,
				       char **controllers)
{
	char **cur_ctrl, **cur_use;

	if (!ops->cgroup_use)
		return true;

	for (cur_ctrl = controllers; cur_ctrl && *cur_ctrl; cur_ctrl++) {
		bool found = false;

		for (cur_use = ops->cgroup_use; cur_use && *cur_use; cur_use++) {
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

/* At startup, parse_hierarchies finds all the info we need about cgroup
 * mountpoints and current cgroups, and stores it in @d.
 */
static bool cg_hybrid_init(struct cgroup_ops *ops)
{
	int ret;
	char *basecginfo;
	bool will_escape;
	FILE *f;
	size_t len = 0;
	char *line = NULL;
	char **klist = NULL, **nlist = NULL;

	/* Root spawned containers escape the current cgroup, so use init's
	 * cgroups as our base in that case.
	 */
	will_escape = (geteuid() == 0);
	if (will_escape)
		basecginfo = read_file("/proc/1/cgroup");
	else
		basecginfo = read_file("/proc/self/cgroup");
	if (!basecginfo)
		return false;

	ret = get_existing_subsystems(&klist, &nlist);
	if (ret < 0) {
		ERROR("Failed to retrieve available legacy cgroup controllers");
		free(basecginfo);
		return false;
	}

	f = fopen("/proc/self/mountinfo", "r");
	if (!f) {
		ERROR("Failed to open \"/proc/self/mountinfo\"");
		free(basecginfo);
		return false;
	}

	lxc_cgfsng_print_basecg_debuginfo(basecginfo, klist, nlist);

	while (getline(&line, &len, f) != -1) {
		int type;
		bool writeable;
		struct hierarchy *new;
		char *base_cgroup = NULL, *mountpoint = NULL;
		char **controller_list = NULL;

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
			if (controller_list_is_dup(ops->hierarchies, controller_list))
				goto next;

		mountpoint = cg_hybrid_get_mountpoint(line);
		if (!mountpoint) {
			ERROR("Failed parsing mountpoint from \"%s\"", line);
			goto next;
		}

		if (type == CGROUP_SUPER_MAGIC)
			base_cgroup = cg_hybrid_get_current_cgroup(basecginfo, controller_list[0], CGROUP_SUPER_MAGIC);
		else
			base_cgroup = cg_hybrid_get_current_cgroup(basecginfo, NULL, CGROUP2_SUPER_MAGIC);
		if (!base_cgroup) {
			ERROR("Failed to find current cgroup");
			goto next;
		}

		trim(base_cgroup);
		prune_init_scope(base_cgroup);
		if (type == CGROUP2_SUPER_MAGIC)
			writeable = test_writeable_v2(mountpoint, base_cgroup);
		else
			writeable = test_writeable_v1(mountpoint, base_cgroup);
		if (!writeable)
			goto next;

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
		if (!cgroup_use_wants_controllers(ops, controller_list))
			goto next;

		new = add_hierarchy(&ops->hierarchies, controller_list, mountpoint, base_cgroup, type);
		if (type == CGROUP2_SUPER_MAGIC && !ops->unified)
			ops->unified = new;

		continue;

	next:
		free_string_list(controller_list);
		free(mountpoint);
		free(base_cgroup);
	}

	free_string_list(klist);
	free_string_list(nlist);

	free(basecginfo);

	fclose(f);
	free(line);

	TRACE("Writable cgroup hierarchies:");
	lxc_cgfsng_print_hierarchies(ops);

	/* verify that all controllers in cgroup.use and all crucial
	 * controllers are accounted for
	 */
	if (!all_controllers_found(ops))
		return false;

	return true;
}

static int cg_is_pure_unified(void)
{

	int ret;
	struct statfs fs;

	ret = statfs("/sys/fs/cgroup", &fs);
	if (ret < 0)
		return -ENOMEDIUM;

	if (is_fs_type(&fs, CGROUP2_SUPER_MAGIC))
		return CGROUP2_SUPER_MAGIC;

	return 0;
}

/* Get current cgroup from /proc/self/cgroup for the cgroupfs v2 hierarchy. */
static char *cg_unified_get_current_cgroup(void)
{
	char *basecginfo, *base_cgroup;
	bool will_escape;
	char *copy = NULL;

	will_escape = (geteuid() == 0);
	if (will_escape)
		basecginfo = read_file("/proc/1/cgroup");
	else
		basecginfo = read_file("/proc/self/cgroup");
	if (!basecginfo)
		return NULL;

	base_cgroup = strstr(basecginfo, "0::/");
	if (!base_cgroup)
		goto cleanup_on_err;

	base_cgroup = base_cgroup + 3;
	copy = copy_to_eol(base_cgroup);
	if (!copy)
		goto cleanup_on_err;

cleanup_on_err:
	free(basecginfo);
	if (copy)
		trim(copy);

	return copy;
}

static int cg_unified_init(struct cgroup_ops *ops)
{
	int ret;
	char *mountpoint, *subtree_path;
	char **delegatable;
	char *base_cgroup = NULL;

	ret = cg_is_pure_unified();
	if (ret == -ENOMEDIUM)
		return -ENOMEDIUM;

	if (ret != CGROUP2_SUPER_MAGIC)
		return 0;

	base_cgroup = cg_unified_get_current_cgroup();
	if (!base_cgroup)
		return -EINVAL;
	prune_init_scope(base_cgroup);

	/* We assume that we have already been given controllers to delegate
	 * further down the hierarchy. If not it is up to the user to delegate
	 * them to us.
	 */
	mountpoint = must_copy_string("/sys/fs/cgroup");
	subtree_path = must_make_path(mountpoint, base_cgroup,
				      "cgroup.subtree_control", NULL);
	delegatable = cg_unified_get_controllers(subtree_path);
	free(subtree_path);
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

	add_hierarchy(&ops->hierarchies, delegatable, mountpoint, base_cgroup, CGROUP2_SUPER_MAGIC);

	ops->cgroup_layout = CGROUP_LAYOUT_UNIFIED;
	return CGROUP2_SUPER_MAGIC;
}

static bool cg_init(struct cgroup_ops *ops)
{
	int ret;
	const char *tmp;

	tmp = lxc_global_config_value("lxc.cgroup.use");
	if (tmp) {
		char *chop, *cur, *pin;

		pin = must_copy_string(tmp);
		chop = pin;

		lxc_iterate_parts(cur, chop, ",") {
			must_append_string(&ops->cgroup_use, cur);
		}

		free(pin);
	}

	ret = cg_unified_init(ops);
	if (ret < 0)
		return false;

	if (ret == CGROUP2_SUPER_MAGIC)
		return true;

	return cg_hybrid_init(ops);
}

static bool cgfsng_data_init(struct cgroup_ops *ops)
{
	const char *cgroup_pattern;

	/* copy system-wide cgroup information */
	cgroup_pattern = lxc_global_config_value("lxc.cgroup.pattern");
	if (!cgroup_pattern) {
		/* lxc.cgroup.pattern is only NULL on error. */
		ERROR("Failed to retrieve cgroup pattern");
		return false;
	}
	ops->cgroup_pattern = must_copy_string(cgroup_pattern);

	return true;
}

struct cgroup_ops *cgfsng_ops_init(void)
{
	struct cgroup_ops *cgfsng_ops;

	cgfsng_ops = malloc(sizeof(struct cgroup_ops));
	if (!cgfsng_ops)
		return NULL;

	memset(cgfsng_ops, 0, sizeof(struct cgroup_ops));
	cgfsng_ops->cgroup_layout = CGROUP_LAYOUT_UNKNOWN;

	if (!cg_init(cgfsng_ops)) {
		free(cgfsng_ops);
		return NULL;
	}

	cgfsng_ops->data_init = cgfsng_data_init;
	cgfsng_ops->destroy = cgfsng_destroy;
	cgfsng_ops->create = cgfsng_create;
	cgfsng_ops->enter = cgfsng_enter;
	cgfsng_ops->escape = cgfsng_escape;
	cgfsng_ops->num_hierarchies = cgfsng_num_hierarchies;
	cgfsng_ops->get_hierarchies = cgfsng_get_hierarchies;
	cgfsng_ops->get_cgroup = cgfsng_get_cgroup;
	cgfsng_ops->get = cgfsng_get;
	cgfsng_ops->set = cgfsng_set;
	cgfsng_ops->unfreeze = cgfsng_unfreeze;
	cgfsng_ops->setup_limits = cgfsng_setup_limits;
	cgfsng_ops->driver = "cgfsng";
	cgfsng_ops->version = "1.0.0";
	cgfsng_ops->attach = cgfsng_attach;
	cgfsng_ops->chown = cgfsng_chown;
	cgfsng_ops->mount = cgfsng_mount;
	cgfsng_ops->nrtasks = cgfsng_nrtasks;

	return cgfsng_ops;
}
