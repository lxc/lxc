/*
 * lxc: linux Container library
 *
 * Copyright © 2016 Canonical Ltd.
 *
 * Authors:
 * Serge Hallyn <serge.hallyn@ubuntu.com>
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
 * each controller.  It also was not designed for unprivileged use, as
 * that was reserved for cgmanager.
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
#include <sys/types.h>

#include "bdev.h"
#include "cgroup.h"
#include "commands.h"
#include "log.h"
#include "utils.h"

lxc_log_define(lxc_cgfsng, lxc);

static struct cgroup_ops cgfsng_ops;

/*
 * A descriptor for a mounted hierarchy
 * @controllers: either NULL, or a null-terminated list of all
 *   the co-mounted controllers
 * @mountpoint: the mountpoint we will use.  It will be either
 *   /sys/fs/cgroup/controller or /sys/fs/cgroup/controllerlist
 * @base_cgroup: the cgroup under which the container cgroup path
     is created.  This will be either the caller's cgroup (if not
     root), or init's cgroup (if root).
 */
struct hierarchy {
	char **controllers;
	char *mountpoint;
	char *base_cgroup;
	char *fullcgpath;
};

/*
 * The cgroup data which is attached to the lxc_handler.
 * @cgroup_pattern - a copy of the lxc.cgroup.pattern
 * @container_cgroup - if not null, the cgroup which was created for
 *   the container.  For each hierarchy, it is created under the
 *   @hierarchy->base_cgroup directory.  Relative to the base_cgroup
 *   it is the same for all hierarchies.
 * @name - the container name
 */
struct cgfsng_handler_data {
	char *cgroup_pattern;
	char *container_cgroup; // cgroup we created for the container
	char *name; // container name
};

/*
 * @hierarchies - a NULL-terminated array of struct hierarchy, one per
 *   hierarchy.  No duplicates.  First sufficient, writeable mounted
 *   hierarchy wins
 */
struct hierarchy **hierarchies;

/*
 * @cgroup_use - a copy of the lxc.cgroup.use
 */
char *cgroup_use;

/*
 * @lxc_cgfsng_debug - whether to print debug info to stdout for the cgfsng
 * driver
 */
static bool lxc_cgfsng_debug;

static void free_string_list(char **clist)
{
	if (clist) {
		int i;

		for (i = 0; clist[i]; i++)
			free(clist[i]);
		free(clist);
	}
}

/* Re-alllocate a pointer, do not fail */
static void *must_realloc(void *orig, size_t sz)
{
	void *ret;

	do {
		ret = realloc(orig, sz);
	} while (!ret);
	return ret;
}

/* Allocate a pointer, do not fail */
static void *must_alloc(size_t sz)
{
	return must_realloc(NULL, sz);
}

/* return copy of string @entry;  do not fail. */
static char *must_copy_string(const char *entry)
{
	char *ret;

	if (!entry)
		return NULL;
	do {
		ret = strdup(entry);
	} while (!ret);
	return ret;
}

/*
 * This is a special case - return a copy of @entry
 * prepending 'name='.  I.e. turn systemd into name=systemd.
 * Do not fail.
 */
static char *must_prefix_named(char *entry)
{
	char *ret;
	size_t len = strlen(entry);

	ret = must_alloc(len + 6);
	snprintf(ret, len + 6, "name=%s", entry);
	return ret;
}

/*
 * Given a pointer to a null-terminated array of pointers, realloc to
 * add one entry, and point the new entry to NULL.  Do not fail.  Return
 * the index to the second-to-last entry - that is, the one which is
 * now available for use (keeping the list null-terminated).
 */
static int append_null_to_list(void ***list)
{
	int newentry = 0;

	if (*list)
		for (; (*list)[newentry]; newentry++);

	*list = must_realloc(*list, (newentry + 2) * sizeof(void **));
	(*list)[newentry + 1] = NULL;
	return newentry;
}

/*
 * Given a null-terminated array of strings, check whether @entry
 * is one of the strings
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

/*
 * append an entry to the clist.  Do not fail.
 * *clist must be NULL the first time we are called.
 *
 * We also handle named subsystems here.  Any controller which is not a
 * kernel subsystem, we prefix 'name='.  Any which is both a kernel and
 * named subsystem, we refuse to use because we're not sure which we
 * have here.  (TODO - we could work around this in some cases by just
 * remounting to be unambiguous, or by comparing mountpoint contents
 * with current cgroup)
 *
 * The last entry will always be NULL.
 */
static void must_append_controller(char **klist, char **nlist, char ***clist, char *entry)
{
	int newentry;
	char *copy;

	if (string_in_list(klist, entry) && string_in_list(nlist, entry)) {
		ERROR("Refusing to use ambiguous controller '%s'", entry);
		ERROR("It is both a named and kernel subsystem");
		return;
	}

	newentry = append_null_to_list((void ***)clist);

	if (strncmp(entry, "name=", 5) == 0)
		copy = must_copy_string(entry);
	else if (string_in_list(klist, entry))
		copy = must_copy_string(entry);
	else
		copy = must_prefix_named(entry);

	(*clist)[newentry] = copy;
}

static void free_handler_data(struct cgfsng_handler_data *d)
{
	free(d->cgroup_pattern);
	free(d->container_cgroup);
	free(d->name);
	free(d);
}

/*
 * Given a handler's cgroup data, return the struct hierarchy for the
 * controller @c, or NULL if there is none.
 */
struct hierarchy *get_hierarchy(const char *c)
{
	int i;

	if (!hierarchies)
		return NULL;
	for (i = 0; hierarchies[i]; i++) {
		if (string_in_list(hierarchies[i]->controllers, c))
			return hierarchies[i];
	}
	return NULL;
}

static char *must_make_path(const char *first, ...) __attribute__((sentinel));

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
static char *read_file(char *fnam)
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
 *  into bit array
 *
 *	1 0 1 1
 */
static uint32_t *lxc_cpumask(char *buf, size_t nbits)
{
	char *token;
	char *saveptr = NULL;
	size_t arrlen = BITS_TO_LONGS(nbits);
	uint32_t *bitarr = calloc(arrlen, sizeof(uint32_t));
	if (!bitarr)
		return NULL;

	for (; (token = strtok_r(buf, ",", &saveptr)); buf = NULL) {
		errno = 0;
		unsigned start = strtoul(token, NULL, 0);
		unsigned end = start;

		char *range = strchr(token, '-');
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
	size_t i;
	int ret;
	char numstr[LXC_NUMSTRLEN64] = {0};
	char **cpulist = NULL;

	for (i = 0; i <= nbits; i++) {
		if (is_set(i, bitarr)) {
			ret = snprintf(numstr, LXC_NUMSTRLEN64, "%zu", i);
			if (ret < 0 || (size_t)ret >= LXC_NUMSTRLEN64) {
				lxc_free_array((void **)cpulist, free);
				return NULL;
			}
			if (lxc_append_string(&cpulist, numstr) < 0) {
				lxc_free_array((void **)cpulist, free);
				return NULL;
			}
		}
	}
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
	else if (!c1 && c2) // The reverse case is obvs. not needed.
		c1 = c2;

	/* If the above logic is correct, c1 should always hold a valid string
	 * here.
	 */

	errno = 0;
	cpus = strtoul(c1, NULL, 0);
	if (errno != 0)
		return -1;

	return cpus;
}

#define __ISOL_CPUS "/sys/devices/system/cpu/isolated"
static bool filter_and_set_cpus(char *path, bool am_initialized)
{
	char *lastslash, *fpath, oldv;
	int ret;
	ssize_t i;

	ssize_t maxposs = 0, maxisol = 0;
	char *cpulist = NULL, *posscpus = NULL, *isolcpus = NULL;
	uint32_t *possmask = NULL, *isolmask = NULL;
	bool bret = false, flipped_bit = false;

	lastslash = strrchr(path, '/');
	if (!lastslash) { // bug...  this shouldn't be possible
		ERROR("Invalid path: %s.", path);
		return bret;
	}
	oldv = *lastslash;
	*lastslash = '\0';
	fpath = must_make_path(path, "cpuset.cpus", NULL);
	posscpus = read_file(fpath);
	if (!posscpus) {
		SYSERROR("Could not read file: %s.\n", fpath);
		goto on_error;
	}

	/* Get maximum number of cpus found in possible cpuset. */
	maxposs = get_max_cpus(posscpus);
	if (maxposs < 0)
		goto on_error;

	if (!file_exists(__ISOL_CPUS)) {
		/* This system doesn't expose isolated cpus. */
		DEBUG("Path: "__ISOL_CPUS" to read isolated cpus from does not exist.\n");
		cpulist = posscpus;
		/* No isolated cpus but we weren't already initialized by
		 * someone. We should simply copy the parents cpuset.cpus
		 * values.
		 */
		if (!am_initialized) {
			DEBUG("Copying cpuset of parent cgroup.");
			goto copy_parent;
		}
		/* No isolated cpus but we were already initialized by someone.
		 * Nothing more to do for us.
		 */
		goto on_success;
	}

	isolcpus = read_file(__ISOL_CPUS);
	if (!isolcpus) {
		SYSERROR("Could not read file "__ISOL_CPUS);
		goto on_error;
	}
	if (!isdigit(isolcpus[0])) {
		DEBUG("No isolated cpus detected.");
		cpulist = posscpus;
		/* No isolated cpus but we weren't already initialized by
		 * someone. We should simply copy the parents cpuset.cpus
		 * values.
		 */
		if (!am_initialized) {
			DEBUG("Copying cpuset of parent cgroup.");
			goto copy_parent;
		}
		/* No isolated cpus but we were already initialized by someone.
		 * Nothing more to do for us.
		 */
		goto on_success;
	}

	/* Get maximum number of cpus found in isolated cpuset. */
	maxisol = get_max_cpus(isolcpus);
	if (maxisol < 0)
		goto on_error;

	if (maxposs < maxisol)
		maxposs = maxisol;
	maxposs++;

	possmask = lxc_cpumask(posscpus, maxposs);
	if (!possmask) {
		ERROR("Could not create cpumask for all possible cpus.\n");
		goto on_error;
	}

	isolmask = lxc_cpumask(isolcpus, maxposs);
	if (!isolmask) {
		ERROR("Could not create cpumask for all isolated cpus.\n");
		goto on_error;
	}

	for (i = 0; i <= maxposs; i++) {
		if (is_set(i, isolmask) && is_set(i, possmask)) {
			flipped_bit = true;
			clear_bit(i, possmask);
		}
	}

	if (!flipped_bit) {
		DEBUG("No isolated cpus present in cpuset.");
		goto on_success;
	}
	DEBUG("Removed isolated cpus from cpuset.");

	cpulist = lxc_cpumask_to_cpulist(possmask, maxposs);
	if (!cpulist) {
		ERROR("Could not create cpu list.\n");
		goto on_error;
	}

copy_parent:
	*lastslash = oldv;
	fpath = must_make_path(path, "cpuset.cpus", NULL);
	ret = lxc_write_to_file(fpath, cpulist, strlen(cpulist), false);
	if (ret < 0) {
		SYSERROR("Could not write cpu list to: %s.\n", fpath);
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
	char *lastslash, *value = NULL, *fpath, oldv;
	int len = 0;
	int ret;

	lastslash = strrchr(path, '/');
	if (!lastslash) { // bug...  this shouldn't be possible
		ERROR("cgfsng:copy_parent_file: bad path %s", path);
		return false;
	}
	oldv = *lastslash;
	*lastslash = '\0';
	fpath = must_make_path(path, file, NULL);
	len = lxc_read_from_file(fpath, NULL, 0);
	if (len <= 0)
		goto bad;
	value = must_alloc(len + 1);
	if (lxc_read_from_file(fpath, value, len) != len)
		goto bad;
	free(fpath);
	*lastslash = oldv;
	fpath = must_make_path(path, file, NULL);
	ret = lxc_write_to_file(fpath, value, len, false);
	if (ret < 0)
		SYSERROR("Unable to write %s to %s", value, fpath);
	free(fpath);
	free(value);
	return ret >= 0;

bad:
	SYSERROR("Error reading '%s'", fpath);
	free(fpath);
	free(value);
	return false;
}

/*
 * Initialize the cpuset hierarchy in first directory of @gname and
 * set cgroup.clone_children so that children inherit settings.
 * Since the h->base_path is populated by init or ourselves, we know
 * it is already initialized.
 */
static bool handle_cpuset_hierarchy(struct hierarchy *h, char *cgname)
{
	char *cgpath, *clonechildrenpath, v, *slash;

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
	if (mkdir(cgpath, 0755) < 0 && errno != EEXIST) {
		SYSERROR("Failed to create '%s'", cgpath);
		free(cgpath);
		return false;
	}

	clonechildrenpath = must_make_path(cgpath, "cgroup.clone_children", NULL);
	if (!file_exists(clonechildrenpath)) { /* unified hierarchy doesn't have clone_children */
		free(clonechildrenpath);
		free(cgpath);
		return true;
	}
	if (lxc_read_from_file(clonechildrenpath, &v, 1) < 0) {
		SYSERROR("Failed to read '%s'", clonechildrenpath);
		free(clonechildrenpath);
		free(cgpath);
		return false;
	}

	/* Make sure any isolated cpus are removed from cpuset.cpus. */
	if (!filter_and_set_cpus(cgpath, v == '1')) {
		SYSERROR("Failed to remove isolated cpus.");
		free(clonechildrenpath);
		free(cgpath);
		return false;
	}

	if (v == '1') {  /* already set for us by someone else */
		DEBUG("\"cgroup.clone_children\" was already set to \"1\".");
		free(clonechildrenpath);
		free(cgpath);
		return true;
	}

	/* copy parent's settings */
	if (!copy_parent_file(cgpath, "cpuset.mems")) {
		SYSERROR("Failed to copy \"cpuset.mems\" settings.");
		free(cgpath);
		free(clonechildrenpath);
		return false;
	}
	free(cgpath);

	if (lxc_write_to_file(clonechildrenpath, "1", 1, false) < 0) {
		/* Set clone_children so children inherit our settings */
		SYSERROR("Failed to write 1 to %s", clonechildrenpath);
		free(clonechildrenpath);
		return false;
	}
	free(clonechildrenpath);
	return true;
}

/*
 * Given two null-terminated lists of strings, return true if any string
 * is in both.
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

/*
 * For a null-terminated list of controllers @clist, return true if any of
 * those controllers is already listed the null-terminated list of
 * hierarchies @hlist.  Realistically, if one is present, all must be present.
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

/*
 * Return true if the controller @entry is found in the null-terminated
 * list of hierarchies @hlist
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

/*
 * Return true if all of the controllers which we require have been found.
 * The required list is  freezer and anything in * lxc.cgroup.use.
 */
static bool all_controllers_found(void)
{
	char *p, *saveptr = NULL;
	struct hierarchy ** hlist = hierarchies;

	if (!controller_found(hlist, "freezer")) {
		ERROR("no freezer controller mountpoint found");
		return false;
	}

	if (!cgroup_use)
		return true;
	for (p = strtok_r(cgroup_use, ",", &saveptr); p;
			p = strtok_r(NULL, ",", &saveptr)) {
		if (!controller_found(hlist, p)) {
			ERROR("no %s controller mountpoint found", p);
			return false;
		}
	}
	return true;
}

/* Return true if the fs type is fuse.lxcfs */
static bool is_lxcfs(const char *line)
{
	char *p = strstr(line, " - ");
	if (!p)
		return false;
	return strncmp(p, " - fuse.lxcfs ", 14) == 0;
}

/*
 * Get the controllers from a mountinfo line
 * There are other ways we could get this info.  For lxcfs, field 3
 * is /cgroup/controller-list.  For cgroupfs, we could parse the mount
 * options.  But we simply assume that the mountpoint must be
 * /sys/fs/cgroup/controller-list
 */
static char **get_controllers(char **klist, char **nlist, char *line)
{
	// the fourth field is /sys/fs/cgroup/comma-delimited-controller-list
	int i;
	char *p = line, *p2, *tok, *saveptr = NULL;
	char **aret = NULL;

	for (i = 0; i < 4; i++) {
		p = strchr(p, ' ');
		if (!p)
			return NULL;
		p++;
	}
	if (!p)
		return NULL;
	/* note - if we change how mountinfo works, then our caller
	 * will need to verify /sys/fs/cgroup/ in this field */
	if (strncmp(p, "/sys/fs/cgroup/", 15) != 0) {
		INFO("cgfsng: found hierarchy not under /sys/fs/cgroup: \"%s\"", p);
		return NULL;
	}
	p += 15;
	p2 = strchr(p, ' ');
	if (!p2) {
		ERROR("corrupt mountinfo");
		return NULL;
	}
	*p2 = '\0';
	for (tok = strtok_r(p, ",", &saveptr); tok;
			tok = strtok_r(NULL, ",", &saveptr)) {
		must_append_controller(klist, nlist, &aret, tok);
	}

	return aret;
}

/* return true if the fstype is cgroup */
static bool is_cgroupfs(char *line)
{
	char *p = strstr(line, " - ");
	if (!p)
		return false;
	return strncmp(p, " - cgroup ", 10) == 0;
}

/* Add a controller to our list of hierarchies */
static void add_controller(char **clist, char *mountpoint, char *base_cgroup)
{
	struct hierarchy *new;
	int newentry;

	new = must_alloc(sizeof(*new));
	new->controllers = clist;
	new->mountpoint = mountpoint;
	new->base_cgroup = base_cgroup;
	new->fullcgpath = NULL;

	newentry = append_null_to_list((void ***)&hierarchies);
	hierarchies[newentry] = new;
}

/*
 * Get a copy of the mountpoint from @line, which is a line from
 * /proc/self/mountinfo
 */
static char *get_mountpoint(char *line)
{
	int i;
	char *p = line, *sret;
	size_t len;

	for (i = 0; i < 4; i++) {
		p = strchr(p, ' ');
		if (!p)
			return NULL;
		p++;
	}
	/* we've already stuck a \0 after the mountpoint */
	len = strlen(p);
	sret = must_alloc(len + 1);
	memcpy(sret, p, len);
	sret[len] = '\0';
	return sret;
}

/*
 * Given a multi-line string, return a null-terminated copy of the
 * current line.
 */
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

/*
 * cgline: pointer to character after the first ':' in a line in a
 * \n-terminated /proc/self/cgroup file. Check whether * controller c is
 * present.
 */
static bool controller_in_clist(char *cgline, char *c)
{
	char *tok, *saveptr = NULL, *eol, *tmp;
	size_t len;

	eol = strchr(cgline, ':');
	if (!eol)
		return false;

	len = eol - cgline;
	tmp = alloca(len + 1);
	memcpy(tmp, cgline, len);
	tmp[len] = '\0';

	for (tok = strtok_r(tmp, ",", &saveptr); tok;
			tok = strtok_r(NULL, ",", &saveptr)) {
		if (strcmp(tok, c) == 0)
			return true;
	}
	return false;
}

/*
 * @basecginfo is a copy of /proc/$$/cgroup.  Return the current
 * cgroup for @controller
 */
static char *get_current_cgroup(char *basecginfo, char *controller)
{
	char *p = basecginfo;

	while (1) {
		p = strchr(p, ':');
		if (!p)
			return NULL;
		p++;
		if (controller_in_clist(p, controller)) {
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

/*
 * Given a hierarchy @mountpoint and base @path, verify that we can create
 * directories underneath it.
 */
static bool test_writeable(char *mountpoint, char *path)
{
	char *fullpath = must_make_path(mountpoint, path, NULL);
	int ret;

	ret = access(fullpath, W_OK);
	free(fullpath);
	return ret == 0;
}

static void must_append_string(char ***list, char *entry)
{
	int newentry = append_null_to_list((void ***)list);
	char *copy;

	copy = must_copy_string(entry);
	(*list)[newentry] = copy;
}

static void get_existing_subsystems(char ***klist, char ***nlist)
{
	FILE *f;
	char *line = NULL;
	size_t len = 0;

	if ((f = fopen("/proc/self/cgroup", "r")) == NULL)
		return;
	while (getline(&line, &len, f) != -1) {
		char *p, *p2, *tok, *saveptr = NULL;
		p = strchr(line, ':');
		if (!p)
			continue;
		p++;
		p2 = strchr(p, ':');
		if (!p2)
			continue;
		*p2 = '\0';

		/* If we have a mixture between cgroup v1 and cgroup v2
		 * hierarchies, then /proc/self/cgroup contains entries of the
		 * form:
		 *
		 *	0::/some/path
		 *
		 * We need to skip those.
		 */
		if ((p2 - p) == 0)
			continue;

		for (tok = strtok_r(p, ",", &saveptr); tok;
				tok = strtok_r(NULL, ",", &saveptr)) {
			if (strncmp(tok, "name=", 5) == 0)
				must_append_string(nlist, tok);
			else
				must_append_string(klist, tok);
		}
	}

	free(line);
	fclose(f);
}

static void trim(char *s)
{
	size_t len = strlen(s);
	while ((len > 1) && (s[len - 1] == '\n'))
		s[--len] = '\0';
}

static void lxc_cgfsng_print_handler_data(const struct cgfsng_handler_data *d)
{
	printf("Cgroup information:\r\n");
	printf("  container name: %s\r\n", d->name ? d->name : "(null)");
	printf("  lxc.cgroup.use: %s\r\n", cgroup_use ? cgroup_use : "(null)");
	printf("  lxc.cgroup.pattern: %s\r\n", d->cgroup_pattern ? d->cgroup_pattern : "(null)");
	printf("  cgroup: %s\r\n", d->container_cgroup ? d->container_cgroup : "(null)");
}

static void lxc_cgfsng_print_hierarchies()
{
	struct hierarchy **it;
	int i;

	if (!hierarchies) {
		printf("  No hierarchies found.\r\n");
		return;
	}
	printf("  Hierarchies:\r\n");
	for (i = 0, it = hierarchies; it && *it; it++, i++) {
		char **cit;
		int j;
		printf("  %d: base_cgroup %s\r\n", i, (*it)->base_cgroup ? (*it)->base_cgroup : "(null)");
		printf("      mountpoint %s\r\n", (*it)->mountpoint ? (*it)->mountpoint : "(null)");
		printf("      controllers:\r\n");
		for (j = 0, cit = (*it)->controllers; cit && *cit; cit++, j++)
			printf("      %d: %s\r\n", j, *cit);
	}
}

static void lxc_cgfsng_print_basecg_debuginfo(char *basecginfo, char **klist, char **nlist)
{
	int k;
	char **it;

	printf("basecginfo is:\r\n");
	printf("%s\r\n", basecginfo);

	for (k = 0, it = klist; it && *it; it++, k++)
		printf("kernel subsystem %d: %s\r\n", k, *it);
	for (k = 0, it = nlist; it && *it; it++, k++)
		printf("named subsystem %d: %s\r\n", k, *it);
}

static void lxc_cgfsng_print_debuginfo(const struct cgfsng_handler_data *d)
{
	lxc_cgfsng_print_handler_data(d);
	lxc_cgfsng_print_hierarchies();
}

/*
 * At startup, parse_hierarchies finds all the info we need about
 * cgroup mountpoints and current cgroups, and stores it in @d.
 */
static bool parse_hierarchies(void)
{
	FILE *f;
	char * line = NULL, *basecginfo;
	char **klist = NULL, **nlist = NULL;
	size_t len = 0;

	/*
	 * Root spawned containers escape the current cgroup, so use init's
	 * cgroups as our base in that case.
	 */
	if (geteuid())
		basecginfo = read_file("/proc/self/cgroup");
	else
		basecginfo = read_file("/proc/1/cgroup");
	if (!basecginfo)
		return false;

	if ((f = fopen("/proc/self/mountinfo", "r")) == NULL) {
		SYSERROR("Failed opening /proc/self/mountinfo");
		return false;
	}

	get_existing_subsystems(&klist, &nlist);

	if (lxc_cgfsng_debug)
		lxc_cgfsng_print_basecg_debuginfo(basecginfo, klist, nlist);

	/* we support simple cgroup mounts and lxcfs mounts */
	while (getline(&line, &len, f) != -1) {
		char **controller_list = NULL;
		char *mountpoint, *base_cgroup;

		if (!is_lxcfs(line) && !is_cgroupfs(line))
			continue;

		controller_list = get_controllers(klist, nlist, line);
		if (!controller_list)
			continue;

		if (controller_list_is_dup(hierarchies, controller_list)) {
			free(controller_list);
			continue;
		}

		mountpoint = get_mountpoint(line);
		if (!mountpoint) {
			ERROR("Error reading mountinfo: bad line '%s'", line);
			free_string_list(controller_list);
			continue;
		}

		base_cgroup = get_current_cgroup(basecginfo, controller_list[0]);
		if (!base_cgroup) {
			ERROR("Failed to find current cgroup for controller '%s'", controller_list[0]);
			free_string_list(controller_list);
			free(mountpoint);
			continue;
		}
		trim(base_cgroup);
		prune_init_scope(base_cgroup);
		if (!test_writeable(mountpoint, base_cgroup)) {
			free_string_list(controller_list);
			free(mountpoint);
			free(base_cgroup);
			continue;
		}
		add_controller(controller_list, mountpoint, base_cgroup);
	}

	free_string_list(klist);
	free_string_list(nlist);

	free(basecginfo);

	fclose(f);
	free(line);

	if (lxc_cgfsng_debug) {
		printf("writeable subsystems:\n");
		lxc_cgfsng_print_hierarchies();
	}

	/* verify that all controllers in cgroup.use and all crucial
	 * controllers are accounted for
	 */
	if (!all_controllers_found()) {
		INFO("cgfsng: not all controllers were find, deferring to cgfs driver");
		return false;
	}

	return true;
}

static bool collect_hierarchy_info(void)
{
	const char *tmp;
	errno = 0;
	tmp = lxc_global_config_value("lxc.cgroup.use");
	if (!cgroup_use && errno != 0) { // lxc.cgroup.use can be NULL
		SYSERROR("cgfsng: error reading list of cgroups to use");
		return false;
	}
	cgroup_use = must_copy_string(tmp);

	return parse_hierarchies();
}

static void *cgfsng_init(const char *name)
{
	struct cgfsng_handler_data *d;
	const char *cgroup_pattern;

	d = must_alloc(sizeof(*d));
	memset(d, 0, sizeof(*d));

	d->name = must_copy_string(name);

	cgroup_pattern = lxc_global_config_value("lxc.cgroup.pattern");
	if (!cgroup_pattern) { // lxc.cgroup.pattern is only NULL on error
		ERROR("Error getting cgroup pattern");
		goto out_free;
	}
	d->cgroup_pattern = must_copy_string(cgroup_pattern);

	if (lxc_cgfsng_debug)
		lxc_cgfsng_print_debuginfo(d);

	return d;

out_free:
	free_handler_data(d);
	return NULL;
}

/*
 * Concatenate all passed-in strings into one path.  Do not fail.  If any piece is
 * not prefixed with '/', add a '/'.
 */
static char *must_make_path(const char *first, ...)
{
	va_list args;
	char *cur, *dest;
	size_t full_len = strlen(first);

	dest = must_copy_string(first);

	va_start(args, first);
	while ((cur = va_arg(args, char *)) != NULL) {
		full_len += strlen(cur);
		if (cur[0] != '/')
			full_len++;
		dest = must_realloc(dest, full_len + 1);
		if (cur[0] != '/')
			strcat(dest, "/");
		strcat(dest, cur);
	}
	va_end(args);

	return dest;
}

static int cgroup_rmdir(char *dirname)
{
	struct dirent *direntp;
	DIR *dir;
	int r = 0;

	dir = opendir(dirname);
	if (!dir)
		return -1;

	while ((direntp = readdir(dir))) {
		struct stat mystat;
		char *pathname;

		if (!direntp)
			break;

		if (!strcmp(direntp->d_name, ".") ||
		    !strcmp(direntp->d_name, ".."))
			continue;

		pathname = must_make_path(dirname, direntp->d_name, NULL);

		if (lstat(pathname, &mystat)) {
			if (!r)
				WARN("failed to stat %s", pathname);
			r = -1;
			goto next;
		}

		if (!S_ISDIR(mystat.st_mode))
			goto next;
		if (cgroup_rmdir(pathname) < 0)
			r = -1;
next:
		free(pathname);
	}

	if (rmdir(dirname) < 0) {
		if (!r)
			WARN("failed to delete %s: %s", dirname, strerror(errno));
		r = -1;
	}

	if (closedir(dir) < 0) {
		if (!r)
			WARN("failed to delete %s: %s", dirname, strerror(errno));
		r = -1;
	}
	return r;
}

static int rmdir_wrapper(void *data)
{
	char *path = data;

	if (setresgid(0,0,0) < 0)
		SYSERROR("Failed to setgid to 0");
	if (setresuid(0,0,0) < 0)
		SYSERROR("Failed to setuid to 0");
	if (setgroups(0, NULL) < 0)
		SYSERROR("Failed to clear groups");

	return cgroup_rmdir(path);
}

void recursive_destroy(char *path, struct lxc_conf *conf)
{
	int r;
	if (conf && !lxc_list_empty(&conf->id_map))
		r = userns_exec_1(conf, rmdir_wrapper, path, "rmdir_wrapper");
	else
		r = cgroup_rmdir(path);

	if (r < 0)
		ERROR("Error destroying %s", path);
}

static void cgfsng_destroy(void *hdata, struct lxc_conf *conf)
{
	struct cgfsng_handler_data *d = hdata;

	if (!d)
		return;

	if (d->container_cgroup && hierarchies) {
		int i;
		for (i = 0; hierarchies[i]; i++) {
			struct hierarchy *h = hierarchies[i];
			if (h->fullcgpath) {
				recursive_destroy(h->fullcgpath, conf);
				free(h->fullcgpath);
				h->fullcgpath = NULL;
			}
		}
	}

	free_handler_data(d);
}

struct cgroup_ops *cgfsng_ops_init(void)
{
	if (getenv("LXC_DEBUG_CGFSNG"))
		lxc_cgfsng_debug = true;

	if (!collect_hierarchy_info())
		return NULL;

	return &cgfsng_ops;
}

static bool create_path_for_hierarchy(struct hierarchy *h, char *cgname)
{
	h->fullcgpath = must_make_path(h->mountpoint, h->base_cgroup, cgname, NULL);
	if (dir_exists(h->fullcgpath)) { // it must not already exist
		ERROR("Path \"%s\" already existed.", h->fullcgpath);
		return false;
	}
	if (!handle_cpuset_hierarchy(h, cgname)) {
		ERROR("Failed to handle cgroupfs v1 cpuset controller.");
		return false;
	}
	return mkdir_p(h->fullcgpath, 0755) == 0;
}

static void remove_path_for_hierarchy(struct hierarchy *h, char *cgname)
{
	if (rmdir(h->fullcgpath) < 0)
		SYSERROR("Failed to clean up cgroup %s from failed creation attempt", h->fullcgpath);
	free(h->fullcgpath);
	h->fullcgpath = NULL;
}

/*
 * Try to create the same cgroup in all hierarchies.
 * Start with cgroup_pattern; next cgroup_pattern-1, -2, ..., -999
 */
static inline bool cgfsng_create(void *hdata)
{
	struct cgfsng_handler_data *d = hdata;
	char *tmp, *cgname, *offset;
	int i, idx = 0;
	size_t len;

	if (!d)
		return false;
	if (d->container_cgroup) {
		WARN("cgfsng_create called a second time");
		return false;
	}

	tmp = lxc_string_replace("%n", d->name, d->cgroup_pattern);
	if (!tmp) {
		ERROR("Failed expanding cgroup name pattern");
		return false;
	}
	len = strlen(tmp) + 5; // leave room for -NNN\0
	cgname = must_alloc(len);
	strcpy(cgname, tmp);
	free(tmp);
	offset = cgname + len - 5;

again:
	if (idx == 1000) {
		ERROR("Too many conflicting cgroup names");
		goto out_free;
	}
	if (idx)
		snprintf(offset, 5, "-%d", idx);
	for (i = 0; hierarchies[i]; i++) {
		if (!create_path_for_hierarchy(hierarchies[i], cgname)) {
			int j;
			SYSERROR("Failed to create %s: %s", hierarchies[i]->fullcgpath, strerror(errno));
			free(hierarchies[i]->fullcgpath);
			hierarchies[i]->fullcgpath = NULL;
			for (j = 0; j < i; j++)
				remove_path_for_hierarchy(hierarchies[j], cgname);
			idx++;
			goto again;
		}
	}
	/* Done */
	d->container_cgroup = cgname;
	return true;

out_free:
	free(cgname);
	return false;
}

static bool cgfsng_enter(void *hdata, pid_t pid)
{
	char pidstr[25];
	int i, len;

	len = snprintf(pidstr, 25, "%d", pid);
	if (len < 0 || len > 25)
		return false;

	for (i = 0; hierarchies[i]; i++) {
		char *fullpath = must_make_path(hierarchies[i]->fullcgpath,
						"cgroup.procs", NULL);
		if (lxc_write_to_file(fullpath, pidstr, len, false) != 0) {
			SYSERROR("Failed to enter %s", fullpath);
			free(fullpath);
			return false;
		}
		free(fullpath);
	}

	return true;
}

struct chown_data {
	struct cgfsng_handler_data *d;
	uid_t origuid; // target uid in parent namespace
};

/*
 * chgrp the container cgroups to container group.  We leave
 * the container owner as cgroup owner.  So we must make the
 * directories 775 so that the container can create sub-cgroups.
 *
 * Also chown the tasks and cgroup.procs files.  Those may not
 * exist depending on kernel version.
 */
static int chown_cgroup_wrapper(void *data)
{
	struct chown_data *arg = data;
	uid_t destuid;
	int i;

	if (setresgid(0,0,0) < 0)
		SYSERROR("Failed to setgid to 0");
	if (setresuid(0,0,0) < 0)
		SYSERROR("Failed to setuid to 0");
	if (setgroups(0, NULL) < 0)
		SYSERROR("Failed to clear groups");

	destuid = get_ns_uid(arg->origuid);

	for (i = 0; hierarchies[i]; i++) {
		char *fullpath, *path = hierarchies[i]->fullcgpath;

		if (chown(path, destuid, 0) < 0) {
			SYSERROR("Error chowning %s to %d", path, (int) destuid);
			return -1;
		}

		if (chmod(path, 0775) < 0) {
			SYSERROR("Error chmoding %s", path);
			return -1;
		}

		/*
		 * Failures to chown these are inconvenient but not detrimental
		 * We leave these owned by the container launcher, so that container
		 * root can write to the files to attach.  We chmod them 664 so that
		 * container systemd can write to the files (which systemd in wily
		 * insists on doing)
		 */
		fullpath = must_make_path(path, "tasks", NULL);
		if (chown(fullpath, destuid, 0) < 0 && errno != ENOENT)
			WARN("Failed chowning %s to %d: %s", fullpath, (int) destuid,
			     strerror(errno));
		if (chmod(fullpath, 0664) < 0)
			WARN("Error chmoding %s: %s", path, strerror(errno));
		free(fullpath);

		fullpath = must_make_path(path, "cgroup.procs", NULL);
		if (chown(fullpath, destuid, 0) < 0 && errno != ENOENT)
			WARN("Failed chowning %s to %d: %s", fullpath, (int) destuid,
			     strerror(errno));
		if (chmod(fullpath, 0664) < 0)
			WARN("Error chmoding %s: %s", path, strerror(errno));
		free(fullpath);
	}

	return 0;
}

static bool cgfsns_chown(void *hdata, struct lxc_conf *conf)
{
	struct cgfsng_handler_data *d = hdata;
	struct chown_data wrap;

	if (!d)
		return false;

	if (lxc_list_empty(&conf->id_map))
		return true;

	wrap.d = d;
	wrap.origuid = geteuid();

	if (userns_exec_1(conf, chown_cgroup_wrapper, &wrap,
			  "chown_cgroup_wrapper") < 0) {
		ERROR("Error requesting cgroup chown in new namespace");
		return false;
	}

	return true;
}

/*
 * We've safe-mounted a tmpfs as parent, so we don't need to protect against
 * symlinks any more - just use mount
 */

/* mount cgroup-full if requested */
static int mount_cgroup_full(int type, struct hierarchy *h, char *dest,
				   char *container_cgroup)
{
	if (type < LXC_AUTO_CGROUP_FULL_RO || type > LXC_AUTO_CGROUP_FULL_MIXED)
		return 0;
	if (mount(h->mountpoint, dest, "cgroup", MS_BIND, NULL) < 0) {
		SYSERROR("Error bind-mounting %s cgroup onto %s", h->mountpoint,
			 dest);
		return -1;
	}
	if (type != LXC_AUTO_CGROUP_FULL_RW) {
		unsigned long flags = MS_BIND | MS_NOSUID | MS_NOEXEC | MS_NODEV |
				      MS_REMOUNT | MS_RDONLY;
		if (mount(NULL, dest, "cgroup", flags, NULL) < 0) {
			SYSERROR("Error remounting %s readonly", dest);
			return -1;
		}
	}

	INFO("Bind mounted %s onto %s", h->mountpoint, dest);
	if (type != LXC_AUTO_CGROUP_FULL_MIXED)
		return 0;

	/* mount just the container path rw */
	char *source = must_make_path(h->mountpoint, h->base_cgroup, container_cgroup, NULL);
	char *rwpath = must_make_path(dest, h->base_cgroup, container_cgroup, NULL);
	if (mount(source, rwpath, "cgroup", MS_BIND, NULL) < 0)
		WARN("Failed to mount %s read-write: %s", rwpath,
		     strerror(errno));
	INFO("Made %s read-write", rwpath);
	free(rwpath);
	free(source);
	return 0;
}

/* cgroup-full:* is done, no need to create subdirs */
static bool cg_mount_needs_subdirs(int type)
{
	if (type >= LXC_AUTO_CGROUP_FULL_RO)
		return false;
	return true;
}

/*
 * After $rootfs/sys/fs/container/controller/the/cg/path has been
 * created, remount controller ro if needed and bindmount the
 * cgroupfs onto controll/the/cg/path
 */
static int
do_secondstage_mounts_if_needed(int type, struct hierarchy *h,
				char *controllerpath, char *cgpath,
				const char *container_cgroup)
{
	if (type == LXC_AUTO_CGROUP_RO || type == LXC_AUTO_CGROUP_MIXED) {
		if (mount(controllerpath, controllerpath, "cgroup", MS_BIND, NULL) < 0) {
			SYSERROR("Error bind-mounting %s", controllerpath);
			return -1;
		}
		if (mount(controllerpath, controllerpath, "cgroup",
			   MS_REMOUNT | MS_BIND | MS_RDONLY, NULL) < 0) {
			SYSERROR("Error remounting %s read-only", controllerpath);
			return -1;
		}
		INFO("Remounted %s read-only", controllerpath);
	}
	char *sourcepath = must_make_path(h->mountpoint, h->base_cgroup, container_cgroup, NULL);
	int flags = MS_BIND;
	if (type == LXC_AUTO_CGROUP_RO)
		flags |= MS_RDONLY;
	INFO("Mounting %s onto %s", sourcepath, cgpath);
	if (mount(sourcepath, cgpath, "cgroup", flags, NULL) < 0) {
		free(sourcepath);
		SYSERROR("Error mounting cgroup %s onto %s", h->controllers[0],
				cgpath);
		return -1;
	}
	free(sourcepath);
	INFO("Completed second stage cgroup automounts for %s", cgpath);
	return 0;
}

static bool cgfsng_mount(void *hdata, const char *root, int type)
{
	struct cgfsng_handler_data *d = hdata;
	char *tmpfspath = NULL;
	bool retval = false;
	int i;

	if ((type & LXC_AUTO_CGROUP_MASK) == 0)
		return true;

	if (cgns_supported())
		return true;

	tmpfspath = must_make_path(root, "/sys/fs/cgroup", NULL);

	if (type == LXC_AUTO_CGROUP_NOSPEC)
		type = LXC_AUTO_CGROUP_MIXED;
	else if (type == LXC_AUTO_CGROUP_FULL_NOSPEC)
		type = LXC_AUTO_CGROUP_FULL_MIXED;

	/* Mount tmpfs */
	if (safe_mount("cgroup_root", tmpfspath, "tmpfs",
			MS_NOSUID|MS_NODEV|MS_NOEXEC|MS_RELATIME,
			"size=10240k,mode=755",
			root) < 0)
		goto  bad;

	for (i = 0; hierarchies[i]; i++) {
		char *controllerpath, *path2;
		struct hierarchy *h = hierarchies[i];
		char *controller = strrchr(h->mountpoint, '/');
		int r;

		if (!controller)
			continue;
		controller++;
		controllerpath = must_make_path(tmpfspath, controller, NULL);
		if (dir_exists(controllerpath)) {
			free(controllerpath);
			continue;
		}
		if (mkdir(controllerpath, 0755) < 0) {
			SYSERROR("Error creating cgroup path: %s", controllerpath);
			free(controllerpath);
			goto bad;
		}
		if (mount_cgroup_full(type, h, controllerpath, d->container_cgroup) < 0) {
			free(controllerpath);
			goto bad;
		}
		if (!cg_mount_needs_subdirs(type)) {
			free(controllerpath);
			continue;
		}
		path2 = must_make_path(controllerpath, h->base_cgroup, d->container_cgroup, NULL);
		if (mkdir_p(path2, 0755) < 0) {
			free(controllerpath);
			goto bad;
		}

		r = do_secondstage_mounts_if_needed(type, h, controllerpath, path2,
						    d->container_cgroup);
		free(controllerpath);
		free(path2);
		if (r < 0)
			goto bad;
	}
	retval = true;

bad:
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

		if (!direntp)
			break;

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

	(void) closedir(dir);

	return count;
}

static int cgfsng_nrtasks(void *hdata) {
	struct cgfsng_handler_data *d = hdata;
	char *path;
	int count;

	if (!d || !d->container_cgroup || !hierarchies)
		return -1;
	path = must_make_path(hierarchies[0]->fullcgpath, NULL);
	count = recursive_count_nrtasks(path);
	free(path);
	return count;
}

/* Only root needs to escape to the cgroup of its init */
static bool cgfsng_escape()
{
	int i;

	if (geteuid())
		return true;

	for (i = 0; hierarchies[i]; i++) {
		char *fullpath = must_make_path(hierarchies[i]->mountpoint,
						hierarchies[i]->base_cgroup,
						"cgroup.procs", NULL);
		if (lxc_write_to_file(fullpath, "0", 2, false) != 0) {
			SYSERROR("Failed to escape to %s", fullpath);
			free(fullpath);
			return false;
		}
		free(fullpath);
	}

	return true;
}

static int cgfsng_num_hierarchies(void)
{
	int i;

	for (i = 0; hierarchies[i]; i++)
		;

	return i;
}

static bool cgfsng_get_hierarchies(int n, char ***out)
{
	int i;

	/* sanity check n */
	for (i = 0; i < n; i++) {
		if (!hierarchies[i])
			return false;
	}

	*out = hierarchies[i]->controllers;

	return true;
}

#define THAWED "THAWED"
#define THAWED_LEN (strlen(THAWED))

static bool cgfsng_unfreeze(void *hdata)
{
	char *fullpath;
	struct hierarchy *h = get_hierarchy("freezer");

	if (!h)
		return false;
	fullpath = must_make_path(h->fullcgpath, "freezer.state", NULL);
	if (lxc_write_to_file(fullpath, THAWED, THAWED_LEN, false) != 0) {
		free(fullpath);
		return false;
	}
	free(fullpath);
	return true;
}

static const char *cgfsng_get_cgroup(void *hdata, const char *subsystem)
{
	struct hierarchy *h = get_hierarchy(subsystem);
	if (!h)
		return NULL;

	return h->fullcgpath ? h->fullcgpath + strlen(h->mountpoint) : NULL;
}

/*
 * Given a cgroup path returned from lxc_cmd_get_cgroup_path, build a
 * full path, which must be freed by the caller.
 */
static char *build_full_cgpath_from_monitorpath(struct hierarchy *h,
						const char *inpath,
						const char *filename)
{
	return must_make_path(h->mountpoint, inpath, filename, NULL);
}

static bool cgfsng_attach(const char *name, const char *lxcpath, pid_t pid)
{
	char pidstr[25];
	int i, len;

	len = snprintf(pidstr, 25, "%d", pid);
	if (len < 0 || len > 25)
		return false;

	for (i = 0; hierarchies[i]; i++) {
		char *path, *fullpath;
		struct hierarchy *h = hierarchies[i];

		path = lxc_cmd_get_cgroup_path(name, lxcpath, h->controllers[0]);
		if (!path) // not running
			continue;

		fullpath = build_full_cgpath_from_monitorpath(h, path, "cgroup.procs");
		free(path);
		if (lxc_write_to_file(fullpath, pidstr, len, false) != 0) {
			SYSERROR("Failed to attach %d to %s", (int)pid, fullpath);
			free(fullpath);
			return false;
		}
		free(fullpath);
	}

	return true;
}

/*
 * Called externally (i.e. from 'lxc-cgroup') to query cgroup limits.
 * Here we don't have a cgroup_data set up, so we ask the running
 * container through the commands API for the cgroup path
 */
static int cgfsng_get(const char *filename, char *value, size_t len, const char *name, const char *lxcpath)
{
	char *subsystem, *p, *path;
	struct hierarchy *h;
	int ret = -1;

	subsystem = alloca(strlen(filename) + 1);
	strcpy(subsystem, filename);
	if ((p = strchr(subsystem, '.')) != NULL)
		*p = '\0';

	path = lxc_cmd_get_cgroup_path(name, lxcpath, subsystem);
	if (!path) // not running
		return -1;

	h = get_hierarchy(subsystem);
	if (h) {
		char *fullpath = build_full_cgpath_from_monitorpath(h, path, filename);
		ret = lxc_read_from_file(fullpath, value, len);
		free(fullpath);
	}

	free(path);

	return ret;
}

/*
 * Called externally (i.e. from 'lxc-cgroup') to set new cgroup limits.
 * Here we don't have a cgroup_data set up, so we ask the running
 * container through the commands API for the cgroup path
 */
static int cgfsng_set(const char *filename, const char *value, const char *name, const char *lxcpath)
{
	char *subsystem, *p, *path;
	struct hierarchy *h;
	int ret = -1;

	subsystem = alloca(strlen(filename) + 1);
	strcpy(subsystem, filename);
	if ((p = strchr(subsystem, '.')) != NULL)
		*p = '\0';

	path = lxc_cmd_get_cgroup_path(name, lxcpath, subsystem);
	if (!path) // not running
		return -1;

	h = get_hierarchy(subsystem);
	if (h) {
		char *fullpath = build_full_cgpath_from_monitorpath(h, path, filename);
		ret = lxc_write_to_file(fullpath, value, strlen(value), false);
		free(fullpath);
	}

	free(path);

	return ret;
}

/*
 * Called from setup_limits - here we have the container's cgroup_data because
 * we created the cgroups
 */
static int lxc_cgroup_set_data(const char *filename, const char *value, struct cgfsng_handler_data *d)
{
	char *subsystem = NULL, *p;
	int ret = -1;
	struct hierarchy *h;

	subsystem = alloca(strlen(filename) + 1);
	strcpy(subsystem, filename);
	if ((p = strchr(subsystem, '.')) != NULL)
		*p = '\0';

	h = get_hierarchy(subsystem);
	if (h) {
		char *fullpath = must_make_path(h->fullcgpath, filename, NULL);
		ret = lxc_write_to_file(fullpath, value, strlen(value), false);
		free(fullpath);
	}
	return ret;
}

static bool cgfsng_setup_limits(void *hdata, struct lxc_list *cgroup_settings,
				  bool do_devices)
{
	struct cgfsng_handler_data *d = hdata;
	struct lxc_list *iterator, *sorted_cgroup_settings, *next;
	struct lxc_cgroup *cg;
	bool ret = false;

	if (lxc_list_empty(cgroup_settings))
		return true;

	sorted_cgroup_settings = sort_cgroup_settings(cgroup_settings);
	if (!sorted_cgroup_settings) {
		return false;
	}

	lxc_list_for_each(iterator, sorted_cgroup_settings) {
		cg = iterator->elem;

		if (do_devices == !strncmp("devices", cg->subsystem, 7)) {
			if (lxc_cgroup_set_data(cg->subsystem, cg->value, d)) {
				if (do_devices && (errno == EACCES || errno == EPERM)) {
					WARN("Error setting %s to %s for %s",
					      cg->subsystem, cg->value, d->name);
					continue;
				}
				SYSERROR("Error setting %s to %s for %s",
				      cg->subsystem, cg->value, d->name);
				goto out;
			}
			DEBUG("cgroup '%s' set to '%s'", cg->subsystem, cg->value);
		}
	}

	ret = true;
	INFO("cgroup has been setup");
out:
	lxc_list_for_each_safe(iterator, sorted_cgroup_settings, next) {
		lxc_list_del(iterator);
		free(iterator);
	}
	free(sorted_cgroup_settings);
	return ret;
}

static struct cgroup_ops cgfsng_ops = {
	.init = cgfsng_init,
	.destroy = cgfsng_destroy,
	.create = cgfsng_create,
	.enter = cgfsng_enter,
	.escape = cgfsng_escape,
	.num_hierarchies = cgfsng_num_hierarchies,
	.get_hierarchies = cgfsng_get_hierarchies,
	.get_cgroup = cgfsng_get_cgroup,
	.get = cgfsng_get,
	.set = cgfsng_set,
	.unfreeze = cgfsng_unfreeze,
	.setup_limits = cgfsng_setup_limits,
	.name = "cgroupfs-ng",
	.attach = cgfsng_attach,
	.chown = cgfsns_chown,
	.mount_cgroup = cgfsng_mount,
	.nrtasks = cgfsng_nrtasks,
	.driver = CGFSNG,

	/* unsupported */
	.create_legacy = NULL,
};
