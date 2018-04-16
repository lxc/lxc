/* pam-cgfs
 *
 * Copyright © 2016 Canonical, Inc
 * Author: Serge Hallyn <serge.hallyn@ubuntu.com>
 * Author: Christian Brauner <christian.brauner@ubuntu.com>
 *
 * When a user logs in, this pam module will create cgroups which the user may
 * administer. It handles both pure cgroupfs v1 and pure cgroupfs v2, as well as
 * mixed mounts, where some controllers are mounted in a standard cgroupfs v1
 * hierarchy location (/sys/fs/cgroup/<controller>) and others are in the
 * cgroupfs v2 hierarchy.
 * Writeable cgroups are either created for all controllers or, if specified,
 * for any controllers listed on the command line.
 * The cgroup created will be "user/$user/0" for the first session,
 * "user/$user/1" for the second, etc.
 *
 * Systems with a systemd init system are treated specially, both with respect
 * to cgroupfs v1 and cgroupfs v2. For both, cgroupfs v1 and cgroupfs v2, We
 * check whether systemd already placed us in a cgroup it created:
 *
 *	user.slice/user-uid.slice/session-n.scope
 *
 * by checking whether uid == our uid. If it did, we simply chown the last
 * part (session-n.scope). If it did not we create a cgroup as outlined above
 * (user/$user/n) and chown it to our uid.
 * The same holds for cgroupfs v2 where this assumptions becomes crucial:
 * We __have to__ be placed in our under the cgroup systemd created for us on
 * login, otherwise things like starting an xserver or similar will not work.
 *
 * All requested cgroups must be mounted under /sys/fs/cgroup/$controller,
 * no messing around with finding mountpoints.
 *
 * See COPYING file for details.
 */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <linux/unistd.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>

#define PAM_SM_SESSION
#include <security/_pam_macros.h>
#include <security/pam_modules.h>

#include "utils.h"

#define pam_cgfs_debug_stream(stream, format, ...)                                \
	do {                                                                   \
		fprintf(stream, "%s: %d: %s: " format, __FILE__, __LINE__,     \
			__func__, __VA_ARGS__);                                \
	} while (false)

#define pam_cgfs_error(format, ...) pam_cgfs_debug_stream(stderr, format, __VA_ARGS__)

#ifdef DEBUG
#define pam_cgfs_debug(format, ...) pam_cgfs_error(format, __VA_ARGS__)
#else
#define pam_cgfs_debug(format, ...)
#endif /* DEBUG */

/* Taken over modified from the kernel sources. */
#define NBITS 32 /* bits in uint32_t */
#define DIV_ROUND_UP(n, d) (((n) + (d)-1) / (d))
#define BITS_TO_LONGS(nr) DIV_ROUND_UP(nr, NBITS)

static enum cg_mount_mode {
	CGROUP_UNKNOWN = -1,
	CGROUP_MIXED = 0,
	CGROUP_PURE_V1 = 1,
	CGROUP_PURE_V2 = 2,
	CGROUP_UNINITIALIZED = 3,
} cg_mount_mode = CGROUP_UNINITIALIZED;

/* Common helper functions. Most of these have been taken from LXC. */
static void append_line(char **dest, size_t oldlen, char *new, size_t newlen);
static int append_null_to_list(void ***list);
static void batch_realloc(char **mem, size_t oldlen, size_t newlen);
static inline void clear_bit(unsigned bit, uint32_t *bitarr)
{
	bitarr[bit / NBITS] &= ~(1 << (bit % NBITS));
}
static char *copy_to_eol(char *s);
static void free_string_list(char **list);
static char *get_mountpoint(char *line);
static bool get_uid_gid(const char *user, uid_t *uid, gid_t *gid);
static int handle_login(const char *user, uid_t uid, gid_t gid);
static inline bool is_set(unsigned bit, uint32_t *bitarr)
{
	return (bitarr[bit / NBITS] & (1 << (bit % NBITS))) != 0;
}
static bool is_lxcfs(const char *line);
static bool is_cgv1(char *line);
static bool is_cgv2(char *line);
static void *must_alloc(size_t sz);
static void must_add_to_list(char ***clist, char *entry);
static void must_append_controller(char **klist, char **nlist, char ***clist,
				   char *entry);
static void must_append_string(char ***list, char *entry);
static void mysyslog(int err, const char *format, ...) __attribute__((sentinel));
static char *read_file(char *fnam);
static int read_from_file(const char *filename, void* buf, size_t count);
static int recursive_rmdir(char *dirname);
static inline void set_bit(unsigned bit, uint32_t *bitarr)
{
	bitarr[bit / NBITS] |= (1 << (bit % NBITS));
}
static bool string_in_list(char **list, const char *entry);
static char *string_join(const char *sep, const char **parts, bool use_as_prefix);
static void trim(char *s);
static bool write_int(char *path, int v);
static ssize_t write_nointr(int fd, const void* buf, size_t count);
static int write_to_file(const char *filename, const void *buf, size_t count,
			 bool add_newline);

/* cgroupfs prototypes. */
static bool cg_belongs_to_uid_gid(const char *path, uid_t uid, gid_t gid);
static uint32_t *cg_cpumask(char *buf, size_t nbits);
static bool cg_copy_parent_file(char *path, char *file);
static char *cg_cpumask_to_cpulist(uint32_t *bitarr, size_t nbits);
static bool cg_enter(const char *cgroup);
static void cg_escape(void);
static bool cg_filter_and_set_cpus(char *path, bool am_initialized);
static ssize_t cg_get_max_cpus(char *cpulist);
static int cg_get_version_of_mntpt(const char *path);
static bool cg_init(uid_t uid, gid_t gid);
static void cg_mark_to_make_rw(char **list);
static void cg_prune_empty_cgroups(const char *user);
static bool cg_systemd_created_user_slice(const char *base_cgroup,
					  const char *init_cgroup,
					  const char *in, uid_t uid);
static bool cg_systemd_chown_existing_cgroup(const char *mountpoint,
					     const char *base_cgroup, uid_t uid,
					     gid_t gid,
					     bool systemd_user_slice);
static bool cg_systemd_under_user_slice_1(const char *in, uid_t uid);
static bool cg_systemd_under_user_slice_2(const char *base_cgroup,
					  const char *init_cgroup, uid_t uid);
static void cg_systemd_prune_init_scope(char *cg);
static bool is_lxcfs(const char *line);

/* cgroupfs v1 prototypes. */
struct cgv1_hierarchy {
	char **controllers;
	char *mountpoint;
	char *base_cgroup;
	char *fullcgpath;
	char *init_cgroup;
	bool create_rw_cgroup;
	bool systemd_user_slice;
};

static struct cgv1_hierarchy **cgv1_hierarchies;

static void cgv1_add_controller(char **clist, char *mountpoint,
				char *base_cgroup, char *init_cgroup);
static bool cgv1_controller_in_clist(char *cgline, char *c);
static bool cgv1_controller_lists_intersect(char **l1, char **l2);
static bool cgv1_controller_list_is_dup(struct cgv1_hierarchy **hlist,
					char **clist);
static bool cgv1_create(const char *cgroup, uid_t uid, gid_t gid,
			bool *existed);
static bool cgv1_create_one(struct cgv1_hierarchy *h, const char *cgroup,
			    uid_t uid, gid_t gid, bool *existed);
static bool cgv1_enter(const char *cgroup);
static void cgv1_escape(void);
static bool cgv1_get_controllers(char ***klist, char ***nlist);
static char *cgv1_get_current_cgroup(char *basecginfo, char *controller);
static char **cgv1_get_proc_mountinfo_controllers(char **klist, char **nlist,
						  char *line);
static bool cgv1_handle_cpuset_hierarchy(struct cgv1_hierarchy *h,
					 const char *cgroup);
static bool cgv1_handle_root_cpuset_hierarchy(struct cgv1_hierarchy *h);
static bool cgv1_init(uid_t uid, gid_t gid);
static void cgv1_mark_to_make_rw(char **clist);
static char *cgv1_must_prefix_named(char *entry);
static bool cgv1_prune_empty_cgroups(const char *user);
static bool cgv1_remove_one(struct cgv1_hierarchy *h, const char *cgroup);
static bool is_cgv1(char *line);

/* cgroupfs v2 prototypes. */
struct cgv2_hierarchy {
	char **controllers;
	char *mountpoint;
	char *base_cgroup;
	char *fullcgpath;
	char *init_cgroup;
	bool create_rw_cgroup;
	bool systemd_user_slice;
};

/* Actually this should only be a single hierarchy. But for the sake of
 * parallelism and because the layout of the cgroupfs v2 is still somewhat
 * changing, we'll leave it as an array of structs.
 */
static struct cgv2_hierarchy **cgv2_hierarchies;

static void cgv2_add_controller(char **clist, char *mountpoint,
				char *base_cgroup, char *init_cgroup,
				bool systemd_user_slice);
static bool cgv2_create(const char *cgroup, uid_t uid, gid_t gid,
			bool *existed);
static bool cgv2_enter(const char *cgroup);
static void cgv2_escape(void);
static char *cgv2_get_current_cgroup(int pid);
static bool cgv2_init(uid_t uid, gid_t gid);
static void cgv2_mark_to_make_rw(char **clist);
static bool cgv2_prune_empty_cgroups(const char *user);
static bool cgv2_remove(const char *cgroup);
static bool is_cgv2(char *line);

static int do_mkdir(const char *path, mode_t mode)
{
	int saved_errno;
	mode_t mask;
	int r;

	mask = umask(0);
	r = mkdir(path, mode);
	saved_errno = errno;
	umask(mask);
	errno = saved_errno;
	return (r);
}

/* Create directory and (if necessary) its parents. */
static bool mkdir_parent(const char *root, char *path)
{
	char *b, orig, *e;

	if (strlen(path) < strlen(root))
		return false;

	if (strlen(path) == strlen(root))
		return true;

	b = path + strlen(root) + 1;
	while (true) {
		while (*b && (*b == '/'))
			b++;
		if (!*b)
			return true;

		e = b + 1;
		while (*e && *e != '/')
			e++;

		orig = *e;
		if (orig)
			*e = '\0';

		if (file_exists(path))
			goto next;

		if (do_mkdir(path, 0755) < 0) {
			pam_cgfs_debug("Failed to create %s: %s.\n", path, strerror(errno));
			return false;
		}

	next:
		if (!orig)
			return true;

		*e = orig;
		b = e + 1;
	}

	return false;
}

/* Common helper functions. Most of these have been taken from LXC. */
static void mysyslog(int err, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	openlog("PAM-CGFS", LOG_CONS | LOG_PID, LOG_AUTH);
	vsyslog(err, format, args);
	va_end(args);
	closelog();
}

/* realloc() pointer in batch sizes; do not fail. */
#define BATCH_SIZE 50
static void batch_realloc(char **mem, size_t oldlen, size_t newlen)
{
	int newbatches = (newlen / BATCH_SIZE) + 1;
	int oldbatches = (oldlen / BATCH_SIZE) + 1;

	if (!*mem || newbatches > oldbatches)
		*mem = must_realloc(*mem, newbatches * BATCH_SIZE);
}

/* Append lines as is to pointer; do not fail. */
static void append_line(char **dest, size_t oldlen, char *new, size_t newlen)
{
	size_t full = oldlen + newlen;

	batch_realloc(dest, oldlen, full + 1);

	memcpy(*dest + oldlen, new, newlen + 1);
}

/* Read in whole file and return allocated pointer. */
static char *read_file(char *fnam)
{
	FILE *f;
	int linelen;
	char *line = NULL, *buf = NULL;
	size_t len = 0, fulllen = 0;

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

/* Given a pointer to a null-terminated array of pointers, realloc to add one
 * entry, and point the new entry to NULL. Do not fail. Return the index to the
 * second-to-last entry - that is, the one which is now available for use
 * (keeping the list null-terminated).
 */
static int append_null_to_list(void ***list)
{
	int newentry = 0;

	if (*list)
		for (; (*list)[newentry]; newentry++) {
			;
		}

	*list = must_realloc(*list, (newentry + 2) * sizeof(void **));
	(*list)[newentry + 1] = NULL;

	return newentry;
}

/* Append new entry to null-terminated array of pointer; make sure that array of
 * pointers will still be null-terminated.
 */
static void must_append_string(char ***list, char *entry)
{
	int newentry;
	char *copy;

	newentry = append_null_to_list((void ***)list);
	copy = must_copy_string(entry);
	(*list)[newentry] = copy;
}

/* Remove newlines from string. */
static void trim(char *s)
{
	size_t len = strlen(s);

	while ((len > 0) && s[len - 1] == '\n')
		s[--len] = '\0';
}

/* Allocate pointer; do not fail. */
static void *must_alloc(size_t sz)
{
	return must_realloc(NULL, sz);
}

/* Make allocated copy of string. End of string is taken to be '\n'. */
static char *copy_to_eol(char *s)
{
	char *newline, *sret;
	size_t len;

	newline = strchr(s, '\n');
	if (!newline)
		return NULL;

	len = newline - s;
	sret = must_alloc(len + 1);
	memcpy(sret, s, len);
	sret[len] = '\0';

	return sret;
}

/* Check if given entry under /proc/<pid>/mountinfo is a fuse.lxcfs mount. */
static bool is_lxcfs(const char *line)
{
	char *p = strstr(line, " - ");
	if (!p)
		return false;

	return strncmp(p, " - fuse.lxcfs ", 14) == 0;
}

/* Check if given entry under /proc/<pid>/mountinfo is a cgroupfs v1 mount. */
static bool is_cgv1(char *line)
{
	char *p = strstr(line, " - ");
	if (!p)
		return false;

	return strncmp(p, " - cgroup ", 10) == 0;
}

/* Check if given entry under /proc/<pid>/mountinfo is a cgroupfs v2 mount. */
static bool is_cgv2(char *line)
{
	char *p = strstr(line, " - ");
	if (!p)
		return false;

	return strncmp(p, " - cgroup2 ", 11) == 0;
}

/* Given a null-terminated array of strings, check whether @entry is one of the
 * strings
 */
static bool string_in_list(char **list, const char *entry)
{
	char **it;

	for (it = list; it && *it; it++)
		if (strcmp(*it, entry) == 0)
			return true;

	return false;
}

/*
 * Creates a null-terminated array of strings, made by splitting the entries in
 * @str on each @sep. Caller is responsible for calling free_string_list.
 */
static char **make_string_list(const char *str, const char *sep)
{
	char *copy, *tok;
	char *saveptr = NULL;
	char **clist = NULL;

	copy = must_copy_string(str);

	for (tok = strtok_r(copy, sep, &saveptr); tok;
	     tok = strtok_r(NULL, sep, &saveptr))
		must_add_to_list(&clist, tok);

	free(copy);

	return clist;
}

/* Gets the length of a null-terminated array of strings. */
static size_t string_list_length(char **list)
{
	size_t len = 0;
	char **it;

	for (it = list; it && *it; it++)
		len++;

	return len;
}

/* Free null-terminated array of strings. */
static void free_string_list(char **list)
{
	char **it;

	for (it = list; it && *it; it++)
		free(*it);
	free(list);
}

/* Write single integer to file. */
static bool write_int(char *path, int v)
{
	FILE *f;
	bool ret = true;

	f = fopen(path, "w");
	if (!f)
		return false;

	if (fprintf(f, "%d\n", v) < 0)
		ret = false;

	if (fclose(f) != 0)
		ret = false;

	return ret;
}

/* Recursively remove directory and its parents. */
static int recursive_rmdir(char *dirname)
{
	struct dirent *direntp;
	DIR *dir;
	int r = 0;

	dir = opendir(dirname);
	if (!dir)
		return -ENOENT;

	while ((direntp = readdir(dir))) {
		struct stat st;
		char *pathname;

		if (!direntp)
			break;

		if (!strcmp(direntp->d_name, ".") ||
		    !strcmp(direntp->d_name, ".."))
			continue;

		pathname = must_make_path(dirname, direntp->d_name, NULL);

		if (lstat(pathname, &st)) {
			if (!r)
				pam_cgfs_debug("Failed to stat %s.\n", pathname);
			r = -1;
			goto next;
		}

		if (!S_ISDIR(st.st_mode))
			goto next;

		if (recursive_rmdir(pathname) < 0)
			r = -1;
next:
		free(pathname);
	}

	if (rmdir(dirname) < 0) {
		if (!r)
			pam_cgfs_debug("Failed to delete %s: %s.\n", dirname, strerror(errno));
		r = -1;
	}

	if (closedir(dir) < 0) {
		if (!r)
			pam_cgfs_debug("Failed to delete %s: %s.\n", dirname, strerror(errno));
		r = -1;
	}

	return r;
}

/* Add new entry to null-terminated array of pointers. Make sure array is still
 * null-terminated.
 */
static void must_add_to_list(char ***clist, char *entry)
{
	int newentry;

	newentry = append_null_to_list((void ***)clist);
	(*clist)[newentry] = must_copy_string(entry);
}

/* Get mountpoint from a /proc/<pid>/mountinfo line. */
static char *get_mountpoint(char *line)
{
	int i;
	char *p, *sret, *p2;
	size_t len;

	p = line;

	for (i = 0; i < 4; i++) {
		p = strchr(p, ' ');
		if (!p)
			return NULL;
		p++;
	}

	p2 = strchr(p, ' ');
	if (p2)
		*p2 = '\0';

	len = strlen(p);
	sret = must_alloc(len + 1);
	memcpy(sret, p, len);
	sret[len] = '\0';

	return sret;
}

/* Create list of cgroupfs v1 controller found under /proc/self/cgroup. Skips
 * the 0::/some/path cgroupfs v2 hierarchy listed. Splits controllers into
 * kernel controllers (@klist) and named controllers (@nlist).
 */
static bool cgv1_get_controllers(char ***klist, char ***nlist)
{
	FILE *f;
	char *line = NULL;
	size_t len = 0;

	f = fopen("/proc/self/cgroup", "r");
	if (!f)
		return false;

	while (getline(&line, &len, f) != -1) {
		char *p, *p2, *tok;
		char *saveptr = NULL;

		p = strchr(line, ':');
		if (!p)
			continue;
		p++;

		p2 = strchr(p, ':');
		if (!p2)
			continue;
		*p2 = '\0';

		/* Skip the v2 hierarchy. */
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

	return true;
}

/* Get list of controllers for cgroupfs v2 hierarchy by looking at
 * cgroup.controllers and/or cgroup.subtree_control of a given (parent) cgroup.
static bool cgv2_get_controllers(char ***klist)
{
	return -ENOSYS;
}
*/

/* Get current cgroup from /proc/self/cgroup for the cgroupfs v2 hierarchy. */
static char *cgv2_get_current_cgroup(int pid)
{
	int ret;
	char *cgroups_v2;
	char *current_cgroup;
	char *copy = NULL;
	/* The largest integer that can fit into long int is 2^64. This is a
	 * 20-digit number. */
#define __PIDLEN /* /proc */ 5 + /* /pid-to-str */ 21 + /* /cgroup */ 7 + /* \0 */ 1
	char path[__PIDLEN];

	ret = snprintf(path, __PIDLEN, "/proc/%d/cgroup", pid);
	if (ret < 0 || ret >= __PIDLEN)
		return NULL;

	cgroups_v2 = read_file(path);
	if (!cgroups_v2)
		return NULL;

	current_cgroup = strstr(cgroups_v2, "0::/");
	if (!current_cgroup)
		goto cleanup_on_err;

	current_cgroup = current_cgroup + 3;
	copy = copy_to_eol(current_cgroup);
	if (!copy)
		goto cleanup_on_err;

cleanup_on_err:
	free(cgroups_v2);
	if (copy)
		trim(copy);

	return copy;
}

/* Given two null-terminated lists of strings, return true if any string is in
 * both.
 */
static bool cgv1_controller_lists_intersect(char **l1, char **l2)
{
	char **it;

	if (!l2)
		return false;

	for (it = l1; it && *it; it++)
		if (string_in_list(l2, *it))
			return true;

	return false;
}

/* For a null-terminated list of controllers @clist, return true if any of those
 * controllers is already listed the null-terminated list of hierarchies @hlist.
 * Realistically, if one is present, all must be present.
 */
static bool cgv1_controller_list_is_dup(struct cgv1_hierarchy **hlist, char **clist)
{
	struct cgv1_hierarchy **it;

	for (it = hlist; it && *it; it++)
		if ((*it)->controllers)
			if (cgv1_controller_lists_intersect((*it)->controllers, clist))
				return true;
	return false;

}

/* Set boolean to mark controllers under which we are supposed create a
 * writeable cgroup.
 */
static void cgv1_mark_to_make_rw(char **clist)
{
	struct cgv1_hierarchy **it;

	for (it = cgv1_hierarchies; it && *it; it++)
		if ((*it)->controllers)
			if (cgv1_controller_lists_intersect((*it)->controllers, clist) ||
				string_in_list(clist, "all"))
				(*it)->create_rw_cgroup = true;
}

/* Set boolean to mark whether we are supposed to create a writeable cgroup in
 * the cgroupfs v2 hierarchy.
 */
static void cgv2_mark_to_make_rw(char **clist)
{
	if (string_in_list(clist, "unified") || string_in_list(clist, "all"))
		if (cgv2_hierarchies)
			(*cgv2_hierarchies)->create_rw_cgroup = true;
}

/* Wrapper around cgv{1,2}_mark_to_make_rw(). */
static void cg_mark_to_make_rw(char **clist)
{
	cgv1_mark_to_make_rw(clist);
	cgv2_mark_to_make_rw(clist);
}

/* Prefix any named controllers with "name=", e.g. "name=systemd". */
static char *cgv1_must_prefix_named(char *entry)
{
	char *s;
	int ret;
	size_t len;

	len = strlen(entry);
	s = must_alloc(len + 6);

	ret = snprintf(s, len + 6, "name=%s", entry);
	if (ret < 0 || (size_t)ret >= (len + 6))
		return NULL;

	return s;
}

/* Append kernel controller in @klist or named controller in @nlist to @clist */
static void must_append_controller(char **klist, char **nlist, char ***clist, char *entry)
{
	int newentry;
	char *copy;

	if (string_in_list(klist, entry) && string_in_list(nlist, entry))
		return;

	newentry = append_null_to_list((void ***)clist);

	if (strncmp(entry, "name=", 5) == 0)
		copy = must_copy_string(entry);
	else if (string_in_list(klist, entry))
		copy = must_copy_string(entry);
	else
		copy = cgv1_must_prefix_named(entry);

	(*clist)[newentry] = copy;
}

/* Get the controllers from a mountinfo line. There are other ways we could get
 * this info. For lxcfs, field 3 is /cgroup/controller-list. For cgroupfs, we
 * could parse the mount options. But we simply assume that the mountpoint must
 * be /sys/fs/cgroup/controller-list
 */
static char **cgv1_get_proc_mountinfo_controllers(char **klist, char **nlist, char *line)
{
	int i;
	char *p, *p2, *tok;
	char *saveptr = NULL;
	char **aret = NULL;

	p = line;

	for (i = 0; i < 4; i++) {
		p = strchr(p, ' ');
		if (!p)
			return NULL;
		p++;
	}
	if (!p)
		return NULL;

	if (strncmp(p, "/sys/fs/cgroup/", 15) != 0)
		return NULL;

	p += 15;

	p2 = strchr(p, ' ');
	if (!p2)
		return NULL;
	*p2 = '\0';

	for (tok = strtok_r(p, ",", &saveptr); tok;
	     tok = strtok_r(NULL, ",", &saveptr))
		must_append_controller(klist, nlist, &aret, tok);

	return aret;
}

/* Check if a cgroupfs v2 controller is present in the string @cgline. */
static bool cgv1_controller_in_clist(char *cgline, char *c)
{
	size_t len;
	char *tok, *eol, *tmp;
	char *saveptr = NULL;

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

/* Get current cgroup from the /proc/<pid>/cgroup file passed in via @basecginfo
 * of a given cgv1 controller passed in via @controller.
 */
static char *cgv1_get_current_cgroup(char *basecginfo, char *controller)
{
	char *p;

	p = basecginfo;

	while (true) {
		p = strchr(p, ':');
		if (!p)
			return NULL;
		p++;

		if (cgv1_controller_in_clist(p, controller)) {
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

	return NULL;
}

/* Remove /init.scope from string @cg. This will mostly affect systemd-based
 * systems.
 */
#define INIT_SCOPE "/init.scope"
static void cg_systemd_prune_init_scope(char *cg)
{
	char *point;

	if (!cg)
		return;

	point = cg + strlen(cg) - strlen(INIT_SCOPE);
	if (point < cg)
		return;

	if (strcmp(point, INIT_SCOPE) == 0) {
		if (point == cg)
			*(point + 1) = '\0';
		else
			*point = '\0';
	}
}

/* Add new info about a mounted cgroupfs v1 hierarchy. Includes the controllers
 * mounted into that hierarchy (e.g. cpu,cpuacct), the mountpoint of that
 * hierarchy (/sys/fs/cgroup/<controller>, the base cgroup of the current
 * process gathered from /proc/self/cgroup, and the init cgroup of PID1 gathered
 * from /proc/1/cgroup.
 */
static void cgv1_add_controller(char **clist, char *mountpoint, char *base_cgroup, char *init_cgroup)
{
	struct cgv1_hierarchy *new;
	int newentry;

	new = must_alloc(sizeof(*new));
	new->controllers = clist;
	new->mountpoint = mountpoint;
	new->base_cgroup = base_cgroup;
	new->fullcgpath = NULL;
	new->create_rw_cgroup = false;
	new->init_cgroup = init_cgroup;
	new->systemd_user_slice = false;

	newentry = append_null_to_list((void ***)&cgv1_hierarchies);
	cgv1_hierarchies[newentry] = new;
}

/* Add new info about the mounted cgroupfs v2 hierarchy. Can (but doesn't
 * currently) include the controllers mounted into the hierarchy (e.g.  memory,
 * pids, blkio), the mountpoint of that hierarchy (Should usually be
 * /sys/fs/cgroup but some init systems seems to think it might be a good idea
 * to also mount empty cgroupfs v2 hierarchies at /sys/fs/cgroup/systemd.), the
 * base cgroup of the current process gathered from /proc/self/cgroup, and the
 * init cgroup of PID1 gathered from /proc/1/cgroup.
 */
static void cgv2_add_controller(char **clist, char *mountpoint, char *base_cgroup, char *init_cgroup, bool systemd_user_slice)
{
	struct cgv2_hierarchy *new;
	int newentry;

	new = must_alloc(sizeof(*new));
	new->controllers = clist;
	new->mountpoint = mountpoint;
	new->base_cgroup = base_cgroup;
	new->fullcgpath = NULL;
	new->create_rw_cgroup = false;
	new->init_cgroup = init_cgroup;
	new->systemd_user_slice = systemd_user_slice;

	newentry = append_null_to_list((void ***)&cgv2_hierarchies);
	cgv2_hierarchies[newentry] = new;
}

/* In Ubuntu 14.04, the paths created for us were
 * '/user/$uid.user/$something.session' This can be merged better with
 * systemd_created_slice_for_us(), but keeping it separate makes it easier to
 * reason about the correctness.
 */
static bool cg_systemd_under_user_slice_1(const char *in, uid_t uid)
{
	char *p;
	size_t len;
	int id;
	char *copy = NULL;
	bool bret = false;

	copy = must_copy_string(in);
	if (strlen(copy) < strlen("/user/1.user/1.session"))
		goto cleanup;
	p = copy + strlen(copy) - 1;

	/* skip any trailing '/' (shouldn't be any, but be sure) */
	while (p >= copy && *p == '/')
		*(p--) = '\0';
	if (p < copy)
		goto cleanup;

	/* Get last path element */
	while (p >= copy && *p != '/')
		p--;
	if (p < copy)
		goto cleanup;
	/* make sure it is something.session */
	len = strlen(p + 1);
	if (len < strlen("1.session") ||
	    strncmp(p + 1 + len - 8, ".session", 8) != 0)
		goto cleanup;

	/* ok last path piece checks out, now check the second to last */
	*(p + 1) = '\0';
	while (p >= copy && *(--p) != '/')
		;
	if (sscanf(p + 1, "%d.user/", &id) != 1)
		goto cleanup;

	if (id != (int)uid)
		goto cleanup;

	bret = true;

cleanup:
	free(copy);
	return bret;
}

/* So long as our path relative to init starts with /user.slice/user-$uid.slice,
 * assume it belongs to $uid and chown it
 */
static bool cg_systemd_under_user_slice_2(const char *base_cgroup,
					  const char *init_cgroup, uid_t uid)
{
	int ret;
	char buf[100];
	size_t curlen, initlen;

	curlen = strlen(base_cgroup);
	initlen = strlen(init_cgroup);
	if (curlen <= initlen)
		return false;

	if (strncmp(base_cgroup, init_cgroup, initlen) != 0)
		return false;

	ret = snprintf(buf, 100, "/user.slice/user-%d.slice/", (int)uid);
	if (ret < 0 || ret >= 100)
		return false;

	if (initlen == 1)
		initlen = 0; // skip the '/'

	return strncmp(base_cgroup + initlen, buf, strlen(buf)) == 0;
}

/* The systemd-created path is: user-$uid.slice/session-c$session.scope. If that
 * is not the end of our systemd path, then we're not part of the PAM call that
 * created that path.
 *
 * The last piece is chowned to $uid, the user- part not.
 * Note: If the user creates paths that look like what we're looking for to
 * 'fool' us, either
 *  - they fool us, we create new cgroups, and they get auto-logged-out.
 *  - they fool a root sudo, systemd cgroup is not changed but chowned, and they
 *    lose ownership of their cgroups
 */
static bool cg_systemd_created_user_slice(const char *base_cgroup,
					  const char *init_cgroup,
					  const char *in, uid_t uid)
{
	char *p;
	size_t len;
	int id;
	char *copy = NULL;
	bool bret = false;

	copy = must_copy_string(in);

	/* An old version of systemd has already created a cgroup for us. */
	if (cg_systemd_under_user_slice_1(in, uid))
		goto succeed;

	/* A new version of systemd has already created a cgroup for us. */
	if (cg_systemd_under_user_slice_2(base_cgroup, init_cgroup, uid))
		goto succeed;

	if (strlen(copy) < strlen("/user-0.slice/session-0.scope"))
		goto cleanup;

	p = copy + strlen(copy) - 1;
	/* Skip any trailing '/' (shouldn't be any, but be sure). */
	while (p >= copy && *p == '/')
		*(p--) = '\0';

	if (p < copy)
		goto cleanup;

	/* Get last path element */
	while (p >= copy && *p != '/')
		p--;

	if (p < copy)
		goto cleanup;

	/* Make sure it is session-something.scope. */
	len = strlen(p + 1);
	if (strncmp(p + 1, "session-", strlen("session-")) != 0 ||
	    strncmp(p + 1 + len - 6, ".scope", 6) != 0)
		goto cleanup;

	/* Ok last path piece checks out, now check the second to last. */
	*(p + 1) = '\0';
	while (p >= copy && *(--p) != '/')
		;

	if (sscanf(p + 1, "user-%d.slice/", &id) != 1)
		goto cleanup;

	if (id != (int)uid)
		goto cleanup;

succeed:
	bret = true;
cleanup:
	free(copy);
	return bret;
}

/* Chown existing cgroup that systemd has already created for us. */
static bool cg_systemd_chown_existing_cgroup(const char *mountpoint,
					     const char *base_cgroup, uid_t uid,
					     gid_t gid, bool systemd_user_slice)
{
	char *path;

	if (!systemd_user_slice)
		return false;

	path = must_make_path(mountpoint, base_cgroup, NULL);

	/* A cgroup within name=systemd has already been created. So we only
	 * need to chown it.
	 */
	if (chown(path, uid, gid) < 0)
		mysyslog(LOG_WARNING, "Failed to chown %s to %d:%d: %s.\n",
			 path, (int)uid, (int)gid, strerror(errno), NULL);
	pam_cgfs_debug("Chowned %s to %d:%d.\n", path, (int)uid, (int)gid);

	free(path);
	return true;
}

/* Detect and store information about cgroupfs v1 hierarchies. */
static bool cgv1_init(uid_t uid, gid_t gid)
{
	FILE *f;
	struct cgv1_hierarchy **it;
	char *basecginfo;
	char *line = NULL;
	char **klist = NULL, **nlist = NULL;
	size_t len = 0;

	basecginfo = read_file("/proc/self/cgroup");
	if (!basecginfo)
		return false;

	f = fopen("/proc/self/mountinfo", "r");
	if (!f) {
		free(basecginfo);
		return false;
	}

	cgv1_get_controllers(&klist, &nlist);

	while (getline(&line, &len, f) != -1) {
		char **controller_list = NULL;
		char *mountpoint, *base_cgroup;

		if (is_lxcfs(line) || !is_cgv1(line))
			continue;

		controller_list = cgv1_get_proc_mountinfo_controllers(klist, nlist, line);
		if (!controller_list)
			continue;

		if (cgv1_controller_list_is_dup(cgv1_hierarchies,
						controller_list)) {
			free(controller_list);
			continue;
		}

		mountpoint = get_mountpoint(line);
		if (!mountpoint) {
			free_string_list(controller_list);
			continue;
		}

		base_cgroup = cgv1_get_current_cgroup(basecginfo, controller_list[0]);
		if (!base_cgroup) {
			free_string_list(controller_list);
			free(mountpoint);
			continue;
		}
		trim(base_cgroup);
		pam_cgfs_debug("Detected cgroupfs v1 controller \"%s\" with "
			    "mountpoint \"%s\" and cgroup \"%s\".\n",
			    controller_list[0], mountpoint, base_cgroup);
		cgv1_add_controller(controller_list, mountpoint, base_cgroup,
				    NULL);
	}
	free_string_list(klist);
	free_string_list(nlist);
	free(basecginfo);
	fclose(f);
	free(line);

	/* Retrieve init cgroup path for all controllers. */
	basecginfo = read_file("/proc/1/cgroup");
	if (!basecginfo)
		return false;

	for (it = cgv1_hierarchies; it && *it; it++) {
		if ((*it)->controllers) {
			char *init_cgroup, *user_slice;
			/* We've already stored the controller and received its
			 * current cgroup. If we now fail to retrieve its init
			 * cgroup, we should probably fail.
			 */
			init_cgroup = cgv1_get_current_cgroup(basecginfo, (*it)->controllers[0]);
			if (!init_cgroup) {
				free(basecginfo);
				return false;
			}
			cg_systemd_prune_init_scope(init_cgroup);
			(*it)->init_cgroup = init_cgroup;
			pam_cgfs_debug("cgroupfs v1 controller \"%s\" has init "
				    "cgroup \"%s\".\n",
				    (*(*it)->controllers), init_cgroup);
			/* Check whether systemd has already created a cgroup
			 * for us.
			 */
			user_slice = must_make_path((*it)->mountpoint, (*it)->base_cgroup, NULL);
			if (cg_systemd_created_user_slice((*it)->base_cgroup, (*it)->init_cgroup, user_slice, uid))
				(*it)->systemd_user_slice = true;
		}
	}
	free(basecginfo);

	return true;
}

/* Check whether @path is a cgroupfs v1 or cgroupfs v2 mount. Returns -1 if
 * statfs fails. If @path is null /sys/fs/cgroup is checked.
 */
static inline int cg_get_version_of_mntpt(const char *path)
{
	if (has_fs_type(path, CGROUP_SUPER_MAGIC))
		return 1;

	if (has_fs_type(path, CGROUP2_SUPER_MAGIC))
		return 2;

	return 0;
}

/* Detect and store information about the cgroupfs v2 hierarchy. Currently only
 * deals with the empty v2 hierachy as we do not retrieve enabled controllers.
 */
static bool cgv2_init(uid_t uid, gid_t gid)
{
	char *mountpoint;
	FILE *f = NULL;
	char *current_cgroup = NULL, *init_cgroup = NULL;
	char * line = NULL;
	size_t len = 0;
	int ret = false;

	current_cgroup = cgv2_get_current_cgroup(getpid());
	if (!current_cgroup) {
		/* No v2 hierarchy present. We're done. */
		ret = true;
		goto cleanup;
	}

	init_cgroup = cgv2_get_current_cgroup(1);
	if (!init_cgroup) {
		/* If we're here and didn't fail already above, then something's
		 * certainly wrong, so error this time.
		 */
		goto cleanup;
	}
	cg_systemd_prune_init_scope(init_cgroup);

	/* Check if the v2 hierarchy is mounted at its standard location.
	 * If so we can skip the rest of the work here. Although the unified
	 * hierarchy can be mounted multiple times, each of those mountpoints
	 * will expose identical information.
	 */
	if (cg_get_version_of_mntpt("/sys/fs/cgroup") == 2) {
		char *user_slice;
		bool has_user_slice = false;

		mountpoint = must_copy_string("/sys/fs/cgroup");
		if (!mountpoint)
			goto cleanup;

		user_slice = must_make_path(mountpoint, current_cgroup, NULL);
		if (cg_systemd_created_user_slice(current_cgroup, init_cgroup, user_slice, uid))
			has_user_slice = true;
		free(user_slice);

		cgv2_add_controller(NULL, mountpoint, current_cgroup, init_cgroup, has_user_slice);

		ret = true;
		goto cleanup;
	}

	f = fopen("/proc/self/mountinfo", "r");
	if (!f)
		goto cleanup;

	/* we support simple cgroup mounts and lxcfs mounts */
	while (getline(&line, &len, f) != -1) {
		char *user_slice;
		bool has_user_slice = false;
		if (!is_cgv2(line))
			continue;

		mountpoint = get_mountpoint(line);
		if (!mountpoint)
			continue;

		user_slice = must_make_path(mountpoint, current_cgroup, NULL);
		if (cg_systemd_created_user_slice(current_cgroup, init_cgroup, user_slice, uid))
			has_user_slice = true;
		free(user_slice);

		cgv2_add_controller(NULL, mountpoint, current_cgroup, init_cgroup, has_user_slice);
		/* Although the unified hierarchy can be mounted multiple times,
		 * each of those mountpoints will expose identical information.
		 * So let the first mountpoint we find, win.
		 */
		ret = true;
		break;
	}

	pam_cgfs_debug("Detected cgroupfs v2 hierarchy at mountpoint \"%s\" with "
		    "current cgroup \"%s\" and init cgroup \"%s\".\n",
		    mountpoint, current_cgroup, init_cgroup);

cleanup:
	if (f)
		fclose(f);
	free(line);

	return ret;
}

/* Detect and store information about mounted cgroupfs v1 hierarchies and the
 * cgroupfs v2 hierarchy.
 * Detect whether we are on a pure cgroupfs v1, cgroupfs v2, or mixed system,
 * where some controllers are mounted into their standard cgroupfs v1 locations
 * (/sys/fs/cgroup/<controller>) and others are mounted into the cgroupfs v2
 * hierarchy (/sys/fs/cgroup).
 */
static bool cg_init(uid_t uid, gid_t gid)
{
	if (!cgv1_init(uid, gid))
		return false;

	if (!cgv2_init(uid, gid))
		return false;

	if (cgv1_hierarchies && cgv2_hierarchies) {
		cg_mount_mode = CGROUP_MIXED;
		pam_cgfs_debug("%s\n", "Detected cgroupfs v1 and v2 hierarchies.");
	} else if (cgv1_hierarchies && !cgv2_hierarchies) {
		cg_mount_mode = CGROUP_PURE_V1;
		pam_cgfs_debug("%s\n", "Detected cgroupfs v1 hierarchies.");
	} else if (cgv2_hierarchies && !cgv1_hierarchies) {
		cg_mount_mode = CGROUP_PURE_V2;
		pam_cgfs_debug("%s\n", "Detected cgroupfs v2 hierarchies.");
	} else {
		cg_mount_mode = CGROUP_UNKNOWN;
		mysyslog(LOG_ERR, "Could not detect cgroupfs hierarchy.\n", NULL);
	}

	if (cg_mount_mode == CGROUP_UNKNOWN)
		return false;

	return true;
}

/* Try to move/migrate us into @cgroup in a cgroupfs v1 hierarchy. */
static bool cgv1_enter(const char *cgroup)
{
	struct cgv1_hierarchy **it;

	for (it = cgv1_hierarchies; it && *it; it++) {
		char **controller;
		bool entered = false;

		if (!(*it)->controllers || !(*it)->mountpoint ||
		    !(*it)->init_cgroup || !(*it)->create_rw_cgroup)
			continue;

		for (controller = (*it)->controllers; controller && *controller;
		     controller++) {
			char *path;

			/* We've already been placed in a user slice, so we
			 * don't need to enter the cgroup again.
			 */
			if ((*it)->systemd_user_slice) {
				entered = true;
				break;
			}

			path = must_make_path((*it)->mountpoint,
					      (*it)->init_cgroup,
					      cgroup,
					      "/cgroup.procs",
					      NULL);
			if (!file_exists(path)) {
				free(path);
				path = must_make_path((*it)->mountpoint,
						      (*it)->init_cgroup,
						      cgroup,
						      "/tasks",
						      NULL);
			}
			pam_cgfs_debug("Attempting to enter cgroupfs v1 hierarchy in \"%s\" cgroup.\n", path);
			entered = write_int(path, (int)getpid());
			if (entered) {
				free(path);
				break;
			}
			pam_cgfs_debug("Failed to enter cgroupfs v1 hierarchy in \"%s\" cgroup.\n", path);
			free(path);
		}
		if (!entered)
			return false;
	}

	return true;
}

/* Try to move/migrate us into @cgroup in the cgroupfs v2 hierarchy. */
static bool cgv2_enter(const char *cgroup)
{
	struct cgv2_hierarchy *v2;
	char *path;
	bool entered = false;

	if (!cgv2_hierarchies)
		return true;

	v2 = *cgv2_hierarchies;

	if (!v2->mountpoint || !v2->base_cgroup)
		return false;

	if (!v2->create_rw_cgroup || v2->systemd_user_slice)
		return true;

	path = must_make_path(v2->mountpoint, v2->base_cgroup, cgroup, "/cgroup.procs", NULL);
	pam_cgfs_debug("Attempting to enter cgroupfs v2 hierarchy in cgroup \"%s\".\n", path);
	entered = write_int(path, (int)getpid());
	if (!entered) {
		pam_cgfs_debug("Failed to enter cgroupfs v2 hierarchy in cgroup \"%s\".\n", path);
		free(path);
		return false;
	}

	free(path);

	return true;
}

/* Wrapper around cgv{1,2}_enter(). */
static bool cg_enter(const char *cgroup)
{
	if (!cgv1_enter(cgroup)) {
		mysyslog(LOG_WARNING, "cgroupfs v1: Failed to enter cgroups.\n", NULL);
		return false;
	}

	if (!cgv2_enter(cgroup)) {
		mysyslog(LOG_WARNING, "cgroupfs v2: Failed to enter cgroups.\n", NULL);
		return false;
	}

	return true;
}

/* Escape to root cgroup in all detected cgroupfs v1 hierarchies. */
static void cgv1_escape(void)
{
	struct cgv1_hierarchy **it;

	/* In case systemd hasn't already placed us in a user slice for the
	 * cpuset v1 controller we will reside in the root cgroup. This means
	 * that cgroup.clone_children will not have been initialized for us so
	 * we need to do it.
	 */
	for (it = cgv1_hierarchies; it && *it; it++)
		if (!cgv1_handle_root_cpuset_hierarchy(*it))
			mysyslog(LOG_WARNING, "cgroupfs v1: Failed to initialize cpuset.\n", NULL);

	if (!cgv1_enter("/"))
		mysyslog(LOG_WARNING, "cgroupfs v1: Failed to escape to init's cgroup.\n", NULL);
}

/* Escape to root cgroup in the cgroupfs v2 hierarchy. */
static void cgv2_escape(void)
{
	if (!cgv2_enter("/"))
		mysyslog(LOG_WARNING, "cgroupfs v2: Failed to escape to init's cgroup.\n", NULL);
}

/* Wrapper around cgv{1,2}_escape(). */
static void cg_escape(void)
{
	cgv1_escape();
	cgv2_escape();
}

/* Get uid and gid for @user. */
static bool get_uid_gid(const char *user, uid_t *uid, gid_t *gid)
{
	struct passwd *pwent;

	pwent = getpwnam(user);
	if (!pwent)
		return false;

	*uid = pwent->pw_uid;
	*gid = pwent->pw_gid;

	return true;
}

/* Check if cgroup belongs to our uid and gid. If so, reuse it. */
static bool cg_belongs_to_uid_gid(const char *path, uid_t uid, gid_t gid)
{
	struct stat statbuf;

	if (stat(path, &statbuf) < 0)
		return false;

	if (!(statbuf.st_uid == uid) || !(statbuf.st_gid == gid))
		return false;

	return true;
}

/* Create cpumask from cpulist aka turn:
 *
 *	0,2-3
 *
 *  into bit array
 *
 *	1 0 1 1
 */
static uint32_t *cg_cpumask(char *buf, size_t nbits)
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

static char *string_join(const char *sep, const char **parts, bool use_as_prefix)
{
	char *result;
	char **p;
	size_t sep_len = strlen(sep);
	size_t result_len = use_as_prefix * sep_len;

	if (!parts)
		return NULL;

	/* calculate new string length */
	for (p = (char **)parts; *p; p++)
		result_len += (p > (char **)parts) * sep_len + strlen(*p);

	result = calloc(result_len + 1, sizeof(char));
	if (!result)
		return NULL;

	if (use_as_prefix)
		strcpy(result, sep);
	for (p = (char **)parts; *p; p++) {
		if (p > (char **)parts)
			strcat(result, sep);
		strcat(result, *p);
	}

	return result;
}

/* The largest integer that can fit into long int is 2^64. This is a
 * 20-digit number.
 */
#define __IN_TO_STR_LEN 21
/* Turn cpumask into simple, comma-separated cpulist. */
static char *cg_cpumask_to_cpulist(uint32_t *bitarr, size_t nbits)
{
	size_t i;
	int ret;
	char numstr[__IN_TO_STR_LEN] = {0};
	char **cpulist = NULL;

	for (i = 0; i <= nbits; i++) {
		if (is_set(i, bitarr)) {
			ret = snprintf(numstr, __IN_TO_STR_LEN, "%zu", i);
			if (ret < 0 || (size_t)ret >= __IN_TO_STR_LEN) {
				free_string_list(cpulist);
				return NULL;
			}
			must_append_string(&cpulist, numstr);
		}
	}
	return string_join(",", (const char **)cpulist, false);
}

static ssize_t cg_get_max_cpus(char *cpulist)
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
	else if (c1 < c2)
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

static ssize_t write_nointr(int fd, const void* buf, size_t count)
{
	ssize_t ret;
again:
	ret = write(fd, buf, count);
	if (ret < 0 && errno == EINTR)
		goto again;
	return ret;
}

static int write_to_file(const char *filename, const void* buf, size_t count, bool add_newline)
{
	int fd, saved_errno;
	ssize_t ret;

	fd = open(filename, O_WRONLY | O_TRUNC | O_CREAT | O_CLOEXEC, 0666);
	if (fd < 0)
		return -1;
	ret = write_nointr(fd, buf, count);
	if (ret < 0)
		goto out_error;
	if ((size_t)ret != count)
		goto out_error;
	if (add_newline) {
		ret = write_nointr(fd, "\n", 1);
		if (ret != 1)
			goto out_error;
	}
	close(fd);
	return 0;

out_error:
	saved_errno = errno;
	close(fd);
	errno = saved_errno;
	return -1;
}

#define __ISOL_CPUS "/sys/devices/system/cpu/isolated"
static bool cg_filter_and_set_cpus(char *path, bool am_initialized)
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
		pam_cgfs_debug("Invalid path: %s.\n", path);
		return bret;
	}
	oldv = *lastslash;
	*lastslash = '\0';
	fpath = must_make_path(path, "cpuset.cpus", NULL);
	posscpus = read_file(fpath);
	if (!posscpus) {
		pam_cgfs_debug("Could not read file: %s.\n", fpath);
		goto on_error;
	}

	/* Get maximum number of cpus found in possible cpuset. */
	maxposs = cg_get_max_cpus(posscpus);
	if (maxposs < 0)
		goto on_error;

	if (!file_exists(__ISOL_CPUS)) {
		/* This system doesn't expose isolated cpus. */
		pam_cgfs_debug("%s", "Path: "__ISOL_CPUS" to read isolated cpus from does not exist.\n");
		cpulist = posscpus;
		/* No isolated cpus but we weren't already initialized by
		 * someone. We should simply copy the parents cpuset.cpus
		 * values.
		 */
		if (!am_initialized) {
			pam_cgfs_debug("%s", "Copying cpuset of parent cgroup.\n");
			goto copy_parent;
		}
		/* No isolated cpus but we were already initialized by someone.
		 * Nothing more to do for us.
		 */
		goto on_success;
	}

	isolcpus = read_file(__ISOL_CPUS);
	if (!isolcpus) {
		pam_cgfs_debug("%s", "Could not read file "__ISOL_CPUS"\n");
		goto on_error;
	}
	if (!isdigit(isolcpus[0])) {
		pam_cgfs_debug("%s", "No isolated cpus detected.\n");
		cpulist = posscpus;
		/* No isolated cpus but we weren't already initialized by
		 * someone. We should simply copy the parents cpuset.cpus
		 * values.
		 */
		if (!am_initialized) {
			pam_cgfs_debug("%s", "Copying cpuset of parent cgroup.\n");
			goto copy_parent;
		}
		/* No isolated cpus but we were already initialized by someone.
		 * Nothing more to do for us.
		 */
		goto on_success;
	}

	/* Get maximum number of cpus found in isolated cpuset. */
	maxisol = cg_get_max_cpus(isolcpus);
	if (maxisol < 0)
		goto on_error;

	if (maxposs < maxisol)
		maxposs = maxisol;
	maxposs++;

	possmask = cg_cpumask(posscpus, maxposs);
	if (!possmask) {
		pam_cgfs_debug("%s", "Could not create cpumask for all possible cpus.\n");
		goto on_error;
	}

	isolmask = cg_cpumask(isolcpus, maxposs);
	if (!isolmask) {
		pam_cgfs_debug("%s", "Could not create cpumask for all isolated cpus.\n");
		goto on_error;
	}

	for (i = 0; i <= maxposs; i++) {
		if (is_set(i, isolmask) && is_set(i, possmask)) {
			flipped_bit = true;
			clear_bit(i, possmask);
		}
	}

	if (!flipped_bit) {
		pam_cgfs_debug("%s", "No isolated cpus present in cpuset.\n");
		goto on_success;
	}
	pam_cgfs_debug("%s", "Removed isolated cpus from cpuset.\n");

	cpulist = cg_cpumask_to_cpulist(possmask, maxposs);
	if (!cpulist) {
		pam_cgfs_debug("%s", "Could not create cpu list.\n");
		goto on_error;
	}

copy_parent:
	*lastslash = oldv;
	fpath = must_make_path(path, "cpuset.cpus", NULL);
	ret = write_to_file(fpath, cpulist, strlen(cpulist), false);
	if (ret < 0) {
		pam_cgfs_debug("Could not write cpu list to: %s.\n", fpath);
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

int read_from_file(const char *filename, void* buf, size_t count)
{
	int fd = -1, saved_errno;
	ssize_t ret;

	fd = open(filename, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;

	if (!buf || !count) {
		char buf2[100];
		size_t count2 = 0;
		while ((ret = read(fd, buf2, 100)) > 0)
			count2 += ret;
		if (ret >= 0)
			ret = count2;
	} else {
		memset(buf, 0, count);
		ret = read(fd, buf, count);
	}

	if (ret < 0)
		pam_cgfs_debug("read %s: %s", filename, strerror(errno));

	saved_errno = errno;
	close(fd);
	errno = saved_errno;
	return ret;
}

/* Copy contents of parent(@path)/@file to @path/@file */
static bool cg_copy_parent_file(char *path, char *file)
{
	char *lastslash, *value = NULL, *fpath, oldv;
	int len = 0;
	int ret;

	lastslash = strrchr(path, '/');
	if (!lastslash) { // bug...  this shouldn't be possible
		pam_cgfs_debug("cgfsng:copy_parent_file: bad path %s", path);
		return false;
	}
	oldv = *lastslash;
	*lastslash = '\0';
	fpath = must_make_path(path, file, NULL);
	len = read_from_file(fpath, NULL, 0);
	if (len <= 0)
		goto bad;
	value = must_alloc(len + 1);
	if (read_from_file(fpath, value, len) != len)
		goto bad;
	free(fpath);
	*lastslash = oldv;
	fpath = must_make_path(path, file, NULL);
	ret = write_to_file(fpath, value, len, false);
	if (ret < 0)
		pam_cgfs_debug("Unable to write %s to %s", value, fpath);
	free(fpath);
	free(value);
	return ret >= 0;

bad:
	pam_cgfs_debug("Error reading '%s'", fpath);
	free(fpath);
	free(value);
	return false;
}

/* In case systemd hasn't already placed us in a user slice for the cpuset v1
 * controller we will reside in the root cgroup. This means that
 * cgroup.clone_children will not have been initialized for us so we need to do
 * it.
 */
static bool cgv1_handle_root_cpuset_hierarchy(struct cgv1_hierarchy *h)
{
	char *clonechildrenpath, v;

	if (!string_in_list(h->controllers, "cpuset"))
		return true;

	clonechildrenpath = must_make_path(h->mountpoint, "cgroup.clone_children", NULL);

	if (read_from_file(clonechildrenpath, &v, 1) < 0) {
		pam_cgfs_debug("Failed to read '%s'", clonechildrenpath);
		free(clonechildrenpath);
		return false;
	}

	if (v == '1') {  /* already set for us by someone else */
		free(clonechildrenpath);
		return true;
	}

	if (write_to_file(clonechildrenpath, "1", 1, false) < 0) {
		/* Set clone_children so children inherit our settings */
		pam_cgfs_debug("Failed to write 1 to %s", clonechildrenpath);
		free(clonechildrenpath);
		return false;
	}
	free(clonechildrenpath);
	return true;
}

/*
 * Initialize the cpuset hierarchy in first directory of @gname and
 * set cgroup.clone_children so that children inherit settings.
 * Since the h->base_path is populated by init or ourselves, we know
 * it is already initialized.
 */
static bool cgv1_handle_cpuset_hierarchy(struct cgv1_hierarchy *h,
					 const char *cgroup)
{
	char *cgpath, *clonechildrenpath, v, *slash;

	if (!string_in_list(h->controllers, "cpuset"))
		return true;

	if (*cgroup == '/')
		cgroup++;
	slash = strchr(cgroup, '/');
	if (slash)
		*slash = '\0';

	cgpath = must_make_path(h->mountpoint, h->base_cgroup, cgroup, NULL);
	if (slash)
		*slash = '/';
	if (do_mkdir(cgpath, 0755) < 0 && errno != EEXIST) {
		pam_cgfs_debug("Failed to create '%s'", cgpath);
		free(cgpath);
		return false;
	}
	clonechildrenpath = must_make_path(cgpath, "cgroup.clone_children", NULL);
	if (!file_exists(clonechildrenpath)) { /* unified hierarchy doesn't have clone_children */
		free(clonechildrenpath);
		free(cgpath);
		return true;
	}
	if (read_from_file(clonechildrenpath, &v, 1) < 0) {
		pam_cgfs_debug("Failed to read '%s'", clonechildrenpath);
		free(clonechildrenpath);
		free(cgpath);
		return false;
	}

	/* Make sure any isolated cpus are removed from cpuset.cpus. */
	if (!cg_filter_and_set_cpus(cgpath, v == '1')) {
		pam_cgfs_debug("%s", "Failed to remove isolated cpus.\n");
		free(clonechildrenpath);
		free(cgpath);
		return false;
	}

	if (v == '1') {  /* already set for us by someone else */
		pam_cgfs_debug("%s", "\"cgroup.clone_children\" was already set to \"1\".\n");
		free(clonechildrenpath);
		free(cgpath);
		return true;
	}

	/* copy parent's settings */
	if (!cg_copy_parent_file(cgpath, "cpuset.mems")) {
		pam_cgfs_debug("%s", "Failed to copy \"cpuset.mems\" settings.\n");
		free(cgpath);
		free(clonechildrenpath);
		return false;
	}
	free(cgpath);

	if (write_to_file(clonechildrenpath, "1", 1, false) < 0) {
		/* Set clone_children so children inherit our settings */
		pam_cgfs_debug("Failed to write 1 to %s", clonechildrenpath);
		free(clonechildrenpath);
		return false;
	}
	free(clonechildrenpath);
	return true;
}

/* Create and chown @cgroup for all given controllers in a cgroupfs v1 hierarchy
 * (For example, create @cgroup for the cpu and cpuacct controller mounted into
 * /sys/fs/cgroup/cpu,cpuacct). Check if the path already exists and report back
 * to the caller in @existed.
 */
#define __PAM_CGFS_USER "/user/"
#define __PAM_CGFS_USER_LEN 6
static bool cgv1_create_one(struct cgv1_hierarchy *h, const char *cgroup, uid_t uid, gid_t gid, bool *existed)
{
	char *clean_base_cgroup, *path;
	char **controller;
	struct cgv1_hierarchy *it;
	bool created = false;

	*existed = false;
	it = h;
	for (controller = it->controllers; controller && *controller;
	     controller++) {
		if (!cgv1_handle_cpuset_hierarchy(it, cgroup))
			return false;

		/* If systemd has already created a cgroup for us, keep using
		 * it.
		 */
		if (cg_systemd_chown_existing_cgroup(it->mountpoint,
						     it->base_cgroup, uid, gid,
						     it->systemd_user_slice)) {
			return true;
		}

		/* We need to make sure that we do not create an endless chain
		 * of sub-cgroups. So we check if we have already logged in
		 * somehow (sudo -i, su, etc.) and have created a
		 * /user/PAM_user/idx cgroup. If so, we skip that part. For most
		 * cgroups this is unnecessary since we use the init_cgroup
		 * anyway, but for controllers which have an existing systemd
		 * cgroup that does not match the current uid, this is pretty
		 * useful.
		 */
		if (strncmp(it->base_cgroup, __PAM_CGFS_USER, __PAM_CGFS_USER_LEN) == 0) {
			free(it->base_cgroup);
			it->base_cgroup = must_copy_string("/");
		} else {
			clean_base_cgroup =
				strstr(it->base_cgroup, __PAM_CGFS_USER);
			if (clean_base_cgroup)
				*clean_base_cgroup = '\0';
		}

		path = must_make_path(it->mountpoint, it->init_cgroup, cgroup, NULL);
		pam_cgfs_debug("Constructing path: %s.\n", path);
		if (file_exists(path)) {
			bool our_cg = cg_belongs_to_uid_gid(path, uid, gid);
			pam_cgfs_debug("%s existed and does %shave our uid: %d and gid: %d.\n", path, our_cg ? "" : "not ", uid, gid);
			free(path);
			if (our_cg)
				*existed = false;
			else
				*existed = true;
			return our_cg;
		}
		created = mkdir_parent(it->mountpoint, path);
		if (!created) {
			free(path);
			continue;
		}
		if (chown(path, uid, gid) < 0)
			mysyslog(LOG_WARNING,
				 "Failed to chown %s to %d:%d: %s.\n", path,
				 (int)uid, (int)gid, strerror(errno), NULL);
		pam_cgfs_debug("Chowned %s to %d:%d.\n", path, (int)uid, (int)gid);
		free(path);
		break;
	}

	return created;
}

/* Try to remove @cgroup for all given controllers in a cgroupfs v1 hierarchy
 * (For example, try to remove @cgroup for the cpu and cpuacct controller
 * mounted into /sys/fs/cgroup/cpu,cpuacct). Ignores failures.
 */
static bool cgv1_remove_one(struct cgv1_hierarchy *h, const char *cgroup)
{

	char *path;

	/* Better safe than sorry. */
	if (!h->controllers)
		return true;

	/* Cgroups created by systemd for us which we re-use won't be removed
	 * here, since we're using init_cgroup + cgroup as path instead of
	 * base_cgroup + cgroup.
	 */
	path = must_make_path(h->mountpoint, h->init_cgroup, cgroup, NULL);
	(void)recursive_rmdir(path);
	free(path);

	return true;
}

/* Try to remove @cgroup the cgroupfs v2 hierarchy. */
static bool cgv2_remove(const char *cgroup)
{
	struct cgv2_hierarchy *v2;
	char *path;

	if (!cgv2_hierarchies)
		return true;

	v2 = *cgv2_hierarchies;

	/* If we reused an already existing cgroup, don't bother trying to
	 * remove (a potentially wrong)/the path.
	 * Cgroups created by systemd for us which we re-use would be removed
	 * here, since we're using base_cgroup + cgroup as path.
	 */
	if (v2->systemd_user_slice)
		return true;

	path = must_make_path(v2->mountpoint, v2->base_cgroup, cgroup, NULL);
	(void)recursive_rmdir(path);
	free(path);

	return true;
}

/* Create @cgroup in all detected cgroupfs v1 hierarchy. If the creation fails
 * for any cgroupfs v1 hierarchy, remove all we have created so far. Report
 * back, to the caller if the creation failed due to @cgroup already existing
 * via @existed.
 */
static bool cgv1_create(const char *cgroup, uid_t uid, gid_t gid, bool *existed)
{
	struct cgv1_hierarchy **it, **rev_it;
	bool all_created = true;

	for (it = cgv1_hierarchies; it && *it; it++) {
		if (!(*it)->controllers || !(*it)->mountpoint ||
		    !(*it)->init_cgroup || !(*it)->create_rw_cgroup)
			continue;

		if (!cgv1_create_one(*it, cgroup, uid, gid, existed)) {
			all_created = false;
			break;
		}
	}

	if (all_created)
		return true;

	for (rev_it = cgv1_hierarchies; rev_it && *rev_it && (*rev_it != *it);
	     rev_it++)
		cgv1_remove_one(*rev_it, cgroup);

	return false;
}

/* Create @cgroup in the cgroupfs v2 hierarchy. Report back, to the caller if
 * the creation failed due to @cgroup already existing via @existed.
 */
static bool cgv2_create(const char *cgroup, uid_t uid, gid_t gid, bool *existed)
{
	int ret;
	char *clean_base_cgroup;
	char *path;
	struct cgv2_hierarchy *v2;
	bool our_cg = false, created = false;

	*existed = false;

	if (!cgv2_hierarchies || !(*cgv2_hierarchies)->create_rw_cgroup)
		return true;

	v2 = *cgv2_hierarchies;

	/* We can't be placed under init's cgroup for the v2 hierarchy. We need
	 * to be placed under our current cgroup.
	 */
	if (cg_systemd_chown_existing_cgroup(v2->mountpoint, v2->base_cgroup,
					     uid, gid, v2->systemd_user_slice))
		goto delegate_files;

	/* We need to make sure that we do not create an endless chain of
	 * sub-cgroups. So we check if we have already logged in somehow (sudo
	 * -i, su, etc.) and have created a /user/PAM_user/idx cgroup. If so, we
	 * skip that part.
	 */
	if (strncmp(v2->base_cgroup, __PAM_CGFS_USER, __PAM_CGFS_USER_LEN) == 0) {
		free(v2->base_cgroup);
		v2->base_cgroup = must_copy_string("/");
	} else {
		clean_base_cgroup = strstr(v2->base_cgroup, __PAM_CGFS_USER);
		if (clean_base_cgroup)
			*clean_base_cgroup = '\0';
	}

	path = must_make_path(v2->mountpoint, v2->base_cgroup, cgroup, NULL);
	pam_cgfs_debug("Constructing path \"%s\".\n", path);
	if (file_exists(path)) {
		our_cg = cg_belongs_to_uid_gid(path, uid, gid);
		pam_cgfs_debug(
		    "%s existed and does %shave our uid: %d and gid: %d.\n",
		    path, our_cg ? "" : "not ", uid, gid);
		free(path);
		if (our_cg) {
			*existed = false;
			goto delegate_files;
		} else {
			*existed = true;
			return false;
		}
	}

	created = mkdir_parent(v2->mountpoint, path);
	if (!created) {
		free(path);
		return false;
	}

	/* chown cgroup to user */
	if (chown(path, uid, gid) < 0)
		mysyslog(LOG_WARNING, "Failed to chown %s to %d:%d: %s.\n",
			 path, (int)uid, (int)gid, strerror(errno), NULL);
	else
		pam_cgfs_debug("Chowned %s to %d:%d.\n", path, (int)uid, (int)gid);
	free(path);

delegate_files:
	/* chown cgroup.procs to user */
	if (v2->systemd_user_slice)
		path = must_make_path(v2->mountpoint, v2->base_cgroup,
				      "/cgroup.procs", NULL);
	else
		path = must_make_path(v2->mountpoint, v2->base_cgroup, cgroup,
				      "/cgroup.procs", NULL);
	ret = chown(path, uid, gid);
	if (ret < 0)
		mysyslog(LOG_WARNING, "Failed to chown %s to %d:%d: %s.\n",
			 path, (int)uid, (int)gid, strerror(errno), NULL);
	else
		pam_cgfs_debug("Chowned %s to %d:%d.\n", path, (int)uid, (int)gid);
	free(path);

	/* chown cgroup.subtree_control to user */
	if (v2->systemd_user_slice)
		path = must_make_path(v2->mountpoint, v2->base_cgroup,
				      "/cgroup.subtree_control", NULL);
	else
		path = must_make_path(v2->mountpoint, v2->base_cgroup, cgroup,
				      "/cgroup.subtree_control", NULL);
	ret = chown(path, uid, gid);
	if (ret < 0)
		mysyslog(LOG_WARNING, "Failed to chown %s to %d:%d: %s.\n",
			 path, (int)uid, (int)gid, strerror(errno), NULL);
	free(path);

	/* chown cgroup.threads to user */
	if (v2->systemd_user_slice)
		path = must_make_path(v2->mountpoint, v2->base_cgroup,
				      "/cgroup.threads", NULL);
	else
		path = must_make_path(v2->mountpoint, v2->base_cgroup, cgroup,
				      "/cgroup.threads", NULL);
	ret = chown(path, uid, gid);
	if (ret < 0 && errno != ENOENT)
		mysyslog(LOG_WARNING, "Failed to chown %s to %d:%d: %s.\n",
			 path, (int)uid, (int)gid, strerror(errno), NULL);
	free(path);

	return true;
}

/* Create writeable cgroups for @user at login. Details can be found in the
 * preamble/license at the top of this file.
 */
static int handle_login(const char *user, uid_t uid, gid_t gid)
{
	int idx = 0, ret;
	bool existed;
	char cg[MAXPATHLEN];

	cg_escape();

	while (idx >= 0) {
		ret = snprintf(cg, MAXPATHLEN, "/user/%s/%d", user, idx);
		if (ret < 0 || ret >= MAXPATHLEN) {
			mysyslog(LOG_ERR, "Username too long.\n", NULL);
			return PAM_SESSION_ERR;
		}

		existed = false;
		if (!cgv2_create(cg, uid, gid, &existed)) {
			if (existed) {
				cgv2_remove(cg);
				idx++;
				continue;
			}
			mysyslog(LOG_ERR, "Failed to create a cgroup for user %s.\n", user, NULL);
			return PAM_SESSION_ERR;
		}

		existed = false;
		if (!cgv1_create(cg, uid, gid, &existed)) {
			if (existed) {
				cgv2_remove(cg);
				idx++;
				continue;
			}
			mysyslog(LOG_ERR, "Failed to create a cgroup for user %s.\n", user, NULL);
			return PAM_SESSION_ERR;
		}

		if (!cg_enter(cg)) {
			mysyslog( LOG_ERR, "Failed to enter user cgroup %s for user %s.\n", cg, user, NULL);
			return PAM_SESSION_ERR;
		}
		break;
	}

	return PAM_SUCCESS;
}

/* Try to prune cgroups we created and that now are empty from all cgroupfs v1
 * hierarchies.
 */
static bool cgv1_prune_empty_cgroups(const char *user)
{
	bool controller_removed = true;
	bool all_removed = true;
	struct cgv1_hierarchy **it;

	for (it = cgv1_hierarchies; it && *it; it++) {
		int ret;
		char *path_base, *path_init;
		char **controller;

		if (!(*it)->controllers || !(*it)->mountpoint ||
		    !(*it)->init_cgroup || !(*it)->create_rw_cgroup)
			continue;

		for (controller = (*it)->controllers; controller && *controller;
		     controller++) {
			bool path_base_rm, path_init_rm;

			path_base = must_make_path((*it)->mountpoint, (*it)->base_cgroup, "/user", user, NULL);
			pam_cgfs_debug("cgroupfs v1: Trying to prune \"%s\".\n", path_base);
			ret = recursive_rmdir(path_base);
			if (ret == -ENOENT || ret >= 0)
				path_base_rm = true;
			else
				path_base_rm = false;
			free(path_base);

			path_init = must_make_path((*it)->mountpoint, (*it)->init_cgroup, "/user", user, NULL);
			pam_cgfs_debug("cgroupfs v1: Trying to prune \"%s\".\n", path_init);
			ret = recursive_rmdir(path_init);
			if (ret == -ENOENT || ret >= 0)
				path_init_rm = true;
			else
				path_init_rm = false;
			free(path_init);

			if (!path_base_rm && !path_init_rm) {
				controller_removed = false;
				continue;
			}

			controller_removed = true;
			break;
		}
		if (!controller_removed)
			all_removed = false;
	}

	return all_removed;
}

/* Try to prune cgroup we created and that now is empty from the cgroupfs v2
 * hierarchy.
 */
static bool cgv2_prune_empty_cgroups(const char *user)
{
	int ret;
	struct cgv2_hierarchy *v2;
	char *path_base, *path_init;
	bool path_base_rm, path_init_rm;

	if (!cgv2_hierarchies)
		return true;

	v2 = *cgv2_hierarchies;

	path_base = must_make_path(v2->mountpoint, v2->base_cgroup, "/user", user, NULL);
	pam_cgfs_debug("cgroupfs v2: Trying to prune \"%s\".\n", path_base);
	ret = recursive_rmdir(path_base);
	if (ret == -ENOENT || ret >= 0)
		path_base_rm = true;
	else
		path_base_rm = false;
	free(path_base);

	path_init = must_make_path(v2->mountpoint, v2->init_cgroup, "/user", user, NULL);
	pam_cgfs_debug("cgroupfs v2: Trying to prune \"%s\".\n", path_init);
	ret = recursive_rmdir(path_init);
	if (ret == -ENOENT || ret >= 0)
		path_init_rm = true;
	else
		path_init_rm = false;
	free(path_init);

	if (!path_base_rm && !path_init_rm)
		return false;

	return true;
}

/* Wrapper around cgv{1,2}_prune_empty_cgroups(). */
static void cg_prune_empty_cgroups(const char *user)
{
	(void)cgv1_prune_empty_cgroups(user);
	(void)cgv2_prune_empty_cgroups(user);
}

/* Free allocated information for detected cgroupfs v1 hierarchies. */
static void cgv1_free_hierarchies(void)
{
	struct cgv1_hierarchy **it;

	if (!cgv1_hierarchies)
		return;

	for (it = cgv1_hierarchies; it && *it; it++) {
		if ((*it)->controllers) {
			char **tmp;
			for (tmp = (*it)->controllers; tmp && *tmp; tmp++)
				free(*tmp);

			free((*it)->controllers);
		}
		free((*it)->mountpoint);
		free((*it)->base_cgroup);
		free((*it)->fullcgpath);
		free((*it)->init_cgroup);
	}
	free(cgv1_hierarchies);
}

/* Free allocated information for the detected cgroupfs v2 hierarchy. */
static void cgv2_free_hierarchies(void)
{
	struct cgv2_hierarchy **it;

	if (!cgv2_hierarchies)
		return;

	for (it = cgv2_hierarchies; it && *it; it++) {
		if ((*it)->controllers) {
			char **tmp;
			for (tmp = (*it)->controllers; tmp && *tmp; tmp++)
				free(*tmp);

			free((*it)->controllers);
		}
		free((*it)->mountpoint);
		free((*it)->base_cgroup);
		free((*it)->fullcgpath);
		free((*it)->init_cgroup);
	}
	free(cgv2_hierarchies);
}

/* Wrapper around cgv{1,2}_free_hierarchies(). */
static void cg_exit(void)
{
	cgv1_free_hierarchies();
	cgv2_free_hierarchies();
}

int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
		const char **argv)
{
	int ret;
	uid_t uid = 0;
	gid_t gid = 0;
	const char *PAM_user = NULL;

	ret = pam_get_user(pamh, &PAM_user, NULL);
	if (ret != PAM_SUCCESS) {
		mysyslog(LOG_ERR, "PAM-CGFS: couldn't get user\n", NULL);
		return PAM_SESSION_ERR;
	}

	if (!get_uid_gid(PAM_user, &uid, &gid)) {
		mysyslog(LOG_ERR, "Failed to get uid and gid for %s.\n", PAM_user, NULL);
		return PAM_SESSION_ERR;
	}

	if (!cg_init(uid, gid)) {
		mysyslog(LOG_ERR, "Failed to get list of controllers\n", NULL);
		return PAM_SESSION_ERR;
	}

	/* Try to prune cgroups, that are actually empty but were still marked
	 * as busy by the kernel so we couldn't remove them on session close.
	 */
	cg_prune_empty_cgroups(PAM_user);

	if (cg_mount_mode == CGROUP_UNKNOWN)
		return PAM_SESSION_ERR;

	if (argc > 1 && !strcmp(argv[0], "-c")) {
		char **clist = make_string_list(argv[1], ",");

		/*
		 * We don't allow using "all" and other controllers explicitly because
		 * that simply doesn't make any sense.
		 */
		if (string_list_length(clist) > 1 && string_in_list(clist, "all")) {
			mysyslog(LOG_ERR, "Invalid -c option, cannot specify individual controllers alongside 'all'.\n", NULL);
			free_string_list(clist);
			return PAM_SESSION_ERR;
		}

		cg_mark_to_make_rw(clist);
		free_string_list(clist);
	}

	return handle_login(PAM_user, uid, gid);
}

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
		const char **argv)
{
	int ret;
	uid_t uid = 0;
	gid_t gid = 0;
	const char *PAM_user = NULL;

	ret = pam_get_user(pamh, &PAM_user, NULL);
	if (ret != PAM_SUCCESS) {
		mysyslog(LOG_ERR, "PAM-CGFS: couldn't get user\n", NULL);
		return PAM_SESSION_ERR;
	}

	if (!get_uid_gid(PAM_user, &uid, &gid)) {
		mysyslog(LOG_ERR, "Failed to get uid and gid for %s.\n", PAM_user, NULL);
		return PAM_SESSION_ERR;
	}

	if (cg_mount_mode == CGROUP_UNINITIALIZED) {
		if (!cg_init(uid, gid))
			mysyslog(LOG_ERR, "Failed to get list of controllers\n", NULL);

		if (argc > 1 && !strcmp(argv[0], "-c")) {
			char **clist = make_string_list(argv[1], ",");

			/*
			 * We don't allow using "all" and other controllers explicitly because
			 * that simply doesn't make any sense.
			 */
			if (string_list_length(clist) > 1 && string_in_list(clist, "all")) {
				mysyslog(LOG_ERR, "Invalid -c option, cannot specify individual controllers alongside 'all'.\n", NULL);
				free_string_list(clist);
				return PAM_SESSION_ERR;
			}

			cg_mark_to_make_rw(clist);
			free_string_list(clist);
		}
	}

	cg_prune_empty_cgroups(PAM_user);
	cg_exit();

	return PAM_SUCCESS;
}
