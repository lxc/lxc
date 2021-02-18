/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <unistd.h>

#include "btrfs.h"
#include "config.h"
#include "log.h"
#include "memory_utils.h"
#include "rsync.h"
#include "storage.h"
#include "utils.h"

#ifndef HAVE_STRLCPY
#include "include/strlcpy.h"
#endif

#ifndef HAVE_STRLCAT
#include "include/strlcat.h"
#endif

lxc_log_define(btrfs, lxc);

/*
 * Return the full path of objid under dirid.  Let's say dirid is
 * /lxc/c1/rootfs, and objid is /lxc/c1/rootfs/a/b/c.  Then we will
 * return a/b/c.  If instead objid is for /lxc/c1/rootfs/a, we will
 * simply return a.
 */
char *get_btrfs_subvol_path(int fd, u64 dir_id, u64 objid, char *name,
			    u16 name_len)
{
	struct btrfs_ioctl_ino_lookup_args args;
	int ret;
	size_t len, retlen;
	char *retpath;

	memset(&args, 0, sizeof(args));
	args.treeid = dir_id;
	args.objectid = objid;

	ret = ioctl(fd, BTRFS_IOC_INO_LOOKUP, &args);
	if (ret) {
		SYSERROR("Failed to lookup path for %llu %llu %s",
		         (unsigned long long) dir_id,
		         (unsigned long long) objid,
		         name);
		return NULL;
	} else
		INFO("Got path for %llu %llu - %s",
		     (unsigned long long) objid, (unsigned long long) dir_id,
		     name);

	if (args.name[0]) {
		/*
		 * we're in a subdirectory of ref_tree, the kernel ioctl
		 * puts a / in there for us
		 */
		len = strlen(args.name) + name_len + 2;
		retpath = malloc(len);
		if (!retpath)
			return NULL;

		(void)strlcpy(retpath, args.name, len);
		(void)strlcat(retpath, "/", len);

		retlen = strlcat(retpath, name, len);
		if (retlen >= len) {
			ERROR("Failed to append name - %s", name);
			free(retpath);
			return NULL;
		}
	} else {
		/* we're at the root of ref_tree */
		len = name_len + 1;
		retpath = malloc(len);
		if (!retpath)
			return NULL;

		*retpath = '\0';

		retlen = strlcat(retpath, name, len);
		if (retlen >= len) {
			ERROR("Failed to append name - %s", name);
			free(retpath);
			return NULL;
		}
	}

	return retpath;
}

int btrfs_list_get_path_rootid(int fd, u64 *treeid)
{
	int  ret;
	struct btrfs_ioctl_ino_lookup_args args;

	memset(&args, 0, sizeof(args));
	args.objectid = BTRFS_FIRST_FREE_OBJECTID;

	ret = ioctl(fd, BTRFS_IOC_INO_LOOKUP, &args);
	if (ret < 0) {
		SYSWARN("Can't perform the search");
		return ret;
	}

	*treeid = args.treeid;
	return 0;
}

bool is_btrfs_fs(const char *path)
{
	int fd, ret;
	struct btrfs_ioctl_space_args sargs;

	/* Make sure this is a btrfs filesystem. */
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return false;

	sargs.space_slots = 0;
	sargs.total_spaces = 0;
	ret = ioctl(fd, BTRFS_IOC_SPACE_INFO, &sargs);
	close(fd);
	if (ret < 0)
		return false;

	return true;
}

/*
 * Taken from btrfs toolsuite. Test if path is a subvolume.
 *	return 0;   path exists but it is not a subvolume
 *	return 1;   path exists and it is  a subvolume
 *	return < 0; error
 */
int is_btrfs_subvol(const char *path)
{
	struct stat st;
	struct statfs stfs;
	int ret;

	ret = stat(path, &st);
	if (ret < 0)
		return -errno;

	if (st.st_ino != BTRFS_FIRST_FREE_OBJECTID || !S_ISDIR(st.st_mode))
		return 0;

	ret = statfs(path, &stfs);
	if (ret < 0)
		return -errno;

	return stfs.f_type == BTRFS_SUPER_MAGIC;
}

bool btrfs_detect(const char *path)
{
	struct stat st;
	int ret;

	if (!strncmp(path, "btrfs:", 6))
		return true;

	if (!is_btrfs_fs(path))
		return false;

	/* make sure it's a subvolume */
	ret = stat(path, &st);
	if (ret < 0)
		return false;

	if (st.st_ino == 256 && S_ISDIR(st.st_mode))
		return true;

	return false;
}

int btrfs_mount(struct lxc_storage *bdev)
{
	unsigned long mntflags = 0;
	char *mntdata = NULL;
	const char *src;
	int ret;

	if (strcmp(bdev->type, "btrfs"))
		return -22;

	if (!bdev->src || !bdev->dest)
		return -22;

	if (parse_mntopts(bdev->mntopts, &mntflags, &mntdata) < 0) {
		free(mntdata);
		return -22;
	}

	src = lxc_storage_get_path(bdev->src, "btrfs");

	ret = mount(src, bdev->dest, "bind", MS_BIND | MS_REC | mntflags, mntdata);
	free(mntdata);
	return ret;
}

int btrfs_umount(struct lxc_storage *bdev)
{
	if (strcmp(bdev->type, "btrfs"))
		return -22;

	if (!bdev->src || !bdev->dest)
		return -22;

	return umount(bdev->dest);
}

static int btrfs_subvolume_create(const char *path)
{
	int ret, saved_errno;
	size_t retlen;
	struct btrfs_ioctl_vol_args args;
	char *p, *newfull;
	int fd = -1;

	newfull = strdup(path);
	if (!newfull) {
		errno = ENOMEM;
		return -ENOMEM;
	}

	p = strrchr(newfull, '/');
	if (!p) {
		free(newfull);
		errno = EINVAL;
		return -EINVAL;
	}
	*p = '\0';

	fd = open(newfull, O_RDONLY);
	if (fd < 0) {
		free(newfull);
		return -errno;
	}

	memset(&args, 0, sizeof(args));
	retlen = strlcpy(args.name, p + 1, BTRFS_SUBVOL_NAME_MAX);
	if (retlen >= BTRFS_SUBVOL_NAME_MAX) {
		free(newfull);
		close(fd);
		return -E2BIG;
	}

	ret = ioctl(fd, BTRFS_IOC_SUBVOL_CREATE, &args);
	saved_errno = errno;

	close(fd);
	free(newfull);
	errno = saved_errno;
	return ret;
}

int btrfs_same_fs(const char *orig, const char *new)
{
	int fd_orig = -1, fd_new = -1, ret = -1;
	struct btrfs_ioctl_fs_info_args orig_args, new_args;

	fd_orig = open(orig, O_RDONLY);
	if (fd_orig < 0) {
		SYSERROR("Failed to open original rootfs %s", orig);
		goto out;
	}

	ret = ioctl(fd_orig, BTRFS_IOC_FS_INFO, &orig_args);
	if (ret < 0) {
		SYSERROR("BTRFS_IOC_FS_INFO %s", orig);
		goto out;
	}

	fd_new = open(new, O_RDONLY);
	if (fd_new < 0) {
		SYSERROR("Failed to open new container dir %s", new);
		ret = -1;
		goto out;
	}

	ret = ioctl(fd_new, BTRFS_IOC_FS_INFO, &new_args);
	if (ret < 0) {
		SYSERROR("BTRFS_IOC_FS_INFO %s", new);
		goto out;
	}

	if (strncmp(orig_args.fsid, new_args.fsid, BTRFS_FSID_SIZE) != 0) {
		ret = -1;
		goto out;
	}

	ret = 0;

out:
	if (fd_new != -1)
		close(fd_new);

	if (fd_orig != -1)
		close(fd_orig);

	return ret;
}

int btrfs_snapshot(const char *orig, const char *new)
{
	size_t retlen;
	struct btrfs_ioctl_vol_args_v2 args;
	char *newdir, *newname;
	char *newfull = NULL;
	int saved_errno = -1;
	int fd = -1, fddst = -1, ret = -1;

	newfull = strdup(new);
	if (!newfull)
		goto out;

	ret = rmdir(newfull);
	if (ret < 0 && errno != ENOENT)
		goto out;

	newname = basename(newfull);
	fd = open(orig, O_RDONLY);
	if (fd < 0)
		goto out;

	newdir = dirname(newfull);
	fddst = open(newdir, O_RDONLY);
	if (fddst < 0)
		goto out;

	memset(&args, 0, sizeof(args));
	args.fd = fd;
	retlen = strlcpy(args.name, newname, BTRFS_SUBVOL_NAME_MAX);
	if (retlen >= BTRFS_SUBVOL_NAME_MAX)
		goto out;

	ret = ioctl(fddst, BTRFS_IOC_SNAP_CREATE_V2, &args);
	saved_errno = errno;

out:
	if (fddst != -1)
		close(fddst);

	if (fd != -1)
		close(fd);

	free(newfull);

	if (saved_errno >= 0)
		errno = saved_errno;

	return ret;
}

int btrfs_snapshot_wrapper(void *data)
{
	const char *src;
	struct rsync_data_char *arg = data;

	(void)lxc_setgroups(0, NULL);

	if (setgid(0) < 0) {
		ERROR("Failed to setgid to 0");
		return -1;
	}

	if (setuid(0) < 0) {
		ERROR("Failed to setuid to 0");
		return -1;
	}

	src = lxc_storage_get_path(arg->src, "btrfs");
	return btrfs_snapshot(src, arg->dest);
}

int btrfs_clonepaths(struct lxc_storage *orig, struct lxc_storage *new,
		     const char *oldname, const char *cname,
		     const char *oldpath, const char *lxcpath, int snap,
		     uint64_t newsize, struct lxc_conf *conf)
{
	const char *src;

	if (!orig->dest || !orig->src)
		return -1;

	if (strcmp(orig->type, "btrfs") && snap) {
		ERROR("btrfs snapshot from %s backing store is not supported",
		      orig->type);
		return -1;
	}

	new->src = lxc_string_join(
	    "/",
	    (const char *[]){"btrfs:", *lxcpath != '/' ? lxcpath : ++lxcpath,
			     cname, "rootfs", NULL},
	    false);
	if (!new->src) {
		ERROR("Failed to create new rootfs path");
		return -1;
	}
	TRACE("Constructed new rootfs path \"%s\"", new->src);

	src = lxc_storage_get_path(new->src, "btrfs");
	new->dest = strdup(src);
	if (!new->dest) {
		ERROR("Failed to duplicate string \"%s\"", src);
		return -1;
	}

	if (orig->mntopts) {
		new->mntopts = strdup(orig->mntopts);
		if (!new->mntopts) {
			ERROR("Failed to duplicate string \"%s\"",
			      orig->mntopts);
			return -1;
		}
	}

	return 0;
}

bool btrfs_create_clone(struct lxc_conf *conf, struct lxc_storage *orig,
			struct lxc_storage *new, uint64_t newsize)
{
	int ret;
	struct rsync_data data = {0, 0};
	char cmd_output[PATH_MAX] = {0};

	ret = rmdir(new->dest);
	if (ret < 0 && errno != ENOENT)
		return false;

	ret = btrfs_subvolume_create(new->dest);
	if (ret < 0) {
		SYSERROR("Failed to create btrfs subvolume \"%s\"", new->dest);
		return false;
	}

	/* rsync the contents from source to target */
	data.orig = orig;
	data.new = new;

	if (am_guest_unpriv()) {
		ret = userns_exec_full(conf, lxc_storage_rsync_exec_wrapper,
				       &data, "lxc_storage_rsync_exec_wrapper");
		if (ret < 0) {
			ERROR("Failed to rsync from \"%s\" into \"%s\"",
			      orig->dest, new->dest);
			return false;
		}

		return true;
	}

	ret = run_command(cmd_output, sizeof(cmd_output),
			lxc_storage_rsync_exec_wrapper, (void *)&data);
	if (ret < 0) {
		ERROR("Failed to rsync from \"%s\" into \"%s\": %s", orig->dest,
		      new->dest, cmd_output);
		return false;
	}

	return true;
}

bool btrfs_create_snapshot(struct lxc_conf *conf, struct lxc_storage *orig,
			   struct lxc_storage *new, uint64_t newsize)
{
	int ret;

	ret = rmdir(new->dest);
	if (ret < 0 && errno != ENOENT)
		return false;

	if (am_guest_unpriv()) {
		struct rsync_data_char args;

		args.src = orig->src;
		args.dest = new->dest;

		ret = userns_exec_1(conf, btrfs_snapshot_wrapper, &args,
				    "btrfs_snapshot_wrapper");
		if (ret < 0) {
			ERROR("Failed to run \"btrfs_snapshot_wrapper\"");
			return false;
		}

		TRACE("Created btrfs snapshot \"%s\" from \"%s\"", new->dest,
		      orig->dest);
		return true;
	}

	ret = btrfs_snapshot(orig->src, new->dest);
	if (ret < 0) {
		SYSERROR("Failed to create btrfs snapshot \"%s\" from \"%s\"",
		         new->dest, orig->dest);
		return false;
	}

	TRACE("Created btrfs snapshot \"%s\" from \"%s\"", new->dest, orig->dest);
	return true;
}

static int btrfs_do_destroy_subvol(const char *path)
{
	int ret, fd = -1;
	size_t retlen;
	struct btrfs_ioctl_vol_args  args;
	char *p, *newfull = strdup(path);

	if (!newfull) {
		ERROR("Out of memory");
		return -1;
	}

	p = strrchr(newfull, '/');
	if (!p) {
		ERROR("Invalid path: %s", path);
		free(newfull);
		return -1;
	}
	*p = '\0';

	fd = open(newfull, O_RDONLY);
	if (fd < 0) {
		SYSERROR("Failed to open %s", newfull);
		free(newfull);
		return -1;
	}

	memset(&args, 0, sizeof(args));
	retlen = strlcpy(args.name, p+1, BTRFS_SUBVOL_NAME_MAX);
	if (retlen >= BTRFS_SUBVOL_NAME_MAX) {
		free(newfull);
		close(fd);
		return -E2BIG;
	}

	ret = ioctl(fd, BTRFS_IOC_SNAP_DESTROY, &args);
	INFO("IOCTL for destroying snapshot returned %d for %s", ret, path);
	if (ret < 0 && errno == EPERM)
		ERROR("Is the rootfs mounted with -o user_subvol_rm_allowed?");

	free(newfull);
	close(fd);
	return ret;
}

static int get_btrfs_tree_idx(struct my_btrfs_tree *tree, u64 id)
{
	int i;

	if (!tree)
		return -1;

	for (i = 0; i < tree->num; i++)
		if (tree->nodes[i].objid == id)
			return i;

	return -1;
}

static struct my_btrfs_tree *create_my_btrfs_tree(u64 id, const char *path,
						  int name_len)
{
	struct my_btrfs_tree *tree;

	tree = malloc(sizeof(struct my_btrfs_tree));
	if (!tree)
		return NULL;

	tree->nodes = malloc(sizeof(struct mytree_node));
	if (!tree->nodes) {
		free(tree);
		return NULL;
	}

	tree->num = 1;
	tree->nodes[0].dirname = NULL;
	tree->nodes[0].name = strdup(path);
	if (!tree->nodes[0].name) {
		free(tree->nodes);
		free(tree);
		return NULL;
	}

	tree->nodes[0].parentid = 0;
	tree->nodes[0].objid = id;
	return tree;
}

static bool update_tree_node(struct mytree_node *n, u64 id, u64 parent,
			     char *name, u16 name_len, char *dirname)
{
	if (id)
		n->objid = id;

	if (parent)
		n->parentid = parent;

	if (name) {
		n->name = malloc(name_len + 1);
		if (!n->name)
			return false;

		(void)strlcpy(n->name, name, name_len + 1);
	}

	if (dirname) {
		size_t len;

		len = strlen(dirname);
		n->dirname = malloc(len + 1);
		if (!n->dirname) {
			free(n->name);
			return false;
		}

		(void)strlcpy(n->dirname, dirname, len + 1);
	}

	return true;
}

static bool add_btrfs_tree_node(struct my_btrfs_tree *tree, u64 id, u64 parent,
				char *name, u16 name_len, char *dirname)
{
	struct mytree_node *tmp;

	int i = get_btrfs_tree_idx(tree, id);
	if (i != -1)
		return update_tree_node(&tree->nodes[i], id, parent, name,
				name_len, dirname);

	tmp = realloc(tree->nodes, (tree->num+1) * sizeof(struct mytree_node));
	if (!tmp)
		return false;

	tree->nodes = tmp;
	memset(&tree->nodes[tree->num], 0, sizeof(struct mytree_node));

	if (!update_tree_node(&tree->nodes[tree->num], id, parent, name,
				name_len, dirname))
		return false;

	tree->num++;
	return true;
}

static void free_btrfs_tree(struct my_btrfs_tree *tree)
{
	int i;

	if (!tree)
		return;

	for (i = 0; i < tree->num;  i++) {
		free(tree->nodes[i].name);
		free(tree->nodes[i].dirname);
	}

	free(tree->nodes);
	free(tree);
}

/*
 * Given a @tree of subvolumes under @path, ask btrfs to remove each
 * subvolume
 */
static bool do_remove_btrfs_children(struct my_btrfs_tree *tree, u64 root_id,
				     const char *path)
{
	int i, ret;
	char *newpath;
	size_t len;

	for (i = 0; i < tree->num; i++) {
		if (tree->nodes[i].parentid == root_id) {
			if (!tree->nodes[i].dirname) {
				WARN("Odd condition: child objid with no name under %s", path);
				continue;
			}

			len = strlen(path) + strlen(tree->nodes[i].dirname) + 2;
			newpath = malloc(len);
			if (!newpath) {
				ERROR("Out of memory");
				return false;
			}

			ret = snprintf(newpath, len, "%s/%s", path, tree->nodes[i].dirname);
			if (ret < 0 || ret >= len) {
				free(newpath);
				return false;
			}

			if (!do_remove_btrfs_children(tree, tree->nodes[i].objid, newpath)) {
				ERROR("Failed to prune %s", tree->nodes[i].name);
				free(newpath);
				return false;
			}

			if (btrfs_do_destroy_subvol(newpath) != 0) {
				ERROR("Failed to remove %s", newpath);
				free(newpath);
				return false;
			}

			free(newpath);
		}
	}

	return true;
}

static int btrfs_lxc_rm_rf(const char *path)
{
	u64 root_id;
	int fd;
	struct btrfs_ioctl_search_args args;
	struct btrfs_ioctl_search_key *sk = &args.key;
	struct btrfs_ioctl_search_header sh;
	struct btrfs_root_ref *ref;
	struct my_btrfs_tree *tree;
	int ret, e, i;
	unsigned long off = 0;
	u16 name_len;
	u64 dir_id;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		ERROR("Failed to open %s", path);
		return -1;
	}

	if (btrfs_list_get_path_rootid(fd, &root_id)) {
		e = errno;
		close(fd);
		if (e == EPERM || e == EACCES) {
			WARN("Will simply try removing");
			goto ignore_search;
		}

		return -1;
	}

	tree = create_my_btrfs_tree(root_id, path, strlen(path));
	if (!tree) {
		ERROR("Out of memory");
		close(fd);
		return -1;
	}

	/* Walk all subvols looking for any under this id */
	memset(&args, 0, sizeof(args));

	/* search in the tree of tree roots */
	sk->tree_id = 1;
	sk->max_type = BTRFS_ROOT_REF_KEY;
	sk->min_type = BTRFS_ROOT_ITEM_KEY;
	sk->min_objectid = 0;
	sk->max_objectid = (u64)-1;
	sk->max_offset = (u64)-1;
	sk->min_offset = 0;
	sk->max_transid = (u64)-1;
	sk->nr_items = 4096;

	for (;;) {
		ret = ioctl(fd, BTRFS_IOC_TREE_SEARCH, &args);
		e = errno;
		if (ret < 0) {
			close(fd);
			free_btrfs_tree(tree);
			if (e == EPERM || e == EACCES) {
				WARN("Can't perform the search under %s. "
				     "Will simply try removing", path);
				goto ignore_search;
			}

			ERROR("Can't perform the search under %s", path);
			return -1;
		}

		if (sk->nr_items == 0)
			break;

		off = 0;
		for (i = 0; i < sk->nr_items; i++) {
			memcpy(&sh, args.buf + off, sizeof(sh));
			off += sizeof(sh);

			/*
			 * A backref key with the name and dirid of the parent
			 * comes followed by the root ref key which has the
			 * name of the child subvol in question.
			 */
			if (sh.objectid != root_id && sh.type == BTRFS_ROOT_BACKREF_KEY) {
				__do_free char *name = NULL, *tmppath = NULL;
				char *tmp;

				ref = (struct btrfs_root_ref *)(args.buf + off);
				name_len = btrfs_stack_root_ref_name_len(ref);
				tmp = (char *)(ref + 1);

				name = malloc(name_len + 1);
				if (!name) {
					ERROR("Out of memory");
					free_btrfs_tree(tree);
					close(fd);
					return -ENOMEM;
				}

				memcpy(name, tmp, name_len);
				name[name_len] = '\0';
				dir_id = btrfs_stack_root_ref_dirid(ref);
				tmppath = get_btrfs_subvol_path(fd, sh.offset,
						dir_id, name, name_len);

				if (!add_btrfs_tree_node(tree, sh.objectid,
							sh.offset, name,
							name_len, tmppath)) {
					ERROR("Out of memory");
					free_btrfs_tree(tree);
					close(fd);
					return -1;
				}
			}

			off += sh.len;

			/*
			 * record the mins in sk so we can make sure the
			 * next search doesn't repeat this root
			 */
			sk->min_objectid = sh.objectid;
			sk->min_type = sh.type;
			sk->min_offset = sh.offset;
		}

		sk->nr_items = 4096;
		sk->min_offset++;

		if (!sk->min_offset)
			sk->min_type++;
		else
			continue;

		if (sk->min_type > BTRFS_ROOT_BACKREF_KEY) {
			sk->min_type = BTRFS_ROOT_ITEM_KEY;
			sk->min_objectid++;
		} else {
			continue;
		}

		if (sk->min_objectid >= sk->max_objectid)
			break;
	}

	close(fd);

	/* now actually remove them */
	if (!do_remove_btrfs_children(tree, root_id, path)) {
		free_btrfs_tree(tree);
		ERROR("Failed to prune");
		return -1;
	}

	free_btrfs_tree(tree);

	/* All child subvols have been removed, now remove this one */
ignore_search:
	return btrfs_do_destroy_subvol(path);
}

bool btrfs_try_remove_subvol(const char *path)
{
	if (!btrfs_detect(path))
		return false;

	return btrfs_lxc_rm_rf(path) == 0;
}

int btrfs_destroy(struct lxc_storage *orig)
{
	const char *src;

	src = lxc_storage_get_path(orig->src, "btrfs");

	return btrfs_lxc_rm_rf(src);
}

int btrfs_create(struct lxc_storage *bdev, const char *dest, const char *n,
		 struct bdev_specs *specs, const struct lxc_conf *conf)
{
	int ret;
	size_t len;


	len = strlen(dest) + 1;
	/* strlen("btrfs:") */
	len += 6;

	bdev->src = malloc(len);
	if (!bdev->src) {
		ERROR("Failed to allocate memory");
		return -1;
	}

	ret = snprintf(bdev->src, len, "btrfs:%s", dest);
	if (ret < 0 || (size_t)ret >= len) {
		ERROR("Failed to create string");
		return -1;
	}

	bdev->dest = strdup(dest);
	if (!bdev->dest) {
		ERROR("Failed to duplicate string \"%s\"", dest);
		return -1;
	}

	ret = btrfs_subvolume_create(bdev->dest);
	if (ret < 0)
		SYSERROR("Failed to create btrfs subvolume \"%s\"", bdev->dest);

	return ret;
}
