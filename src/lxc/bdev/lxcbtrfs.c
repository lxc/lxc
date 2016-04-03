/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Daniel Lezcano <daniel.lezcano at free.fr>
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

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "bdev.h"
#include "log.h"
#include "lxcbtrfs.h"
#include "lxcrsync.h"
#include "utils.h"

lxc_log_define(lxcbtrfs, lxc);

/* defined in lxccontainer.c: needs to become common helper */
extern char *dir_new_path(char *src, const char *oldname, const char *name,
			  const char *oldpath, const char *lxcpath);

/*
 * Return the full path of objid under dirid.  Let's say dirid is
 * /lxc/c1/rootfs, and objid is /lxc/c1/rootfs/a/b/c.  Then we will
 * return a/b/c.  If instead objid is for /lxc/c1/rootfs/a, we will
 * simply return a.
 */
char *get_btrfs_subvol_path(int fd, u64 dir_id, u64 objid, char *name,
			    int name_len)
{
	struct btrfs_ioctl_ino_lookup_args args;
	int ret, e;
	size_t len;
	char *retpath;

	memset(&args, 0, sizeof(args));
	args.treeid = dir_id;
	args.objectid = objid;

	ret = ioctl(fd, BTRFS_IOC_INO_LOOKUP, &args);
	e = errno;
	if (ret) {
		ERROR("%s: ERROR: Failed to lookup path for %llu %llu %s - %s\n",
				 __func__, (unsigned long long) dir_id,
				 (unsigned long long) objid,
				 name, strerror(e));
		return NULL;
	} else
		INFO("%s: got path for %llu %llu - %s\n", __func__,
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
		strcpy(retpath, args.name);
		strcat(retpath, "/");
		strncat(retpath, name, name_len);
	} else {
		/* we're at the root of ref_tree */
		len = name_len + 1;
		retpath = malloc(len);
		if (!retpath)
			return NULL;
		*retpath = '\0';
		strncat(retpath, name, name_len);
	}
	return retpath;
}

//
// btrfs ops
//

int btrfs_list_get_path_rootid(int fd, u64 *treeid)
{
	int  ret;
	struct btrfs_ioctl_ino_lookup_args args;

	memset(&args, 0, sizeof(args));
	args.objectid = BTRFS_FIRST_FREE_OBJECTID;

	ret = ioctl(fd, BTRFS_IOC_INO_LOOKUP, &args);
	if (ret < 0) {
		WARN("Warning: can't perform the search -%s\n",
				strerror(errno));
		return ret;
	}
	*treeid = args.treeid;
	return 0;
}

bool is_btrfs_fs(const char *path)
{
	int fd, ret;
	struct btrfs_ioctl_space_args sargs;

	// make sure this is a btrfs filesystem
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

int btrfs_detect(const char *path)
{
	struct stat st;
	int ret;

	if (!is_btrfs_fs(path))
		return 0;

	// and make sure it's a subvolume.
	ret = stat(path, &st);
	if (ret < 0)
		return 0;

	if (st.st_ino == 256 && S_ISDIR(st.st_mode))
		return 1;

	return 0;
}

int btrfs_mount(struct bdev *bdev)
{
	unsigned long mntflags;
	char *mntdata;
	int ret;

	if (strcmp(bdev->type, "btrfs"))
		return -22;
	if (!bdev->src || !bdev->dest)
		return -22;

	if (parse_mntopts(bdev->mntopts, &mntflags, &mntdata) < 0) {
		free(mntdata);
		return -22;
	}

	ret = mount(bdev->src, bdev->dest, "bind", MS_BIND | MS_REC | mntflags, mntdata);
	free(mntdata);
	return ret;
}

int btrfs_umount(struct bdev *bdev)
{
	if (strcmp(bdev->type, "btrfs"))
		return -22;
	if (!bdev->src || !bdev->dest)
		return -22;
	return umount(bdev->dest);
}

static int btrfs_subvolume_create(const char *path)
{
	int ret, fd = -1;
	struct btrfs_ioctl_vol_args  args;
	char *p, *newfull = strdup(path);

	if (!newfull) {
		ERROR("Error: out of memory");
		return -1;
	}

	p = strrchr(newfull, '/');
	if (!p) {
		ERROR("bad path: %s", path);
		free(newfull);
		return -1;
	}
	*p = '\0';

	fd = open(newfull, O_RDONLY);
	if (fd < 0) {
		ERROR("Error opening %s", newfull);
		free(newfull);
		return -1;
	}

	memset(&args, 0, sizeof(args));
	strncpy(args.name, p+1, BTRFS_SUBVOL_NAME_MAX);
	args.name[BTRFS_SUBVOL_NAME_MAX-1] = 0;
	ret = ioctl(fd, BTRFS_IOC_SUBVOL_CREATE, &args);
	INFO("btrfs: snapshot create ioctl returned %d", ret);

	free(newfull);
	close(fd);
	return ret;
}

int btrfs_same_fs(const char *orig, const char *new)
{
	int fd_orig = -1, fd_new = -1, ret = -1;
	struct btrfs_ioctl_fs_info_args orig_args, new_args;

	fd_orig = open(orig, O_RDONLY);
	if (fd_orig < 0) {
		SYSERROR("Error opening original rootfs %s", orig);
		goto out;
	}
	ret = ioctl(fd_orig, BTRFS_IOC_FS_INFO, &orig_args);
	if (ret < 0) {
		SYSERROR("BTRFS_IOC_FS_INFO %s", orig);
		goto out;
	}

	fd_new = open(new, O_RDONLY);
	if (fd_new < 0) {
		SYSERROR("Error opening new container dir %s", new);
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
	int fd = -1, fddst = -1, ret = -1;
	struct btrfs_ioctl_vol_args_v2  args;
	char *newdir, *newname, *newfull = NULL;

	newfull = strdup(new);
	if (!newfull) {
		ERROR("Error: out of memory");
		goto out;
	}
	// make sure the directory doesn't already exist
	if (rmdir(newfull) < 0 && errno != ENOENT) {
		SYSERROR("Error removing empty new rootfs");
		goto out;
	}
	newname = basename(newfull);
	newdir = dirname(newfull);
	fd = open(orig, O_RDONLY);
	if (fd < 0) {
		SYSERROR("Error opening original rootfs %s", orig);
		goto out;
	}
	fddst = open(newdir, O_RDONLY);
	if (fddst < 0) {
		SYSERROR("Error opening new container dir %s", newdir);
		goto out;
	}

	memset(&args, 0, sizeof(args));
	args.fd = fd;
	strncpy(args.name, newname, BTRFS_SUBVOL_NAME_MAX);
	args.name[BTRFS_SUBVOL_NAME_MAX-1] = 0;
	ret = ioctl(fddst, BTRFS_IOC_SNAP_CREATE_V2, &args);
	INFO("btrfs: snapshot create ioctl returned %d", ret);

out:
	if (fddst != -1)
		close(fddst);
	if (fd != -1)
		close(fd);
	free(newfull);
	return ret;
}

static int btrfs_snapshot_wrapper(void *data)
{
	struct rsync_data_char *arg = data;
	if (setgid(0) < 0) {
		ERROR("Failed to setgid to 0");
		return -1;
	}
	if (setgroups(0, NULL) < 0)
		WARN("Failed to clear groups");
	if (setuid(0) < 0) {
		ERROR("Failed to setuid to 0");
		return -1;
	}
	return btrfs_snapshot(arg->src, arg->dest);
}

int btrfs_clonepaths(struct bdev *orig, struct bdev *new, const char *oldname,
		     const char *cname, const char *oldpath,
		     const char *lxcpath, int snap, uint64_t newsize,
		     struct lxc_conf *conf)
{
	if (!orig->dest || !orig->src)
		return -1;

	if (strcmp(orig->type, "btrfs")) {
		int len, ret;
		if (snap) {
			ERROR("btrfs snapshot from %s backing store is not supported",
				orig->type);
			return -1;
		}
		len = strlen(lxcpath) + strlen(cname) + strlen("rootfs") + 3;
		new->src = malloc(len);
		if (!new->src)
			return -1;
		ret = snprintf(new->src, len, "%s/%s/rootfs", lxcpath, cname);
		if (ret < 0 || ret >= len)
			return -1;
	} else {
		// in case rootfs is in custom path, reuse it
		if ((new->src = dir_new_path(orig->src, oldname, cname, oldpath, lxcpath)) == NULL)
			return -1;

	}

	if ((new->dest = strdup(new->src)) == NULL)
		return -1;

	if (orig->mntopts && (new->mntopts = strdup(orig->mntopts)) == NULL)
		return -1;

	if (snap) {
		struct rsync_data_char sdata;
		if (!am_unpriv())
			return btrfs_snapshot(orig->dest, new->dest);
		sdata.dest = new->dest;
		sdata.src = orig->dest;
		return userns_exec_1(conf, btrfs_snapshot_wrapper, &sdata);
	}

	if (rmdir(new->dest) < 0 && errno != ENOENT) {
		SYSERROR("removing %s", new->dest);
		return -1;
	}

	return btrfs_subvolume_create(new->dest);
}

static int btrfs_do_destroy_subvol(const char *path)
{
	int ret, fd = -1;
	struct btrfs_ioctl_vol_args  args;
	char *p, *newfull = strdup(path);

	if (!newfull) {
		ERROR("Error: out of memory");
		return -1;
	}

	p = strrchr(newfull, '/');
	if (!p) {
		ERROR("bad path: %s", path);
		free(newfull);
		return -1;
	}
	*p = '\0';

	fd = open(newfull, O_RDONLY);
	if (fd < 0) {
		SYSERROR("Error opening %s", newfull);
		free(newfull);
		return -1;
	}

	memset(&args, 0, sizeof(args));
	strncpy(args.name, p+1, BTRFS_SUBVOL_NAME_MAX);
	args.name[BTRFS_SUBVOL_NAME_MAX-1] = 0;
	ret = ioctl(fd, BTRFS_IOC_SNAP_DESTROY, &args);
	INFO("btrfs: snapshot destroy ioctl returned %d for %s", ret, path);
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
	for (i = 0; i < tree->num; i++) {
		if (tree->nodes[i].objid == id)
			return i;
	}
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
			     char *name, int name_len, char *dirname)
{
	if (id)
		n->objid = id;
	if (parent)
		n->parentid = parent;
	if (name) {
		n->name = malloc(name_len + 1);
		if (!n->name)
			return false;
		strncpy(n->name, name, name_len);
		n->name[name_len] = '\0';
	}
	if (dirname) {
		n->dirname = malloc(strlen(dirname) + 1);
		if (!n->dirname) {
			free(n->name);
			return false;
		}
		strcpy(n->dirname, dirname);
	}
	return true;
}

static bool add_btrfs_tree_node(struct my_btrfs_tree *tree, u64 id, u64 parent,
				char *name, int name_len, char *dirname)
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
	int i;
	char *newpath;
	size_t len;

	for (i = 0; i < tree->num; i++) {
		if (tree->nodes[i].parentid == root_id) {
			if (!tree->nodes[i].dirname) {
				WARN("Odd condition: child objid with no name under %s\n", path);
				continue;
			}
			len = strlen(path) + strlen(tree->nodes[i].dirname) + 2;
			newpath = malloc(len);
			if (!newpath) {
				ERROR("Out of memory");
				return false;
			}
			snprintf(newpath, len, "%s/%s", path, tree->nodes[i].dirname);
			if (!do_remove_btrfs_children(tree, tree->nodes[i].objid, newpath)) {
				ERROR("Failed to prune %s\n", tree->nodes[i].name);
				free(newpath);
				return false;
			}
			if (btrfs_do_destroy_subvol(newpath) != 0) {
				ERROR("Failed to remove %s\n", newpath);
				free(newpath);
				return false;
			}
			free(newpath);
		}
	}
	return true;
}

static int btrfs_recursive_destroy(const char *path)
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
	int name_len;
	char *name;
	char *tmppath;
	u64 dir_id;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		ERROR("Failed to open %s\n", path);
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
		ERROR("Out of memory\n");
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

	while(1) {
		ret = ioctl(fd, BTRFS_IOC_TREE_SEARCH, &args);
		e = errno;
		if (ret < 0) {
			close(fd);
			free_btrfs_tree(tree);
			if (e == EPERM || e == EACCES) {
				WARN("Warn: can't perform the search under %s. Will simply try removing", path);
				goto ignore_search;
			}

			ERROR("Error: can't perform the search under %s\n", path);
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
			 * comes followed by the reoot ref key which has the
			 * name of the child subvol in question.
			 */
			if (sh.objectid != root_id && sh.type == BTRFS_ROOT_BACKREF_KEY) {
				ref = (struct btrfs_root_ref *)(args.buf + off);
				name_len = btrfs_stack_root_ref_name_len(ref);
				name = (char *)(ref + 1);
				dir_id = btrfs_stack_root_ref_dirid(ref);
				tmppath = get_btrfs_subvol_path(fd, sh.offset,
						dir_id, name, name_len);
				if (!add_btrfs_tree_node(tree, sh.objectid,
							sh.offset, name,
							name_len, tmppath)) {
					ERROR("Out of memory");
					free_btrfs_tree(tree);
					free(tmppath);
					close(fd);
					return -1;
				}
				free(tmppath);
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
		} else
			continue;

		if (sk->min_objectid >= sk->max_objectid)
			break;
	}
	close(fd);

	/* now actually remove them */

	if (!do_remove_btrfs_children(tree, root_id, path)) {
		free_btrfs_tree(tree);
		ERROR("failed pruning\n");
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
	return btrfs_recursive_destroy(path) == 0;
}

int btrfs_destroy(struct bdev *orig)
{
	return btrfs_recursive_destroy(orig->src);
}

int btrfs_create(struct bdev *bdev, const char *dest, const char *n,
		 struct bdev_specs *specs)
{
	bdev->src = strdup(dest);
	bdev->dest = strdup(dest);
	if (!bdev->src || !bdev->dest)
		return -1;
	return btrfs_subvolume_create(bdev->dest);
}

