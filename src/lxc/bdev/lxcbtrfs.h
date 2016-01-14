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

#ifndef __LXC_BTRFS_H
#define __LXC_BTRFS_H

#define _GNU_SOURCE
#include <linux/types.h> /* __le64, __l32 ... */
#include <stdbool.h>
#include <stdint.h>
#include <byteswap.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

struct btrfs_ioctl_space_info {
	unsigned long long flags;
	unsigned long long total_bytes;
	unsigned long long used_bytes;
};

struct btrfs_ioctl_space_args {
	unsigned long long space_slots;
	unsigned long long total_spaces;
	struct btrfs_ioctl_space_info spaces[];
};

#define BTRFS_IOCTL_MAGIC 0x94
#define BTRFS_IOC_SUBVOL_GETFLAGS _IOR(BTRFS_IOCTL_MAGIC, 25, unsigned long long)
#define BTRFS_IOC_SPACE_INFO _IOWR(BTRFS_IOCTL_MAGIC, 20, \
                                    struct btrfs_ioctl_space_args)

#define BTRFS_FSID_SIZE 16
struct btrfs_ioctl_fs_info_args {
	unsigned long long max_id;
	unsigned long long num_devices;
	char fsid[BTRFS_FSID_SIZE];
	unsigned long long reserved[124];
};

#define BTRFS_IOC_FS_INFO _IOR(BTRFS_IOCTL_MAGIC, 31, \
		struct btrfs_ioctl_fs_info_args)


#define BTRFS_SUBVOL_NAME_MAX 4039
#define BTRFS_PATH_NAME_MAX 4087

struct btrfs_ioctl_vol_args {
	signed long long fd;
	char name[BTRFS_PATH_NAME_MAX + 1];
};

#define BTRFS_IOCTL_MAGIC 0x94
#define BTRFS_IOC_SUBVOL_CREATE_V2 _IOW(BTRFS_IOCTL_MAGIC, 24, \
                                   struct btrfs_ioctl_vol_args_v2)
#define BTRFS_IOC_SNAP_CREATE_V2 _IOW(BTRFS_IOCTL_MAGIC, 23, \
                                   struct btrfs_ioctl_vol_args_v2)
#define BTRFS_IOC_SUBVOL_CREATE _IOW(BTRFS_IOCTL_MAGIC, 14, \
                                   struct btrfs_ioctl_vol_args)
#define BTRFS_IOC_SNAP_DESTROY _IOW(BTRFS_IOCTL_MAGIC, 15, \
                                   struct btrfs_ioctl_vol_args)

#define BTRFS_QGROUP_INHERIT_SET_LIMITS (1ULL << 0)

struct btrfs_ioctl_vol_args_v2 {
	signed long long fd;
	unsigned long long transid;
	unsigned long long flags;
	union {
		struct {
			unsigned long long size;
			//struct btrfs_qgroup_inherit *qgroup_inherit;
			void *qgroup_inherit;
		};
		unsigned long long unused[4];
	};
	char name[BTRFS_SUBVOL_NAME_MAX + 1];
};

/*
 * root backrefs tie subvols and snapshots to the directory entries that
 * reference them
 */
#define BTRFS_ROOT_BACKREF_KEY  144

/*
 * root items point to tree roots.  There are typically in the root
 * tree used by the super block to find all the other trees
 */
#define BTRFS_ROOT_ITEM_KEY     132

/*
 * root refs make a fast index for listing all of the snapshots and
 * subvolumes referenced by a given root.  They point directly to the
 * directory item in the root that references the subvol
 */
#define BTRFS_ROOT_REF_KEY      156

#define BTRFS_ROOT_TREE_DIR_OBJECTID 6ULL
#define BTRFS_DIR_ITEM_KEY      84

/*
 *  * this is used for both forward and backward root refs
 *   */
struct btrfs_root_ref {
	__le64 dirid;
	__le64 sequence;
	__le16 name_len;
} __attribute__ ((__packed__));

struct btrfs_disk_key {
	__le64 objectid;
	u8 type;
	__le64 offset;
} __attribute__ ((__packed__));

struct btrfs_dir_item {
	struct btrfs_disk_key location;
	__le64 transid;
	__le16 data_len;
	__le16 name_len;
	u8 type;
} __attribute__ ((__packed__));

#define BTRFS_IOCTL_MAGIC 0x94
#define BTRFS_VOL_NAME_MAX 255
#define BTRFS_PATH_NAME_MAX 4087

struct btrfs_ioctl_search_key {
	/* which root are we searching.  0 is the tree of tree roots */
	__u64 tree_id;

	/* keys returned will be >= min and <= max */
	__u64 min_objectid;
	__u64 max_objectid;

	/* keys returned will be >= min and <= max */
	__u64 min_offset;
	__u64 max_offset;

	/* max and min transids to search for */
	__u64 min_transid;
	__u64 max_transid;

	/* keys returned will be >= min and <= max */
	__u32 min_type;
	__u32 max_type;

	/*
	 * how many items did userland ask for, and how many are we
	 * returning
	 */
	__u32 nr_items;

	/* align to 64 bits */
	__u32 unused;

	/* some extra for later */
	__u64 unused1;
	__u64 unused2;
	__u64 unused3;
	__u64 unused4;
};

struct btrfs_ioctl_search_header {
	__u64 transid;
	__u64 objectid;
	__u64 offset;
	__u32 type;
	__u32 len;
} __attribute__((may_alias));

#define BTRFS_SEARCH_ARGS_BUFSIZE (4096 - sizeof(struct btrfs_ioctl_search_key))
/*
 * the buf is an array of search headers where
 * each header is followed by the actual item
 * the type field is expanded to 32 bits for alignment
 */
struct btrfs_ioctl_search_args {
	struct btrfs_ioctl_search_key key;
	char buf[BTRFS_SEARCH_ARGS_BUFSIZE];
};

#define BTRFS_IOC_TREE_SEARCH _IOWR(BTRFS_IOCTL_MAGIC, 17, \
                                   struct btrfs_ioctl_search_args)
#define BTRFS_UUID_SIZE 16

struct btrfs_timespec {
	__le64 sec;
	__le32 nsec;
} __attribute__ ((__packed__));

struct btrfs_inode_item {
	/* nfs style generation number */
	__le64 generation;
	/* transid that last touched this inode */
	__le64 transid;
	__le64 size;
	__le64 nbytes;
	__le64 block_group;
	__le32 nlink;
	__le32 uid;
	__le32 gid;
	__le32 mode;
	__le64 rdev;
	__le64 flags;

	/* modification sequence number for NFS */
	__le64 sequence;

	/*
	 * a little future expansion, for more than this we can
	 * just grow the inode item and version it
	 */
	__le64 reserved[4];
	struct btrfs_timespec atime;
	struct btrfs_timespec ctime;
	struct btrfs_timespec mtime;
	struct btrfs_timespec otime;
} __attribute__ ((__packed__));

struct btrfs_root_item_v0 {
	struct btrfs_inode_item inode;
	__le64 generation;
	__le64 root_dirid;
	__le64 bytenr;
	__le64 byte_limit;
	__le64 bytes_used;
	__le64 last_snapshot;
	__le64 flags;
	__le32 refs;
	struct btrfs_disk_key drop_progress;
	u8 drop_level;
	u8 level;
} __attribute__ ((__packed__));

struct btrfs_root_item {
	struct btrfs_inode_item inode;
	__le64 generation;
	__le64 root_dirid;
	__le64 bytenr;
	__le64 byte_limit;
	__le64 bytes_used;
	__le64 last_snapshot;
	__le64 flags;
	__le32 refs;
	struct btrfs_disk_key drop_progress;
	u8 drop_level;
	u8 level;

	/*
	 * The following fields appear after subvol_uuids+subvol_times
	 * were introduced.
	 */

	/*
	 * This generation number is used to test if the new fields are valid
	 * and up to date while reading the root item. Every time the root item
	 * is written out, the "generation" field is copied into this field. If
	 * anyone ever mounted the fs with an older kernel, we will have
	 * mismatching generation values here and thus must invalidate the
	 * new fields. See btrfs_update_root and btrfs_find_last_root for
	 * details.
	 * the offset of generation_v2 is also used as the start for the memset
	 * when invalidating the fields.
	 */
	__le64 generation_v2;
	u8 uuid[BTRFS_UUID_SIZE];
	u8 parent_uuid[BTRFS_UUID_SIZE];
	u8 received_uuid[BTRFS_UUID_SIZE];
	__le64 ctransid; /* updated when an inode changes */
	__le64 otransid; /* trans when created */
	__le64 stransid; /* trans when sent. non-zero for received subvol */
	__le64 rtransid; /* trans when received. non-zero for received subvol */
	struct btrfs_timespec ctime;
	struct btrfs_timespec otime;
	struct btrfs_timespec stime;
	struct btrfs_timespec rtime;
	__le64 reserved[8]; /* for future */
} __attribute__ ((__packed__));

#define BTRFS_IOC_INO_LOOKUP _IOWR(BTRFS_IOCTL_MAGIC, 18, \
                                   struct btrfs_ioctl_ino_lookup_args)

#define BTRFS_INO_LOOKUP_PATH_MAX 4080
struct btrfs_ioctl_ino_lookup_args {
	__u64 treeid;
	__u64 objectid;
	char name[BTRFS_INO_LOOKUP_PATH_MAX];
};

/*
 * All files have objectids in this range.
 */
#define BTRFS_FIRST_FREE_OBJECTID 256ULL
#define BTRFS_LAST_FREE_OBJECTID -256ULL
#define BTRFS_FIRST_CHUNK_TREE_OBJECTID 256ULL

/*
 * The followings are macro for correctly getting member of
 * structures in both low and big endian platforms as per
 * btrfs-progs
 */
#ifdef __CHECKER__
#define __force    __attribute__((force))
#else
#define __force
#endif

#if __BYTE_ORDER == __BIG_ENDIAN
#define cpu_to_le64(x) ((__force __le64)(u64)(bswap_64(x)))
#define le64_to_cpu(x) ((__force u64)(__le64)(bswap_64(x)))
#define cpu_to_le32(x) ((__force __le32)(u32)(bswap_32(x)))
#define le32_to_cpu(x) ((__force u32)(__le32)(bswap_32(x)))
#define cpu_to_le16(x) ((__force __le16)(u16)(bswap_16(x)))
#define le16_to_cpu(x) ((__force u16)(__le16)(bswap_16(x)))
#else
#define cpu_to_le64(x) ((__force __le64)(u64)(x))
#define le64_to_cpu(x) ((__force u64)(__le64)(x))
#define cpu_to_le32(x) ((__force __le32)(u32)(x))
#define le32_to_cpu(x) ((__force u32)(__le32)(x))
#define cpu_to_le16(x) ((__force __le16)(u16)(x))
#define le16_to_cpu(x) ((__force u16)(__le16)(x))
#endif

#define BTRFS_SETGET_STACK_FUNCS(name, type, member, bits)              \
static inline u##bits btrfs_##name(type *s)                             \
{                                                                       \
        return le##bits##_to_cpu(s->member);                            \
}                                                                       \
static inline void btrfs_set_##name(type *s, u##bits val)               \
{                                                                       \
        s->member = cpu_to_le##bits(val);                               \
}

/* defined as btrfs_stack_root_ref_dirid */
BTRFS_SETGET_STACK_FUNCS(stack_root_ref_dirid, struct btrfs_root_ref, dirid, 64);
/* defined as btrfs_stack_root_ref_sequence */
BTRFS_SETGET_STACK_FUNCS(stack_root_ref_sequence, struct btrfs_root_ref, sequence, 64);
/* defined as btrfs_stack_root_ref_name_len */
BTRFS_SETGET_STACK_FUNCS(stack_root_ref_name_len, struct btrfs_root_ref, name_len, 16);

/* defined in bdev.h */
struct bdev;

/* defined in lxccontainer.h */
struct bdev_specs;

/* defined conf.h */
struct lxc_conf;

struct mytree_node {
	u64 objid;
	u64 parentid;
	char *name;
	char *dirname;
};

struct my_btrfs_tree {
	struct mytree_node *nodes;
	int num;
};

/*
 * Functions associated with a btrfs bdev struct.
 */
int btrfs_clonepaths(struct bdev *orig, struct bdev *new, const char *oldname,
		     const char *cname, const char *oldpath,
		     const char *lxcpath, int snap, uint64_t newsize,
		     struct lxc_conf *conf);
int btrfs_create(struct bdev *bdev, const char *dest, const char *n,
		 struct bdev_specs *specs);
int btrfs_destroy(struct bdev *orig);
int btrfs_detect(const char *path);
int btrfs_mount(struct bdev *bdev);
int btrfs_umount(struct bdev *bdev);

/*
 * Helper functions
 */
char *get_btrfs_subvol_path(int fd, u64 dir_id, u64 objid, char *name,
			    int name_len);
int btrfs_list_get_path_rootid(int fd, u64 *treeid);
bool is_btrfs_fs(const char *path);
bool btrfs_try_remove_subvol(const char *path);
int btrfs_same_fs(const char *orig, const char *new);
int btrfs_snapshot(const char *orig, const char *new);

#endif // __LXC_BTRFS_H
