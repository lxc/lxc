/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>

#include "macro.h"
#include "memory_utils.h"
#include "mount_utils.h"
#include "syscall_numbers.h"
#include "syscall_wrappers.h"

int mnt_attributes_new(unsigned int old_flags, unsigned int *new_flags)
{
	unsigned int flags = 0;

	if (old_flags & MS_RDONLY) {
		flags |= MOUNT_ATTR_RDONLY;
		old_flags &= ~MS_RDONLY;
	}

	if (old_flags & MS_NOSUID) {
		flags |= MOUNT_ATTR_NOSUID;
		old_flags &= ~MS_NOSUID;
	}

	if (old_flags & MS_NODEV) {
		flags |= MOUNT_ATTR_NODEV;
		old_flags &= ~MS_NODEV;
	}

	if (old_flags & MS_NOEXEC) {
		flags |= MOUNT_ATTR_NOEXEC;
		old_flags &= ~MS_NOEXEC;
	}

	if (old_flags & MS_RELATIME) {
		flags |= MOUNT_ATTR_RELATIME;
		old_flags &= ~MS_RELATIME;
	}

	if (old_flags & MS_NOATIME) {
		flags |= MOUNT_ATTR_NOATIME;
		old_flags &= ~MS_NOATIME;
	}

	if (old_flags & MS_STRICTATIME) {
		flags |= MOUNT_ATTR_STRICTATIME;
		old_flags &= ~MS_STRICTATIME;
	}

	if (old_flags & MS_NODIRATIME) {
		flags |= MOUNT_ATTR_NODIRATIME;
		old_flags &= ~MS_NODIRATIME;
	}

	*new_flags |= flags;
	return old_flags;
}

int mnt_attributes_old(unsigned int new_flags, unsigned int *old_flags)
{
	unsigned int flags = 0;

	if (new_flags & MOUNT_ATTR_RDONLY) {
		flags |= MS_RDONLY;
		new_flags &= ~MOUNT_ATTR_RDONLY;
	}

	if (new_flags & MOUNT_ATTR_NOSUID) {
		flags |= MS_NOSUID;
		new_flags &= ~MOUNT_ATTR_NOSUID;
	}

	if (new_flags & MS_NODEV) {
		flags |= MOUNT_ATTR_NODEV;
		new_flags &= ~MS_NODEV;
	}

	if (new_flags & MOUNT_ATTR_NOEXEC) {
		flags |= MS_NOEXEC;
		new_flags &= ~MOUNT_ATTR_NOEXEC;
	}

	if (new_flags & MS_RELATIME) {
		flags |= MS_RELATIME;
		new_flags &= ~MOUNT_ATTR_RELATIME;
	}

	if (new_flags & MS_NOATIME) {
		flags |= MS_NOATIME;
		new_flags &= ~MOUNT_ATTR_NOATIME;
	}

	if (new_flags & MS_STRICTATIME) {
		flags |= MS_STRICTATIME;
		new_flags &= ~MOUNT_ATTR_STRICTATIME;
	}

	if (new_flags & MS_NODIRATIME) {
		flags |= MS_NODIRATIME;
		new_flags &= ~MOUNT_ATTR_NODIRATIME;
	}

	*old_flags |= flags;
	return new_flags;
}
