/* apparmor
 *
 * Copyright © 2012 Serge Hallyn <serge.hallyn@ubuntu.com>.
 * Copyright © 2012 Canonical Ltd.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.

 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.

 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <lxc/start.h>  /* for lxc_handler */
#include <lxc/conf.h>

struct lxc_handler;

/*
 * apparmor_handler_init is really just a wrapper around check_apparmor_enabled
 * to allow us to keep from having #ifdef APPARMOR in start.c
 */
extern void apparmor_handler_init(struct lxc_handler *handler);

#if HAVE_APPARMOR
extern char *aa_get_profile(pid_t pid);
extern int do_apparmor_load(int aa_enabled, char *aa_profile,
				   int umount_proc, int dropprivs);
extern int apparmor_load(struct lxc_handler *handler);
extern int attach_apparmor(char *profile);
extern int lsm_mount_proc_if_needed(char *root_src, char *rootfs_tgt);
#else
static inline char *aa_get_profile(pid_t pid) {
	return NULL;
}
static inline int do_apparmor_load(int aa_enabled, char *aa_profile,
				   int umount_proc, int dropprivs) {
	return 0;
}
static inline int attach_apparmor(char *profile) {
	return 0;
}
static inline int apparmor_load(struct lxc_handler *handler) {
	return 0;
}
static inline int lsm_mount_proc_if_needed(char *root_src, char *rootfs_tgt) {
	return 0;
}
#endif
