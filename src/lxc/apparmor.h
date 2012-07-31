#include <lxc/start.h>  /* for lxc_handler */
#include <lxc/conf.h>

struct lxc_handler;

#if HAVE_APPARMOR
extern int apparmor_load(struct lxc_handler *handler);
extern int lsm_mount_proc_if_needed(char *root_src, char *rootfs_tgt);
extern void apparmor_handler_init(struct lxc_handler *handler);
#else
static inline int apparmor_load(struct lxc_handler *handler) {
	return 0;
}
static inline int lsm_mount_proc_if_needed(char *root_src, char *rootfs_tgt) {
	return 0;
}
extern void apparmor_handler_init(struct lxc_handler *handler);
#endif
