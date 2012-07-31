#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>

#include "log.h"
#include "apparmor.h"

lxc_log_define(lxc_apparmor, lxc);

#if HAVE_APPARMOR
#include <sys/apparmor.h>

#define AA_MOUNT_RESTR "/sys/kernel/security/apparmor/features/mount/mask"
#define AA_ENABLED_FILE "/sys/module/apparmor/parameters/enabled"

static int aa_am_unconfined(void)
{
	int ret;
	char path[100], p[100];
	sprintf(path, "/proc/%d/attr/current", getpid());
	FILE *f = fopen(path, "r");
	if (!f)
		return 0;
	ret = fscanf(f, "%99s", p);
	fclose(f);
	if (ret < 1)
		return 0;
	if (strcmp(p, "unconfined") == 0)
		return 1;
	return 0;
}

/* aa_getcon is not working right now.  Use our hand-rolled version below */
static int check_apparmor_enabled(void)
{
	struct stat statbuf;
	FILE *fin;
	char e;
	int ret;

	ret = stat(AA_MOUNT_RESTR, &statbuf);
	if (ret != 0)
		return 0;
	fin = fopen(AA_ENABLED_FILE, "r");
	if (!fin)
		return 0;
	ret = fscanf(fin, "%c", &e);
	fclose(fin);
	if (ret == 1 && e == 'Y')
		return 1;
	return 0;
}

extern void apparmor_handler_init(struct lxc_handler *handler)
{
	handler->aa_enabled = check_apparmor_enabled();
	INFO("aa_enabled set to %d\n", handler->aa_enabled);
}

#define AA_DEF_PROFILE "lxc-container-default"
extern int apparmor_load(struct lxc_handler *handler)
{
	if (!handler->aa_enabled) {
		INFO("apparmor not enabled");
		return 0;
	}
	INFO("setting up apparmor");

	if (!handler->conf->aa_profile)
		handler->conf->aa_profile = AA_DEF_PROFILE;

	if (strcmp(handler->conf->aa_profile, "unconfined") == 0 &&
	    aa_am_unconfined()) {
		INFO("apparmor profile unchanged");
		return 0;
	}

	//if (aa_change_onexec(handler->conf->aa_profile) < 0) {
	if (aa_change_profile(handler->conf->aa_profile) < 0) {
		SYSERROR("failed to change apparmor profile to %s", handler->conf->aa_profile);
		return -1;
	}
	if (handler->conf->lsm_umount_proc == 1)
		umount("/proc");

	INFO("changed apparmor profile to %s", handler->conf->aa_profile);

	return 0;
}

/*
 * this will likely move to a generic lsm.c, as selinux and smack will both
 * also want proc mounted in the container so as to transition
 */
extern int lsm_mount_proc_if_needed(char *root_src, char *rootfs_tgt)
{
	char path[MAXPATHLEN];
	char link[20];
	int linklen, ret;

	ret = snprintf(path, MAXPATHLEN, "%s/proc/self", root_src ? rootfs_tgt : "");
	if (ret < 0 || ret >= MAXPATHLEN) {
		SYSERROR("proc path name too long");
		return -1;
	}
	memset(link, 0, 20);
	linklen = readlink(path, link, 20);
	INFO("I am %d, /proc/self points to %s\n", getpid(), link);
	ret = snprintf(path, MAXPATHLEN, "%s/proc", root_src ? rootfs_tgt : "");
	if (linklen < 0) /* /proc not mounted */
		goto domount;
	/* can't be longer than rootfs/proc/1 */
	if (strncmp(link, "1", linklen) != 0) {
		/* wrong /procs mounted */
		umount2(path, MNT_DETACH); /* ignore failure */
		goto domount;
	}
	/* the right proc is already mounted */
	return 0;

domount:
	if (mount("proc", path, "proc", 0, NULL))
		return -1;
	INFO("Mounted /proc for the container\n");
	return 1;
}
#else
extern void apparmor_handler_init(struct lxc_handler *handler) {
	INFO("apparmor_load - apparmor is disabled");
}
#endif
