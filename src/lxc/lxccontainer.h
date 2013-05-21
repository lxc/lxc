#ifndef __LXC_CONTAINER_H
#define __LXC_CONTAINER_H
#include "lxclock.h"
#include "attach_options.h"
#include <stdlib.h>
#include <malloc.h>

#include <stdbool.h>

#define LXC_CLONE_KEEPNAME        (1 << 0)
#define LXC_CLONE_COPYHOOKS       (1 << 1)
#define LXC_CLONE_KEEPMACADDR     (1 << 2)
#define LXC_CLONE_SNAPSHOT        (1 << 3)
#define LXC_CLONE_MAXFLAGS        (1 << 4)

#define LXC_CREATE_QUIET	  (1 << 0)
#define LXC_CREATE_MAXFLAGS       (1 << 1)

struct bdev_specs;

struct lxc_container {
	// private fields
	char *name;
	char *configfile;
	struct lxc_lock *slock;
	struct lxc_lock *privlock;
	int numthreads; /* protected by privlock. */
	struct lxc_conf *lxc_conf; // maybe we'll just want the whole lxc_handler?

	// public fields
	char *error_string;
	int error_num;
	int daemonize;

	char *config_path;

	bool (*is_defined)(struct lxc_container *c);  // did /var/lib/lxc/$name/config exist
	const char *(*state)(struct lxc_container *c);
	bool (*is_running)(struct lxc_container *c);  // true so long as defined and not stopped
	bool (*freeze)(struct lxc_container *c);
	bool (*unfreeze)(struct lxc_container *c);
	pid_t (*init_pid)(struct lxc_container *c);
	bool (*load_config)(struct lxc_container *c, const char *alt_file);
	/* The '...' is the command line.  If provided, it must be ended with a NULL */
	bool (*start)(struct lxc_container *c, int useinit, char * const argv[]);
	bool (*startl)(struct lxc_container *c, int useinit, ...);
	bool (*stop)(struct lxc_container *c);
	void (*want_daemonize)(struct lxc_container *c);
	// Return current config file name.  The result is strdup()d, so free the result.
	char *(*config_file_name)(struct lxc_container *c);
	// for wait, timeout == -1 means wait forever, timeout == 0 means don't wait.
	// otherwise timeout is seconds to wait.
	bool (*wait)(struct lxc_container *c, const char *state, int timeout);
	bool (*set_config_item)(struct lxc_container *c, const char *key, const char *value);
	bool (*destroy)(struct lxc_container *c);
	bool (*save_config)(struct lxc_container *c, const char *alt_file);
	bool (*create)(struct lxc_container *c, const char *t, const char *bdevtype,
			struct bdev_specs *specs, int flags, char *const argv[]);
	bool (*createl)(struct lxc_container *c, const char *t, const char *bdevtype,
			struct bdev_specs *specs, int flags, ...);
	/* send SIGINT to ask container to reboot */
	bool (*reboot)(struct lxc_container *c);
	/* send SIGPWR.  if timeout is not 0 or -1, do a hard stop after timeout seconds */
	bool (*shutdown)(struct lxc_container *c, int timeout);
	/* clear all network or capability items in the in-memory configuration */
	bool (*clear_config_item)(struct lxc_container *c, const char *key);
	/* print a config item to a in-memory string allocated by the caller.  Return
	 * the length which was our would be printed. */
	int (*get_config_item)(struct lxc_container *c, const char *key, char *retv, int inlen);
	int (*get_keys)(struct lxc_container *c, const char *key, char *retv, int inlen);
	char** (*get_ips)(struct lxc_container *c, char* interface, char* family, int scope);
	/*
	 * get_cgroup_item returns the number of bytes read, or an error (<0).
	 * If retv NULL or inlen 0 is passed in, then the length of the cgroup
	 * file will be returned.  *   Otherwise it will return the # of bytes read.
	 * If inlen is less than the number of bytes available, then the returned
	 * value will be inlen, not the full available size of the file.
	 */
	int (*get_cgroup_item)(struct lxc_container *c, const char *subsys, char *retv, int inlen);
	bool (*set_cgroup_item)(struct lxc_container *c, const char *subsys, const char *value);

	/*
	 * Each container can have a custom configuration path.  However
	 * by default it will be set to either the LXCPATH configure
	 * variable, or the lxcpath value in the LXC_GLOBAL_CONF configuration
	 * file (i.e. /etc/lxc/lxc.conf).
	 * You can change the value for a specific container with
	 * set_config_path().  Note there is no other way to specify this in
	 * general at the moment.
	 */
	const char *(*get_config_path)(struct lxc_container *c);
	bool (*set_config_path)(struct lxc_container *c, const char *path);

	/*
	 * @c: the original container
	 * @newname: new name for the container.  If NULL, the same name is used, and
	 *  a new lxcpath MUST be specified.
	 * @lxcpath: lxcpath in which to create the new container.  If NULL, then the
	 *  original container's lxcpath will be used.  (Shoudl we use the default
	 *  instead?)
	 * @flags: additional flags to modify cloning behavior.
	 *  LXC_CLONE_KEEPNAME: don't edit the rootfs to change the hostname.
	 *  LXC_CLONE_COPYHOOKS: copy all hooks into the container dir
	 *  LXC_CLONE_KEEPMACADDR: don't change the mac address on network interfaces.
	 *  LXC_CLONE_SNAPSHOT: snapshot the original filesystem(s).  If @devtype was not
	 *   specified, then do so with the native bdevtype if possible, else use an
	 *   overlayfs.
	 * @bdevtype: optionally force the cloned bdevtype to a specified plugin.  By
	 *  default the original  is used (subject to snapshot requirements).
	 * @bdevdata: information about how to create the new storage (i.e. fstype and
	 *  fsdata)
	 * @newsize: in case of a block device backing store, an optional size.  If 0,
	 *  then the original backing store's size will be used if possible.  Note this
	 *  only applies to the rootfs.  For any other filesystems, the original size
	 *  will be duplicated.
	 * @hookargs: additional arguments to pass to the clone hook script
	 */
	struct lxc_container *(*clone)(struct lxc_container *c, const char *newname,
		const char *lxcpath, int flags, const char *bdevtype,
		const char *bdevdata, unsigned long newsize, char **hookargs);

	/* lxcapi_console_getfd: allocate a console tty from container @c
	 *
	 * @c        : the running container
	 * @ttynum   : in : tty number to attempt to allocate or -1 to
	 *                  allocate the first available tty
	 *             out: the tty number that was allocated
	 * @masterfd : out: fd refering to the master side of pty
	 *
	 * Returns "ttyfd" on success, -1 on failure. The returned "ttyfd" is
	 * used to keep the tty allocated. The caller should close "ttyfd" to
	 * indicate that it is done with the allocated console so that it can
	 * be allocated by another caller.
	 */
	int (*console_getfd)(struct lxc_container *c, int *ttynum, int *masterfd);

	/* lxcapi_console: allocate and run a console tty from container @c
	 *
	 * @c        : the running container
	 * @ttynum   : tty number to attempt to allocate, -1 to
	 *             allocate the first available tty, or 0 to allocate
	 *             the console
	 * @stdinfd  : fd to read input from
	 * @stdoutfd : fd to write output to
	 * @stderrfd : fd to write error output to
	 * @escape   : the escape character (1 == 'a', 2 == 'b', ...)
	 *
	 * Returns 0 on success, -1 on failure. This function will not return
	 * until the console has been exited by the user.
	 */
	int (*console)(struct lxc_container *c, int ttynum,
		       int stdinfd, int stdoutfd, int stderrfd, int escape);

	/* create subprocess and attach it to the container, run exec_function inside */
	int (*attach)(struct lxc_container *c, lxc_attach_exec_t exec_function, void *exec_payload, lxc_attach_options_t *options, pid_t *attached_process);

	/* run program in container, wait for it to exit */
	int (*attach_run_wait)(struct lxc_container *c, lxc_attach_options_t *options, const char *program, const char * const argv[]);
	int (*attach_run_waitl)(struct lxc_container *c, lxc_attach_options_t *options, const char *program, const char *arg, ...);
#if 0
	bool (*commit_cgroups)(struct lxc_container *c);
	bool (*reread_cgroups)(struct lxc_container *c);
	// question with clone: how do we handle non-standard config file in orig?
	struct lxc_container (*clone)(struct container *c);
	// we'll need some plumbing to support lxc-console
#endif
};

struct lxc_container *lxc_container_new(const char *name, const char *configpath);
int lxc_container_get(struct lxc_container *c);
int lxc_container_put(struct lxc_container *c);
int lxc_get_wait_states(const char **states);
const char *lxc_get_default_config_path(void);
const char *lxc_get_default_lvm_vg(void);
const char *lxc_get_default_zfs_root(void);
const char *lxc_get_version(void);

#if 0
char ** lxc_get_valid_keys();
char ** lxc_get_valid_values(char *key);
#endif
#endif
