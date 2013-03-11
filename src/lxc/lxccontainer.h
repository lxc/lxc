#include "lxclock.h"
#include <stdlib.h>
#include <malloc.h>

#include <stdbool.h>

struct lxc_container {
	// private fields
	char *name;
	char *configfile;
	sem_t *slock;
	sem_t *privlock;
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
	bool (*create)(struct lxc_container *c, char *t, char *const argv[]);
	bool (*createl)(struct lxc_container *c, char *t, ...);
	/* send SIGPWR.  if timeout is not 0 or -1, do a hard stop after timeout seconds */
	bool (*shutdown)(struct lxc_container *c, int timeout);
	/* clear all network or capability items in the in-memory configuration */
	bool (*clear_config_item)(struct lxc_container *c, const char *key);
	/* print a config item to a in-memory string allocated by the caller.  Return
	 * the length which was our would be printed. */
	int (*get_config_item)(struct lxc_container *c, const char *key, char *retv, int inlen);
	int (*get_keys)(struct lxc_container *c, const char *key, char *retv, int inlen);
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

#if 0
	bool (*commit_cgroups)(struct lxc_container *c);
	bool (*reread_cgroups)(struct lxc_container *c);
	// question with clone: how do we handle non-standard config file in orig?
	struct lxc_container (*clone)(struct container *c);
	int (*ns_attach)(struct lxc_container *c, int ns_mask);
	// we'll need some plumbing to support lxc-console
#endif
};

struct lxc_container *lxc_container_new(const char *name, const char *configpath);
int lxc_container_get(struct lxc_container *c);
int lxc_container_put(struct lxc_container *c);
int lxc_get_wait_states(const char **states);
const char *lxc_get_default_config_path(void);
const char *lxc_get_version(void);

#if 0
char ** lxc_get_valid_keys();
char ** lxc_get_valid_values(char *key);
#endif
