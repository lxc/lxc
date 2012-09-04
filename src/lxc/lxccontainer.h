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

#define LXCDIR "/var/lib/lxc"
	bool (*is_defined)(struct lxc_container *c);  // did /var/lib/lxc/$name/config exist
	const char *(*state)(struct lxc_container *c);
	bool (*is_running)(struct lxc_container *c);  // true so long as defined and not stopped
	bool (*freeze)(struct lxc_container *c);
	bool (*unfreeze)(struct lxc_container *c);
	pid_t (*init_pid)(struct lxc_container *c);
	bool (*load_config)(struct lxc_container *c, char *alt_file);
	/* The '...' is the command line.  If provided, it must be ended with a NULL */
	bool (*start)(struct lxc_container *c, int useinit, char ** argv);
	bool (*startl)(struct lxc_container *c, int useinit, ...);
	bool (*stop)(struct lxc_container *c);
	void (*want_daemonize)(struct lxc_container *c);
	// Return current config file name.  The result is strdup()d, so free the result.
	char *(*config_file_name)(struct lxc_container *c);
	// for wait, timeout == -1 means wait forever, timeout == 0 means don't wait.
	// otherwise timeout is seconds to wait.
	bool (*wait)(struct lxc_container *c, char *state, int timeout);
	bool (*set_config_item)(struct lxc_container *c, char *key, char *value);
	bool (*destroy)(struct lxc_container *c);
	bool (*save_config)(struct lxc_container *c, char *alt_file);
	bool (*create)(struct lxc_container *c, char *t, char **argv);
	bool (*createl)(struct lxc_container *c, char *t, ...);
	/* send SIGPWR.  if timeout is not 0 or -1, do a hard stop after timeout seconds */
	bool (*shutdown)(struct lxc_container *c, int timeout);
	/* clear all network or capability items in the in-memory configuration */
	bool (*clear_config_item)(struct lxc_container *c, char *key);
	/* print a config item to a in-memory string allocated by the caller.  Return
	 * the length which was our would be printed. */
	int (*get_config_item)(struct lxc_container *c, char *key, char *retv, int inlen);
	int (*get_keys)(struct lxc_container *c, char *key, char *retv, int inlen);

#if 0
	bool (*commit_cgroups)(struct lxc_container *c);
	bool (*reread_cgroups)(struct lxc_container *c);
	// question with clone: how do we handle non-standard config file in orig?
	struct lxc_container (*clone)(struct container *c);
	int (*ns_attach)(struct lxc_container *c, int ns_mask);
	// we'll need some plumbing to support lxc-console
#endif
};

struct lxc_container *lxc_container_new(char *name);
int lxc_container_get(struct lxc_container *c);
int lxc_container_put(struct lxc_container *c);
int lxc_get_wait_states(const char **states);

#if 0
char ** lxc_get_valid_keys();
char ** lxc_get_valid_values(char *key);
#endif
