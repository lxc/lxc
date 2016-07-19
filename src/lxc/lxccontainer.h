/*! \file
 *
 * liblxcapi
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

#ifndef __LXC_CONTAINER_H
#define __LXC_CONTAINER_H
#include <malloc.h>
#include <semaphore.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>

#include <lxc/attach_options.h>

#ifdef  __cplusplus
extern "C" {
#endif

#define LXC_CLONE_KEEPNAME        (1 << 0) /*!< Do not edit the rootfs to change the hostname */
#define LXC_CLONE_KEEPMACADDR     (1 << 1) /*!< Do not change the MAC address on network interfaces */
#define LXC_CLONE_SNAPSHOT        (1 << 2) /*!< Snapshot the original filesystem(s) */
#define LXC_CLONE_KEEPBDEVTYPE    (1 << 3) /*!< Use the same bdev type */
#define LXC_CLONE_MAYBE_SNAPSHOT  (1 << 4) /*!< Snapshot only if bdev supports it, else copy */
#define LXC_CLONE_MAXFLAGS        (1 << 5) /*!< Number of \c LXC_CLONE_* flags */
#define LXC_CREATE_QUIET          (1 << 0) /*!< Redirect \c stdin to \c /dev/zero and \c stdout and \c stderr to \c /dev/null */
#define LXC_CREATE_MAXFLAGS       (1 << 1) /*!< Number of \c LXC_CREATE* flags */

struct bdev_specs;

struct lxc_snapshot;

struct lxc_lock;

struct migrate_opts;

/*!
 * An LXC container.
 *
 * Note that changing the order of struct members is an API change, as callers
 * will end up having the wrong offset when calling a function.  So when making
 * changes, whenever possible stick to simply appending new members.
 */
struct lxc_container {
	// private fields
	/*!
	 * \private
	 * Name of container.
	 */
	char *name;

	/*!
	 * \private
	 * Full path to configuration file.
	 */
	char *configfile;

	/*!
	 * \private
	 * File to store pid.
	 */
	char *pidfile;

	/*!
	 * \private
	 * Container semaphore lock.
	 */
	struct lxc_lock *slock;

	/*!
	 * \private
	 * Container private lock.
	 */
	struct lxc_lock *privlock;

	/*!
	 * \private
	 * Number of references to this container.
	 * \note protected by privlock.
	 */
	int numthreads;

	/*!
	 * \private
	 * Container configuration.
	 *
	 * \internal FIXME: do we want the whole lxc_handler?
	 */
	struct lxc_conf *lxc_conf;

	// public fields
	/*! Human-readable string representing last error */
	char *error_string;

	/*! Last error number */
	int error_num;

	/*! Whether container wishes to be daemonized */
	bool daemonize;

	/*! Full path to configuration file */
	char *config_path;

	/*!
	 * \brief Determine if \c /var/lib/lxc/$name/config exists.
	 *
	 * \param c Container.
	 *
	 * \return \c true if container is defined, else \c false.
	 */
	bool (*is_defined)(struct lxc_container *c);

	/*!
	 * \brief Determine state of container.
	 *
	 * \param c Container.
	 *
	 * \return Static upper-case string representing state of container.
	 *
	 * \note Returned string must not be freed.
	 */
	const char *(*state)(struct lxc_container *c);

	/*!
	 * \brief Determine if container is running.
	 *
	 * \param c Container.
	 *
	 * \return \c true on success, else \c false.
	 */
	bool (*is_running)(struct lxc_container *c);

	/*!
	 * \brief Freeze running container.
	 *
	 * \param c Container.
	 *
	 * \return \c true on success, else \c false.
	 */
	bool (*freeze)(struct lxc_container *c);

	/*!
	 * \brief Thaw a frozen container.
	 *
	 * \param c Container.
	 *
	 * \return \c true on success, else \c false.
	 */
	bool (*unfreeze)(struct lxc_container *c);

	/*!
	 * \brief Determine process ID of the containers init process.
	 *
	 * \param c Container.
	 *
	 * \return pid of init process as seen from outside the
	 *  container.
	 */
	pid_t (*init_pid)(struct lxc_container *c);

	/*!
	 * \brief Load the specified configuration for the container.
	 *
	 * \param c Container.
	 * \param alt_file Full path to alternate configuration file, or
	 *  \c NULL to use the default configuration file.
	 *
	 * \return \c true on success, else \c false.
	 */
	bool (*load_config)(struct lxc_container *c, const char *alt_file);

	/*!
	 * \brief Start the container.
	 *
	 * \param c Container.
	 * \param useinit Use lxcinit rather than \c /sbin/init.
	 * \param argv Array of arguments to pass to init.
	 *
	 * \return \c true on success, else \c false.
	 */
	bool (*start)(struct lxc_container *c, int useinit, char * const argv[]);

	/*!
	 * \brief Start the container (list variant).
	 *
	 * \param c Container.
	 * \param useinit Use lxcinit rather than \c /sbin/init.
	 * \param ... Command-line to pass to init (must end in \c NULL).
	 *
	 * \return \c true on success, else \c false.
	 *
	 * \note Identical to \ref start except that that the init
	 *  arguments are specified via a list rather than an array of
	 *  pointers.
	 */
	bool (*startl)(struct lxc_container *c, int useinit, ...);

	/*!
	 * \brief Stop the container.
	 *
	 * \param c Container.
	 *
	 * \return \c true on success, else \c false.
	 */
	bool (*stop)(struct lxc_container *c);

	/*!
	 * \brief Change whether the container wants to run disconnected
	 * from the terminal.
	 *
	 * \param c Container.
	 * \param state Value for the daemonize bit (0 or 1).
	 *
	 * \return \c true on success, else \c false.
	 */
	bool (*want_daemonize)(struct lxc_container *c, bool state);

	/*!
	 * \brief Change whether the container wishes all file descriptors
	 *  to be closed on startup.
	 *
	 * \param c Container.
	 * \param state Value for the close_all_fds bit (0 or 1).
	 *
	 * \return \c true on success, else \c false.
	 */
	bool (*want_close_all_fds)(struct lxc_container *c, bool state);

	/*!
	 * \brief Return current config file name.
	 *
	 * \param c Container.
	 *
	 * \return config file name, or \c NULL on error.
	 *
	 * \note The result is allocated, so the caller must free the result.
	 */
	char *(*config_file_name)(struct lxc_container *c);

	/*!
	 * \brief Wait for container to reach a particular state.
	 *
	 * \param c Container.
	 * \param state State to wait for.
	 * \param timeout Timeout in seconds.
	 *
	 * \return \c true if state reached within \p timeout, else \c false.
	 *
	 * \note A \p timeout of \c -1 means wait forever. A \p timeout
	 *  of \c 0 means do not wait.
	 */
	bool (*wait)(struct lxc_container *c, const char *state, int timeout);

	/*!
	 * \brief Set a key/value configuration option.
	 *
	 * \param c Container.
	 * \param key Name of option to set.
	 * \param value Value of \p name to set.
	 *
	 * \return \c true on success, else \c false.
	 */
	bool (*set_config_item)(struct lxc_container *c, const char *key, const char *value);

	/*!
	 * \brief Delete the container.
	 *
	 * \param c Container.
	 *
	 * \return \c true on success, else \c false.
	 *
	 * \note Container must be stopped and have no dependent snapshots.
	 */
	bool (*destroy)(struct lxc_container *c);

	/*!
	 * \brief Save configuaration to a file.
	 *
	 * \param c Container.
	 * \param alt_file Full path to file to save configuration in.
	 *
	 * \return \c true on success, else \c false.
	 */
	bool (*save_config)(struct lxc_container *c, const char *alt_file);

	/*!
	 * \brief Create a container.
	 *
	 * \param c Container (with lxcpath, name and a starting
	 *  configuration set).
	 * \param t Template to execute to instantiate the root
	 *  filesystem and adjust the configuration.
	 * \param bdevtype Backing store type to use (if \c NULL, \c dir will be used).
	 * \param specs Additional parameters for the backing store (for
	 *  example LVM volume group to use).
	 * \param flags \c LXC_CREATE_* options (currently only \ref
	 *  LXC_CREATE_QUIET is supported).
	 * \param argv Arguments to pass to the template, terminated by \c NULL (if no
	 *  arguments are required, just pass \c NULL).
	 *
	 * \return \c true on success, else \c false.
	 */
	bool (*create)(struct lxc_container *c, const char *t, const char *bdevtype,
			struct bdev_specs *specs, int flags, char *const argv[]);

	/*!
	 * \brief Create a container (list variant).
	 *
	 * \param c Container (with lxcpath, name and a starting
	 *  configuration set).
	 * \param t Template to execute to instantiate the root
	 *  filesystem and adjust the configuration.
	 * \param bdevtype Backing store type to use (if \c NULL, \c dir will be used).
	 * \param specs Additional parameters for the backing store (for
	 *  example LVM volume group to use).
	 * \param flags \c LXC_CREATE_* options (currently only \ref
	 *  LXC_CREATE_QUIET is supported).
	 * \param ... Command-line to pass to init (must end in \c NULL).
	 *
	 * \return \c true on success, else \c false.
	 *
	 * \note Identical to \ref create except that the template
	 *  arguments are specified as a list rather than an array of
	 *  pointers.
	 */
	bool (*createl)(struct lxc_container *c, const char *t, const char *bdevtype,
			struct bdev_specs *specs, int flags, ...);

	/*!
	 * \brief Rename a container
	 *
	 * \param c Container.
	 * \param newname New name to be used for the container.
	 *
	 * \return \c true on success, else \c false.
	 */
	bool (*rename)(struct lxc_container *c, const char *newname);

	/*!
	 * \brief Request the container reboot by sending it \c SIGINT.
	 *
	 * \param c Container.
	 *
	 * \return \c true if reboot request successful, else \c false.
	 */
	bool (*reboot)(struct lxc_container *c);

	/*!
	 * \brief Request the container shutdown by sending it \c
	 * SIGPWR.
	 *
	 * \param c Container.
	 * \param timeout Seconds to wait before returning false.
	 *  (-1 to wait forever, 0 to avoid waiting).
	 *
	 * \return \c true if the container was shutdown successfully, else \c false.
	 */
	bool (*shutdown)(struct lxc_container *c, int timeout);

	/*!
	 * \brief Completely clear the containers in-memory configuration.
	 *
	 * \param c Container.
	 */
	void (*clear_config)(struct lxc_container *c);

	/*!
	 * \brief Clear a configuration item.
	 *
	 * \param c Container.
	 * \param key Name of option to clear.
	 *
	 * \return \c true on success, else \c false.
	 *
	 * \note Analog of \ref set_config_item.
	 */
	bool (*clear_config_item)(struct lxc_container *c, const char *key);

	/*!
	 * \brief Retrieve the value of a config item.
	 *
	 * \param c Container.
	 * \param key Name of option to get.
	 * \param[out] retv Caller-allocated buffer to write value of \p key
	 * into (or \c NULL to determine length of value).
	 * \param inlen Length of \p retv (may be zero).
	 *
	 * \return Length of config items value, or < 0 on error.
	 *
	 * \note The caller can (and should) determine how large a buffer to allocate for
	 *  \p retv by initially passing its value as \c NULL and considering the return value.
	 *  This function can then be called again passing a newly-allocated suitably-sized buffer.
	 * \note If \p retv is NULL, \p inlen is ignored.
	 * \note If \p inlen is smaller than required, the value written
	 *  to \p retv will be truncated.
	 */
	int (*get_config_item)(struct lxc_container *c, const char *key, char *retv, int inlen);


	/*!
	 * \brief Retrieve the value of a config item from running container.
	 *
	 * \param c Container.
	 * \param key Name of option to get.
	 *
	 * \return the item or NULL on error.
	 *
	 * \note Returned string must be freed by the caller.
	 */
	char* (*get_running_config_item)(struct lxc_container *c, const char *key);

	/*!
	 * \brief Retrieve a list of config item keys given a key
	 * prefix.
	 *
	 * \param c Container.
	 * \param key Name of option to get.
	 * \param[out] retv Caller-allocated buffer to write list of keys to
	 *  (or \c NULL to determine overall length of keys list).
	 * \param inlen Length of \p retv (may be zero).
	 *
	 * \return Length of keys list, or < 0 on error.
	 *
	 * \note The list values written to \p retv are separated by
	 *  a newline character ('\\n').
	 * \note The caller can (and should) determine how large a buffer to allocate for
	 *  \p retv by initially passing its value as \c NULL and considering the return value.
	 *  This function can then be called again passing a newly-allocated suitably-sized buffer.
	 * \note If \p retv is NULL, \p inlen is ignored.
	 * \note If \p inlen is smaller than required, the value written
	 *  to \p retv will be truncated.
	 */
	int (*get_keys)(struct lxc_container *c, const char *key, char *retv, int inlen);

	/*!
	 * \brief Obtain a list of network interfaces.
	 * \param c Container.
	 *
	 * \return Newly-allocated array of network interfaces, or \c
	 *  NULL on error.
	 *
	 * \note The returned array is allocated, so the caller must free it.
	 * \note The returned array is terminated with a \c NULL entry.
	 */
	char** (*get_interfaces)(struct lxc_container *c);

	/*!
	 * \brief Determine the list of container IP addresses.
	 *
	 * \param c Container.
	 * \param interface Network interface name to consider.
	 * \param family Network family (for example "inet", "inet6").
	 * \param scope IPv6 scope id (ignored if \p family is not "inet6").
	 *
	 * \return Newly-allocated array of network interfaces, or \c
	 *  NULL on error.
	 *
	 * \note The returned array is allocated, so the caller must free it.
	 * \note The returned array is terminated with a \c NULL entry.
	 */
	char** (*get_ips)(struct lxc_container *c, const char* interface, const char* family, int scope);

	/*!
	 * \brief Retrieve the specified cgroup subsystem value for the container.
	 *
	 * \param c Container.
	 * \param subsys cgroup subsystem to retrieve.
	 * \param[out] retv Caller-allocated buffer to write value of \p
	 *  subsys into (or \c NULL to determine length of value).
	 * \param inlen length of \p retv (may be zero).
	 *
	 * \return Length of \p subsys value, or < 0 on error.
	 *
	 * \note If \p retv is \c NULL, \p inlen is ignored.
	 * \note If \p inlen is smaller than required, the value written
	 *  to \p retv will be truncated.
	 */
	int (*get_cgroup_item)(struct lxc_container *c, const char *subsys, char *retv, int inlen);

	/*!
	 * \brief Set the specified cgroup subsystem value for the container.
	 *
	 * \param c Container.
	 * \param subsys cgroup subsystem to consider.
	 * \param value Value to set for \p subsys.
	 *
	 * \return \c true on success, else \c false.
	 */
	bool (*set_cgroup_item)(struct lxc_container *c, const char *subsys, const char *value);

	/*!
	 * \brief Determine full path to the containers configuration file.
	 * Each container can have a custom configuration path. However
	 * by default it will be set to either the \c LXCPATH configure
	 * variable, or the lxcpath value in the \c LXC_GLOBAL_CONF configuration
	 * file (i.e. \c /etc/lxc/lxc.conf).
	 * The value for a specific container can be changed using
	 * \ref set_config_path. There is no other way to specify this in general at the moment.
	 *
	 * \param c Container.
	 *
	 * \return Static string representing full path to configuration
	 * file.
	 *
	 * \note Returned string must not be freed.
	 */
	const char *(*get_config_path)(struct lxc_container *c);

	/*!
	 * \brief Set the full path to the containers configuration
	 * file.
	 *
	 * \param c Container.
	 * \param path Full path to configuration file.
	 *
	 * \return \c true on success, else \c false.
	 */
	bool (*set_config_path)(struct lxc_container *c, const char *path);

	/*!
	 * \brief Copy a stopped container.
	 *
	 * \param c Original container.
	 * \param newname New name for the container. If \c NULL, the same
	 *  name is used and a new lxcpath MUST be specified.
	 * \param lxcpath lxcpath in which to create the new container. If
	 *  \c NULL, the original container's lxcpath will be used.
	 *  (XXX: should we use the default instead?)
	 * \param flags Additional \c LXC_CLONE* flags to change the cloning behaviour:
	 *  - \ref LXC_CLONE_KEEPNAME
	 *  - \ref LXC_CLONE_KEEPMACADDR
	 *  - \ref LXC_CLONE_SNAPSHOT
	 * \param bdevtype Optionally force the cloned bdevtype to a specified plugin.
	 *  By default the original is used (subject to snapshot requirements).
	 * \param bdevdata Information about how to create the new storage
	 *  (i.e. fstype and fsdata).
	 * \param newsize In case of a block device backing store, an
	 *  optional size. If \c 0, the original backing store's size will
	 *  be used if possible. Note this only applies to the rootfs. For
	 *  any other filesystems, the original size will be duplicated.
	 * \param hookargs Additional arguments to pass to the clone hook script.
	 *
	 * \return Newly-allocated copy of container \p c, or \p NULL on
	 * error.
	 *
	 * \note If devtype was not specified, and \p flags contains \ref
	 * LXC_CLONE_SNAPSHOT then use the native \p bdevtype if possible,
	 * else use an overlayfs.
	 */
	struct lxc_container *(*clone)(struct lxc_container *c, const char *newname,
			const char *lxcpath, int flags, const char *bdevtype,
			const char *bdevdata, uint64_t newsize, char **hookargs);

	/*!
	 * \brief Allocate a console tty for the container.
	 *
	 * \param c Container.
	 * \param[in,out] ttynum Terminal number to attempt to allocate,
	 *  or \c -1 to allocate the first available tty.
	 * \param[out] masterfd File descriptor referring to the master side of the pty.
	 *
	 * \return tty file descriptor number on success, or \c -1 on
	 *  failure.
	 *
	 * \note On successful return, \p ttynum will contain the tty number
	 *  that was allocated.
	 * \note The returned file descriptor is used to keep the tty
	 *  allocated. The caller should call close(2) on the returned file
	 *  descriptor when no longer required so that it may be allocated
	 *  by another caller.
	 */
	int (*console_getfd)(struct lxc_container *c, int *ttynum, int *masterfd);

	/*!
	 * \brief Allocate and run a console tty.
	 *
	 * \param c Container.
	 * \param ttynum Terminal number to attempt to allocate, \c -1 to
	 *  allocate the first available tty or \c 0 to allocate the
	 *  console.
	 * \param stdinfd File descriptor to read input from.
	 * \param stdoutfd File descriptor to write output to.
	 * \param stderrfd File descriptor to write error output to.
	 * \param escape The escape character (1 == 'a', 2 == 'b', ...).
	 *
	 * \return \c 0 on success, \c -1 on failure.
	 *
	 * \note This function will not return until the console has been
	 *  exited by the user.
	 */
	int (*console)(struct lxc_container *c, int ttynum,
			int stdinfd, int stdoutfd, int stderrfd, int escape);

	/*!
	 * \brief Create a sub-process attached to a container and run
	 *  a function inside it.
	 *
	 * \param c Container.
	 * \param exec_function Function to run.
	 * \param exec_payload Data to pass to \p exec_function.
	 * \param options \ref lxc_attach_options_t.
	 * \param[out] attached_process Process ID of process running inside
	 *  container \p c that is running \p exec_function.
	 *
	 * \return \c 0 on success, \c -1 on error.
	 */
	int (*attach)(struct lxc_container *c, lxc_attach_exec_t exec_function,
			void *exec_payload, lxc_attach_options_t *options, pid_t *attached_process);

	/*!
	 * \brief Run a program inside a container and wait for it to exit.
	 *
	 * \param c Container.
	 * \param options See \ref attach options.
	 * \param program Full path inside container of program to run.
	 * \param argv Array of arguments to pass to \p program.
	 *
	 * \return \c waitpid(2) status of exited process that ran \p
	 * program, or \c -1 on error.
	 */
	int (*attach_run_wait)(struct lxc_container *c, lxc_attach_options_t *options, const char *program, const char * const argv[]);

	/*!
	 * \brief Run a program inside a container and wait for it to exit (list variant).
	 *
	 * \param c Container.
	 * \param options See \ref attach options.
	 * \param program Full path inside container of program to run.
	 * \param ... Command-line to pass to \p program (must end in \c NULL).
	 *
	 * \return \c waitpid(2) status of exited process that ran \p
	 * program, or \c -1 on error.
	 */
	int (*attach_run_waitl)(struct lxc_container *c, lxc_attach_options_t *options, const char *program, const char *arg, ...);

	/*!
	 * \brief Create a container snapshot.
	 *
	 * Assuming default paths, snapshots will be created as
	 * \c /var/lib/lxc/\<c\>/snaps/snap\<n\>
	 * where \c \<c\> represents the container name and \c \<n\>
	 * represents the zero-based snapshot number.
	 *
	 * \param c Container.
	 * \param commentfile Full path to file containing a description
	 *  of the snapshot.
	 *
	 * \return -1 on error, or zero-based snapshot number.
	 *
	 * \note \p commentfile may be \c NULL but this is discouraged.
	 */
	int (*snapshot)(struct lxc_container *c, const char *commentfile);

	/*!
	 * \brief Obtain a list of container snapshots.
	 *
	 * \param c Container.
	 * \param[out] snapshots Dynamically-allocated Array of lxc_snapshot's.
	 *
	 * \return Number of snapshots.
	 *
	 * \note The array returned in \p snapshots is allocated, so the caller must free it.
	 * \note To free an individual snapshot as returned in \p
	 * snapshots, call the snapshots \c free function (see \c src/tests/snapshot.c for an example).
	 */
	int (*snapshot_list)(struct lxc_container *c, struct lxc_snapshot **snapshots);

	/*!
	 * \brief Create a new container based on a snapshot.
	 *
	 *  The restored container will be a copy (not snapshot) of the snapshot,
	 *  and restored in the lxcpath of the original container.
	 * \param c Container.
	 * \param snapname Name of snapshot.
	 * \param newname Name to be used for the restored snapshot.
	 * \return \c true on success, else \c false.
	 * \warning If \p newname is the same as the current container
	 *  name, the container will be destroyed. However, this will
	 *  fail if the  snapshot is overlay-based, since the snapshots
	 *  will pin the original container.
	 * \note As an example, if the container exists as \c /var/lib/lxc/c1, snapname might be \c 'snap0'
	 *  (representing \c /var/lib/lxc/c1/snaps/snap0). If \p newname is \p c2,
	 *  then \c snap0 will be copied to \c /var/lib/lxc/c2.
	 */
	bool (*snapshot_restore)(struct lxc_container *c, const char *snapname, const char *newname);

	/*!
	 * \brief Destroy the specified snapshot.
	 *
	 * \param c Container.
	 * \param snapname Name of snapshot.
	 *
	 * \return \c true on success, else \c false.
	 */
	bool (*snapshot_destroy)(struct lxc_container *c, const char *snapname);

	/*!
	 * \brief Determine if the caller may control the container.
	 *
	 * \param c Container.
	 *
	 * \return \c false if there is a control socket for the
	 *  container monitor and the caller may not access it, otherwise
	 * returns \c true.
	 */
	bool (*may_control)(struct lxc_container *c);

	/*!
	 * \brief Add specified device to the container.
	 *
	 * \param c Container.
	 * \param src_path Full path of the device.
	 * \param dest_path Alternate path in the container (or \p NULL
	 *  to use \p src_path).
	 *
	 * \return \c true on success, else \c false.
	 */
	bool (*add_device_node)(struct lxc_container *c, const char *src_path, const char *dest_path);

	/*!
	 * \brief Remove specified device from the container.
	 *
	 * \param c Container.
	 * \param src_path Full path of the device.
	 * \param dest_path Alternate path in the container (or \p NULL
	 *  to use \p src_path).
	 *
	 * \return \c true on success, else \c false.
	 */
	bool (*remove_device_node)(struct lxc_container *c, const char *src_path, const char *dest_path);

	/* Post LXC-1.0 additions */

	/*!
	 * \brief Add specified netdev to the container.
	 *
	 * \param c Container.
	 * \param dev name of net device.
	 *
	 * \return \c true on success, else \c false.
	 */
	bool (*attach_interface)(struct lxc_container *c, const char *dev, const char *dst_dev);

	/*!
	 * \brief Remove specified netdev from the container.
	 *
	 * \param c Container.
	 * \param dev name of net device.
	 *
	 * \return \c true on success, else \c false.
	 */
	bool (*detach_interface)(struct lxc_container *c, const char *dev, const char *dst_dev);
	/*!
	 * \brief Checkpoint a container.
	 *
	 * \param c Container.
	 * \param directory The directory to dump the container to.
	 * \param stop Whether or not to stop the container after checkpointing.
	 * \param verbose Enable criu's verbose logs.
	 *
	 * \return \c true on success, else \c false.
	 * present at compile time).
	 */
	bool (*checkpoint)(struct lxc_container *c, char *directory, bool stop, bool verbose);

	/*!
	 * \brief Restore a container from a checkpoint.
	 *
	 * \param c Container.
	 * \param directory The directory to restore the container from.
	 * \param verbose Enable criu's verbose logs.
	 *
	 * \return \c true on success, else \c false.
	 *
	 */
	bool (*restore)(struct lxc_container *c, char *directory, bool verbose);

	/*!
	 * \brief Delete the container and all its snapshots.
	 *
	 * \param c Container.
	 *
	 * \return \c true on success, else \c false.
	 *
	 * \note Container must be stopped.
	 */
	bool (*destroy_with_snapshots)(struct lxc_container *c);

	/*!
	 * \brief Destroy all the container's snapshot.
	 *
	 * \param c Container.
	 *
	 * \return \c true on success, else \c false.
	 */
	bool (*snapshot_destroy_all)(struct lxc_container *c);

	/* Post LXC-1.1 additions */
	/*!
	 * \brief An API call to perform various migration operations
	 *
	 * \param cmd One of the MIGRATE_ contstants.
	 * \param opts A migrate_opts struct filled with relevant options.
	 * \param size The size of the migrate_opts struct, i.e. sizeof(struct migrate_opts).
	 *
	 * \return \c 0 on success, nonzero on failure.
	 */
	int (*migrate)(struct lxc_container *c, unsigned int cmd, struct migrate_opts *opts, unsigned int size);
};

/*!
 * \brief An LXC container snapshot.
 */
struct lxc_snapshot {
	char *name; /*!< Name of snapshot */
	char *comment_pathname; /*!< Full path to snapshots comment file (may be \c NULL) */
	char *timestamp; /*!< Time snapshot was created */
	char *lxcpath; /*!< Full path to LXCPATH for snapshot */

	/*!
	 * \brief De-allocate the snapshot.
	 * \param s snapshot.
	 */
	void (*free)(struct lxc_snapshot *s);
};


/*!
 * \brief Specifications for how to create a new backing store
 */
struct bdev_specs {
	char *fstype; /*!< Filesystem type */
	uint64_t fssize;  /*!< Filesystem size in bytes */
	struct {
		char *zfsroot; /*!< ZFS root path */
	} zfs;
	struct {
		char *vg; /*!< LVM Volume Group name */
		char *lv; /*!< LVM Logical Volume name */
		char *thinpool; /*!< LVM thin pool to use, if any */
	} lvm;
	char *dir; /*!< Directory path */
	struct {
		char *rbdname; /*!< RBD image name */
		char *rbdpool; /*!< Ceph pool name */
	} rbd;
};

/*!
 * \brief Commands for the migrate API call.
 */
enum {
	MIGRATE_PRE_DUMP,
	MIGRATE_DUMP,
	MIGRATE_RESTORE,
};

/*!
 * \brief Options for the migrate API call.
 */
struct migrate_opts {
	/* new members should be added at the end */
	char *directory;
	bool verbose;

	bool stop; /* stop the container after dump? */
	char *predump_dir; /* relative to directory above */
	char *pageserver_address; /* where should memory pages be send? */
	char *pageserver_port;

	/* This flag indicates whether or not the container's rootfs will have
	 * the same inodes on checkpoint and restore. In the case of e.g. zfs
	 * send or btrfs send, or an LVM snapshot, this will be true, but it
	 * won't if e.g. you rsync the filesystems between two machines.
	 */
	bool preserves_inodes;

	/* Path to an executable script that will be registered as a criu
	 * "action script"
	 */
	char *action_script;

	/* If CRIU >= 2.4 is detected the option to skip in-flight connections
	 * will be enabled by default. The flag 'disable_skip_in_flight' will
	 * unconditionally disable this feature. In-flight connections are
	 * not fully established TCP connections: SYN, SYN-ACK */
	bool disable_skip_in_flight;

	/* This is the maximum file size for deleted files (which CRIU calls
	 * "ghost" files) that will be handled. 0 indicates the CRIU default,
	 * which at this time is 1MB.
	 */
	uint64_t ghost_limit;
};

/*!
 * \brief Create a new container.
 *
 * \param name Name to use for container.
 * \param configpath Full path to configuration file to use.
 *
 * \return Newly-allocated container, or \c NULL on error.
 */
struct lxc_container *lxc_container_new(const char *name, const char *configpath);

/*!
 * \brief Add a reference to the specified container.
 *
 * \param c Container.
 *
 * \return \c true on success, \c false on error.
 */
int lxc_container_get(struct lxc_container *c);

/*!
 * \brief Drop a reference to the specified container.
 *
 * \param c Container.
 *
 * \return \c 0 on success, \c 1 if reference was successfully dropped
 * and container has been freed, and \c -1 on error.
 *
 * \warning If \c 1 is returned, \p c is no longer valid.
 */
int lxc_container_put(struct lxc_container *c);

/*!
 * \brief Obtain a list of all container states.
 * \param[out] states Caller-allocated array to hold all states (may be \c NULL).
 *
 * \return Number of container states.
 *
 * \note Passing \c NULL for \p states allows the caller to first
 *  calculate how many states there are before calling the function again, the second time
 *  providing a suitably-sized array to store the static string pointers
 *  in.
 * \note The \p states array should be freed by the caller, but not the strings the elements point to.
 */
int lxc_get_wait_states(const char **states);

/*!
 * \brief Get the value for a global config key
 *
 * \param key The name of the config key
 *
 * \return String representing the current value for the key.
 */
const char *lxc_get_global_config_item(const char *key);

/*!
 * \brief Determine version of LXC.
 * \return Static string representing version of LXC in use.
 *
 * \note Returned string must not be freed.
 */
const char *lxc_get_version(void);

/*!
 * \brief Get a list of defined containers in a lxcpath.
 *
 * \param lxcpath lxcpath under which to look.
 * \param names If not \c NULL, then a list of container names will be returned here.
 * \param cret If not \c NULL, then a list of lxc_containers will be returned here.
 *
 * \return Number of containers found, or \c -1 on error.
 *
 * \note Values returned in \p cret are sorted by container name.
 */
int list_defined_containers(const char *lxcpath, char ***names, struct lxc_container ***cret);

/*!
 * \brief Get a list of active containers for a given lxcpath.
 *
 * \param lxcpath Full \c LXCPATH path to consider.
 * \param[out] names Dynamically-allocated array of container names.
 * \param[out] cret Dynamically-allocated list of containers.
 *
 * \return Number of containers found, or -1 on error.
 *
 * \note Some of the containers may not be "defined".
 * \note Values returned in \p cret are sorted by container name.
 * \note \p names and \p cret may both (or either) be specified as \c NULL.
 * \note \p names and \p cret must be freed by the caller.
 */
int list_active_containers(const char *lxcpath, char ***names, struct lxc_container ***cret);

/*!
 * \brief Get a complete list of all containers for a given lxcpath.
 *
 * \param lxcpath Full \c LXCPATH path to consider.
 * \param[out] names Dynamically-allocated array of container name.
 * \param[out] cret Dynamically-allocated list of containers.
 *
 * \return Number of containers, or -1 on error.
 *
 * \note Some of the containers may not be "defined".
 * \note Values returned in \p cret are sorted by container name.
 * \note \p names and \p cret may both (or either) be specified as \c NULL.
 * \note \p names and \p cret must be freed by the caller.
 */
int list_all_containers(const char *lxcpath, char ***names, struct lxc_container ***cret);

/*!
 * \brief Close log file.
 */
void lxc_log_close(void);

#ifdef  __cplusplus
}
#endif

#endif
