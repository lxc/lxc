/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Daniel Lezcano <dlezcano at fr.ibm.com>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
#ifndef __lxc_h
#define __lxc_h

/**
 Following code is for liblxc.

 liblxc/lxc.h will contain exports of liblxc
 **/

#define LXCPATH "/var/lxc"
#define MAXPIDLEN 20

struct lxc_mem_stat;
struct lxc_conf;

typedef enum {
	STOPPED, STARTING, RUNNING, STOPPING,
	ABORTING, FREEZING, FROZEN, MAX_STATE,
} lxc_state_t;

typedef int (*lxc_callback_t)(const char *name, int argc, 
			      char *argv[], void *data);

/*
 * Create the container object. Creates the /lxc/<name> directory
 * and fills it with the files corresponding to the configuration
 * structure passed as parameter.
 * The first container will create the /lxc directory.
 * @name : the name of the container
 * @conf : the configuration data for the container
 * Returns 0 on success, < 0 otherwise
 */
extern int lxc_create(const char *name, struct lxc_conf *conf);

/*
 * Destroy the container object. Removes the files into the /lxc/<name>
 * directory and removes the <name> directory.
 * The last container will remove the /lxc directory.
 * @name : the name of the container to be detroyed
 * Returns 0 on success, < 0 otherwise
 */
extern int lxc_destroy(const char *name);

/*
 * Start the container previously created with lxc_create.
 * @name     : the name of the container
 * @argc     : the number of arguments of the command line
 * @argv     : an array of char * corresponding to the commande line
 * @prestart : hooks will be called just before the command execs
 * Returns 0 on sucess, < 0 otherwise
 */
extern int lxc_start(const char *name, int argc, char *argv[], 
		     lxc_callback_t prestart, void *data);

/*
 * Create the container and start it directly, using the argc, argv 
 * parameter. This command is for application container.
 * At the end of the exec'ed command, the container will
 * automatically autodestroy.
 * @name    : the name of the container
 * @conf    : the configuration data
 * @argc    : the number of arguments of the command line
 * @argv    : an array of char * corresponding to the commande line
 * @preexec : hooks will be called just before the command execs
 * Returns 0 on success, < 0 otherwise
 */
extern int lxc_execute(const char *name, int argc, char *argv[], 
		       lxc_callback_t preexec, void *data);

/*
 * Stop the container previously started with lxc_start or lxc_exec
 * @name : the name of the container
 * Returns 0 on success, < 0 otherwise
 */
extern int lxc_stop(const char *name);

/*
 * Monitor the container, each time the state of the container
 * is changed, a state data is send through a file descriptor passed to
 * the function with output_fd.
 * The function will block until the container is destroyed.
 * @name : the name of the contaier
 * @output_fd : the file descriptor where to send the states
 * Returns 0 on success, < 0 otherwise
 */
extern int lxc_monitor(const char *name, int output_fd);

/*
 * Show the console of the container.
 * @name : the name of container
 * Returns 0 on sucess, < 0 otherwise
 */
extern int lxc_console(const char *name);

/*
 * Freeze all the tasks running inside the container <name>
 * @name : the container name
 * Returns 0 on success, < 0 otherwise
 */
extern int lxc_freeze(const char *name);

/*
 * Unfreeze all previously frozen tasks.
 * @name : the name of the container
 * Return 0 on sucess, < 0 otherwise
 */
extern int lxc_unfreeze(const char *name);

/*
 * Retrieve the container state
 * @name : the name of the container
 * Returns the state of the container on success, < 0 otherwise
 */
extern lxc_state_t lxc_state(const char *name);

/*
 * Send a signal to all processes of the container. This is the same
 * behavior of the well-known 'killpg' command except it is related
 * to all tasks belonging to a container.
 * @name   : the name of the container
 * @signum : the signal number to be sent
 * Returns 0 on success, < 0 otherwise
 */
extern int lxc_kill(const char *name, int signum);

/*
 * Change the priority of the container
 * @name     : the name of the container
 * @priority : an integer representing the desired priority
 * Returns 0 on success, < 0 otherwise
 */
extern int lxc_cgroup_set_priority(const char *name, int priority);

/*
 * Retrieve the priority of the container
 * @name     : the name of the container
 * @priority : a pointer to an int where the priority will be stored
 * Returns 0 on success, < 0 otherwise
 */
extern int lxc_cgroup_get_priority(const char *name, int *priority);

/*
 * Set the maximum memory usable by the container
 * @name   : the name of the container
 * @memmax : the maximum usable memory in bytes
 * Returns 0 on sucess, < 0 otherwise
 */
extern int lxc_cgroup_set_memory(const char *name, size_t memmax);

/*
 * Get the maximum memory usable by the container
 * @name : the name of the container
 * @memmax : a pointer to a size_t where the value will be stored
 * Returns 0 on sucess, < 0 otherwise
 */
extern int lxc_cgroup_get_memory(const char *name, size_t *memmax);

/*
 * Get the memory statistics of the container
 * @name    : the name of the container
 * @memstat : a pointer to a structure defining the memory statistic
 * Returns 0 on sucess, < 0 otherwise
 */
extern int lxc_cgroup_get_memstat(const char *name, 
				  struct lxc_mem_stat *memstat);

/*
 * Set the cpuset for the container
 * @name    : the name of the container
 * @cpumask : a bitmask representing the cpu maps
 * @len     : the len of the bitmask
 * @shared  : a boolean specifying if the cpu could be shared with
 *            processes not belonging to the container
 * Returns 0 on sucess, < 0 otherwise
 */
extern int lxc_cgroup_set_cpuset(const char *name, long *cpumask, 
				 int len, int shared);

/*
 * Get the actual cpuset for the container
 * @cpumask : a bitmask representing the cpu maps
 * @len     : the len of the bitmask
 * @shared  : a boolean specifying if the cpu is shared with
 *            processes not belonging to the container
 * Returns 0 on sucess, < 0 otherwise
 */
extern int lxc_cgroup_get_cpuset(const char *name, long *cpumask, 
				 int len, int *shared);

/*
 * Get the cpu usage of the container
 * @name  : the name of the container
 * @usage : a value to be filled with the current container cpu usage
 * Returns 0 on sucess, < 0 otherwise
 */
extern int lxc_cgroup_get_cpu_usage(const char *name, long long *usage);

#endif
