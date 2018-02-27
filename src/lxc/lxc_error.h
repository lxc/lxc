#ifndef __LXC_ERRORS_H
#define __LXC_ERRORS_H

/* Overview 
 *
 * 1. Error codes defined based on grepping for "error" in tools/
 *
 * 2. lxc_error_dump() has intelligence to know when/if to dump errors and concat,
 *    or just concatenate, thus only needing to add one lxc_error_dump call per
 *    error to capture, and all that needs to be known is what type of error it is.
 *
 * 3. lxc_error_concat() is called by lxc_error_dump and has logic for appropriately
 *    concatenating past/new error strings. Used '~' as delimiter since it's the least
 *    used ASCII character, reduces need for escaping. If not sufficient can use, "~~" :)
 *
 * 4. lxc_error_handle() can be called to look at the most recent error_num and run
 *    some code to "handle" it in some way, then return success/failure
 *
 * 5. main() and test_dump() are only there for testing at this point, it will be removed
 *
 * Example:
 *   if (something_did_not_work) {
 *     char *lxc_error = "<some-error>";
 *     SYSERROR("%s", lxc_error);
 *     lxc_error_dump(c, lxc_error, <LXC_ERROR_CODE>);
 *   }
 *
 * Issues:
 * 1. Can only store errors where a struct lxc_container *c is accessible, this
 *    means lots of liblxc files cannot use this. How to resolve this/is this a
 *    problem? Shouldn't the container try to handle errors from functions it can't
 *    see inside of?
 *
 * 2. Would like to be able to identify which file the error occurred in. i.e.
 *    "lxc_attach: Out of memory", but not sure how to do it (aside from manually).
 *    Trying to figure out a way to use my_args.progname, but any other suggestions
 *    welcome.
 *
 * 3. Need a better ordering for macros, and way to determine which are considered
 *    leaf vs non-leaf
 *
 * 4. Need to figure out how/which errors should/can be handled/ignored.
 *
 * 5. Incorporate into Makefile and build, handle dependencies and decide #includes
 *
 * 6. 3 memory leaks from lxc_error_concat
 *
 */

// These should be organized in a way that makes more sense

// lxc_copy.c:518:		ERROR("Error: Renaming container %s to %s failed\n", c->name, newname);
// lxc_unshare.c:248:		ERROR("failed to clone");
#define LXC_CLONE_ERR 1 

// lxc_copy.c:866:		SYSERROR("Failed to set close-on-exec on file descriptor.");
#define LXC_FD_ERR 2

// TODO lxc_create.c:127:	ERROR("Error executing %s -h", path);
// lxc_init.c:210:		ERROR("%s - Failed to exec \"%s\"", strerror(errno), my_args.argv[0]);
// lxc_unshare.c:134:	ERROR("failed to exec: '%s': %s", args[0], strerror(errno));
#define LXC_EXEC_ERR 3

// lxc_create.c:329:		ERROR("Error creating container %s", c->name);
// lxc_execute.c:149:		ERROR("Failed to create lxc_container");
// lxc_start.c:215:			ERROR("Failed to create lxc_container");
// lxc_start.c:246:			ERROR("Failed to create lxc_container");
#define LXC_CREATE_ERR 4

// maybe combined with OOM, idk what else can go wrong with calloc
// lxc_destroy.c:236:			SYSERROR("failed to allocate memory");
// lxc_monitor.c:144:		ERROR("failed to allocate memory");
// lxc_top.c:540:			ERROR("cannot alloc mem");
// lxc_top.c:546:				ERROR("cannot alloc mem");
// lxc_start.c:234:			SYSERROR("failed to allocate memory");
#define LXC_MEM_ALLOC_ERR 5

// lxc_destroy.c:243:			ERROR("could not read %s", path);
#define LXC_FILE_READ_ERR 6

// lxc_device.c:68:		SYSERROR("failed to fork task.");
#define LXC_FORK_ERR 7

// lxc_device.c:76:			ERROR("failed to enter netns of container.");
#define LXC_NS_ERR 8

// lxc_device.c:82:			ERROR("failed to get interfaces list");
#define LXC_NETIF_ERR 9

// lxc_device.c:109:		ERROR("%s must be run as root", argv[0]);
// lxc_freeze.c:104:		ERROR("Insufficent privileges to control %s:%s", my_args.lxcpath[0], my_args.name);
// lxc_unfreeze.c:88:		ERROR("Insufficent privileges to control %s:%s", my_args.lxcpath[0], my_args.name);
#define LXC_INSUF_PRIV_ERR 10

// lxc_device.c:135:		ERROR("%s doesn't exist", my_args.name);
// lxc_freeze.c:84:		ERROR("No such container: %s:%s", my_args.lxcpath[0], my_args.name);
// lxc_unfreeze.c:83:		ERROR("No such container: %s:%s", my_args.lxcpath[0], my_args.name);
#define LXC_CONT_EXIST_ERR 11

// lxc_device.c:142:			ERROR("Failed to load rcfile");
// lxc_execute.c:156:			ERROR("Failed to load rcfile");
// lxc_freeze.c:91:			ERROR("Failed to load rcfile");
// lxc_start.c:220:			ERROR("Failed to load rcfile");
// lxc_unfreeze.c:96:			ERROR("Failed to load rcfile");
#define LXC_RCFILE_ERR 12

// lxc_device.c:147:			ERROR("Out of memory setting new config filename");
// lxc_execute.c:162:			ERROR("Out of memory setting new config filename");
// lxc_freeze.c:97:			ERROR("Out of memory setting new config filename");
// lxc_monitor.c:160:		SYSERROR("out of memory");
// lxc_start.c:226:			ERROR("Out of memory setting new config filename");
// lxc_unfreeze.c:102:			ERROR("Out of memory setting new config filename");
#define LXC_OOM_ERR 13

// lxc_device.c:176:			ERROR("Failed to add %s to %s.", dev_name, c->name);
// lxc_device.c:187:			ERROR("Failed to del %s from %s.", dev_name, c->name);
#define LXC_DEVICE_ERR 14

// lxc_device.c:153:		ERROR("Container %s is not running.", c->name);
// lxc_device.c:158:		ERROR("Error: no command given (Please see --help output)");
// lxc_device.c:192:		ERROR("Error: Please use add or del (Please see --help output)");
// lxc_execute.c:170:			ERROR("missing command to execute!");
// lxc_init.c:102:		ERROR("Please specify a command to execute");
// lxc_monitor.c:149:		ERROR("Name too long");
// lxc_monitor.c:154:		ERROR("failed to compile the regex '%s'", my_args.name);
// lxc_start.c:279:		ERROR("Executing '/sbin/init' with no configuration file may crash the host");
// lxc_start.c:285:			ERROR("failed to ensure pidfile '%s'", my_args.pidfile);
// lxc_start.c:263:		ERROR("Container is already running.");
// lxc_unshare.c:84:			ERROR("invalid username %s", name);
// lxc_unshare.c:91:			ERROR("invalid uid %u", *uid);
// lxc_unshare.c:192:		ERROR("a command to execute in the new namespace is required");
// lxc_unshare.c:232:		ERROR("-i <interfacename> needs -s NETWORK option");
// lxc_unshare.c:237:		ERROR("-H <hostname> needs -s UTSNAME option");
// lxc_unshare.c:242:		ERROR("-M needs -s MOUNT option");
#define LXC_ARGS_INVAL 15

// lxc_execute.c:193:		ERROR("Failed run an application inside container");
#define LXC_APP_ERR 16

// lxc_freeze.c:110:		ERROR("Failed to freeze %s:%s", my_args.lxcpath[0], my_args.name);
#define LXC_FREEZE_ERR 17

// lxc_init.c:171:			SYSERROR("Failed to change signal action");
#define LXC_SIGACTION_ERR 18

// lxc_init.c:196:			SYSERROR("Failed to set signal mask");
// lxc_init.c:224:		SYSERROR("Failed to set signal mask");
#define LXC_SIGMSK_ERR 19

// lxc_init.c:274:			ERROR("%s - Failed to wait on child %d",
// lxc_unshare.c:263:		ERROR("failed to wait for '%d'", pid);
#define LXC_WAIT_ERR 20

// lxc_monitor.c:126:				ERROR("Unable to open monitor on path: %s", my_args.lxcpath[i]);
// lxc_monitor.c:131:				SYSERROR("Unable to close monitor on path: %s", my_args.lxcpath[i]);
#define LXC_MONITOR_ERR 21

// lxc_snapshot.c:211:		ERROR("Error creating a snapshot");
// lxc_snapshot.c:230:		ERROR("Error destroying snapshot %s", snapname);
// lxc_snapshot.c:244:		ERROR("Error listing snapshots");
// lxc_snapshot.c:284:		ERROR("Error restoring snapshot %s", args->snapname);
#define LXC_SNAPSHOT_ERR 22

// lxc_start.c:71:				SYSERROR("failed to create '%s'", path);
// lxc_start.c:80:			SYSERROR("failed to get the real path of '%s'", path);
#define LXC_PATH_ERR 23

// lxc_start.c:325:		ERROR("The container failed to start.");
#define LXC_START_ERR 24

// lxc_top.c:152:		ERROR("stdin is not a tty");
// lxc_top.c:171:		ERROR("failed to set new terminal settings");
// lxc_top.c:566:		ERROR("failed to setup terminal");
// lxc_top.c:576:		ERROR("failed to create mainloop");
// lxc_top.c:582:		ERROR("failed to add stdin handler");
// lxc_top.c:157:		SYSERROR("failed to get current terminal settings");
#define LXC_TOP_ERR 25

// lxc_top.c:236:		ERROR("unable to read cgroup item %s", item);
// lxc_top.c:255:		ERROR("unable to read cgroup item %s", item);
// lxc_top.c:311:		ERROR("unable to read cgroup item %s", item);
#define LXC_READ_CGROUP_ERR 26

// lxc_unfreeze.c:109:		ERROR("Failed to unfreeze %s:%s", my_args.lxcpath[0], my_args.name);
#define LXC_UNFREEZE_ERR 27

// lxc_unshare.c:128:		ERROR("failed to set uid %d: %s", uid, strerror(errno));
#define LXC_UID_ERR 28

// lxc_unshare.c:122:			ERROR("failed to set hostname %s: %s", want_hostname, strerror(errno));
#define LXC_HOSTNAME_ERR 29

// MISC: used as printf
// lxc_start.c:327:			ERROR("To get more details, run the container in foreground mode.");
// lxc_start.c:328:		ERROR("Additional information can be obtained by setting the "

/* temporary placeholder for testing */
struct lxc_container {
  char *name;
  char *error_string;
  int error_num;
  /* other fun stuff */
}; 

extern void *lxc_error_concat(struct lxc_container *c, char *lxc_error, int LXC_ERROR_CODE);
extern void lxc_error_dump(struct lxc_container *c, char *lxc_error, int LXC_ERROR_CODE);
extern int lxc_error_handle(struct lxc_container *c);
extern void test_dump(struct lxc_container *c);

#endif /* __LXC_ERRORS_H */
