LXC Coding Style Guide
======================

In general the LXC project follows the Linux kernel coding style.  However,
there are a few differences. They are outlined in this document.

The Linux kernel coding style guide can be found within the kernel tree:

	Documentation/process/coding-style.rst

It can be accessed online too:

https://www.kernel.org/doc/html/latest/process/coding-style.html

## 1) General Notes

- The coding style guide refers to new code. But legacy code can be cleaned up
  and we are happy to take those patches.
- Just because there is still code in LXC that doesn't adhere to the coding
  standards outlined here does not license not adhering to the coding style. In
  other words: please stick to the coding style.
- Maintainers are free to ignore rules specified here when merging pull
  requests. This guideline might seem a little weird but it exits to ease new
  developers into the code base and to prevent unnecessary bikeshedding. If
  a maintainer feels hat enforcing a specific rule in a given commit would do
  more harm than good they should always feel free to ignore the rule.

  Furthermore, when merging pull requests that do not adhere to our coding
  style maintainers should feel free to grab the commit, adapt it to our coding
  style and add their Signed-off-by line to it. This is especially helpful to
  make it easier for first-time contributors and to prevent having pull
  requests being stuck in the merge queue because of minor details.
- We currently do not provide automatic coding style checks but if a suitable
  tool is found we are happy to integrate it into our test suite. It is
  possible and recommended to use the `clang-format` binary to check your code.
  The following options are an approximation of the coding style used here.
  Simply create a file called `.clang-format` in your home directory with the
  following options:
  ```sh
  cat << EOF > "${HOME}"/.clang-format
  AlignEscapedNewlines: Left
  BreakBeforeBraces: Attach
  AlwaysBreakBeforeMultilineStrings: false
  BreakBeforeBinaryOperators: None
  MaxEmptyLinesToKeep: 1
  PenaltyBreakBeforeFirstCallParameter: 1000000
  BinPackArguments: true
  BinPackParameters: true
  AllowAllParametersOfDeclarationOnNextLine: false
  AlignAfterOpenBracket: true
  SpacesInSquareBrackets: false
  SpacesInCStyleCastParentheses: false
  SpaceInEmptyParentheses: false
  SpaceBeforeParens: ControlStatements
  SpaceAfterCStyleCast: false
  SortIncludes: true
  PenaltyReturnTypeOnItsOwnLine: 10000
  PenaltyExcessCharacter: 10
  Language: Cpp
  ForEachMacros: ['lxc_list_for_each', 'lxc_list_for_each_safe']
  AllowShortLoopsOnASingleLine: false
  AllowShortIfStatementsOnASingleLine: false
  AllowShortFunctionsOnASingleLine: None
  AllowShortCaseLabelsOnASingleLine: false
  AllowShortBlocksOnASingleLine: false
  BasedOnStyle: LLVM
  TabWidth: 8
  IndentWidth: 8
  UseTab: Always
  BreakBeforeBraces: Linux
  AllowShortIfStatementsOnASingleLine: false
  IndentCaseLabels: false
  EOF
  ```
  However, it will not handle all cases correctly. For example, most `struct`
  initializations will not be correct. In such cases please refer to the coding
  style here.

## 2) Only Use Tabs

- LXC uses tabs.

## 3) Only use `/* */` Style Comments

- Any comments that are added must use `/* */`.
- Single-line comments should start on the same line as the opening `/*`.
- Single-line comments should simply be placed between `/* */`. For example:
  ```C
  /* Define pivot_root() if missing from the C library */
  ```
- Mutli-line comment should start on the next line following the opening
  `/*`and should end with the closing `*/` on a separate line. For
  example:
  ```C
  /*
   * At this point the old-root is mounted on top of our new-root
   * To unmounted it we must not be chdir()ed into it, so escape back
   * to old-root.
   */
  ```

## 4) Try To Wrap At 80chars

- This is not strictly enforced. It is perfectly valid to sometimes
  overflow this limit if it helps clarity. Nonetheless, try to stick to it
  and use common sense to decide when not to.

## 5) Error Messages

- Error messages must start with a capital letter and must **not** end with a
  punctuation sign.
- They should be descriptive, without being needlessly long. It is best to just
  use already existing error messages as examples.
- The commit message itself is not subject to rule 4), i.e. it should not be
  wrapped at 80chars. This is to make it easy to grep for it.
- Examples of acceptable error messages are:
  ```C
  SYSERROR("Failed to create directory \"%s\"", path);
  WARN("\"/dev\" directory does not exist. Proceeding without autodev being set up");
  ```

## 6) Set `errno`

- Functions that can fail in a non-binary way should return `-1` and set
  `errno` to a meaningful error code.
  As a convenience LXC provides the `minus_one_set_errno` macro:
  ```C
  static int set_config_net_l2proxy(const char *key, const char *value,
                                    struct lxc_conf *lxc_conf, void *data)
  {
          struct lxc_netdev *netdev = data;
          unsigned int val = 0;
          int ret;

          if (lxc_config_value_empty(value))
                  return clr_config_net_l2proxy(key, lxc_conf, data);

          if (!netdev)
                  return minus_one_set_errno(EINVAL);

          ret = lxc_safe_uint(value, &val);
          if (ret < 0)
                  return minus_one_set_errno(-ret);

          switch (val) {
          case 0:
                  netdev->l2proxy = false;
                  return 0;
          case 1:
                  netdev->l2proxy = true;
                  return 0;
          }

          return minus_one_set_errno(EINVAL);
  }
  ```

## 7) All Unexported Functions Must Be Declared `static`

- Functions which are only used in the current file and are not exported
  within the codebase need to be declared with the `static` attribute.

## 8) All Exported Functions Must Be Declared `extern` In A Header File

- Functions declared in header files (`*.h`) should use the `extern` keyword.
- Functions declared in source files (`*.c`) should not use the `extern` keyword.

## 9) Declaring Variables

- variables should be declared at the top of the function or at the beginning
  of a new scope but **never** in the middle of a scope. They should be ordered
  in the following way:
1. automatically freed variables
   - This specifically references variables cleaned up via the `cleanup`
     attribute as supported by `gcc` and `clang`.
2. initialized variables
3. uninitialized variables
General rules are:
- put base types before complex types
- put standard types defined by libc before types defined by LXC
- put multiple declarations of the same type on the same line
- Examples of good declarations can be seen in the following function:
  ```C
  int lxc_clear_procs(struct lxc_conf *c, const char *key)
  {
          struct lxc_list *it, *next;
          bool all = false;
          const char *k = NULL;

          if (strcmp(key, "lxc.proc") == 0)
                  all = true;
          else if (strncmp(key, "lxc.proc.", sizeof("lxc.proc.") - 1) == 0)
                  k = key + sizeof("lxc.proc.") - 1;
          else
                  return -1;

          lxc_list_for_each_safe(it, &c->procs, next) {
                  struct lxc_proc *proc = it->elem;

                  if (!all && strcmp(proc->filename, k) != 0)
                          continue;
                  lxc_list_del(it);
                  free(proc->filename);
                  free(proc->value);
                  free(proc);
                  free(it);
          }

          return 0;
  }
    ```

## 10) Functions Not Returning Booleans Must Assign Return Value Before Performing Checks

- When checking whether a function not returning booleans was successful or not
  the returned value must be assigned before it is checked (`str{n}cmp()`
  functions being one notable exception). For example:
  ```C
  /* assign value to "ret" first */
  ret = mount(sourcepath, cgpath, "cgroup", remount_flags, NULL);
  /* check whether function was successful */
  if (ret < 0) {
          SYSERROR("Failed to remount \"%s\" ro", cgpath);
          free(sourcepath);
          return -1;
  }
  ```
  Functions returning booleans can be checked directly. For example:
  ```C
  extern bool lxc_string_in_array(const char *needle, const char **haystack);

  /* check right away */
  if (lxc_string_in_array("ns", (const char **)h->subsystems))
          continue;
  ```

## 11) Non-Boolean Functions That Behave Like Boolean Functions Must Explicitly Check Against A Value

- This rule mainly exists for `str{n}cmp()` type functions. In most cases they
  are used like a boolean function to check whether a string matches or not.
  But they return an integer. It is perfectly fine to check `str{n}cmp()`
  functions directly but you must compare explicitly against a value. That is
  to say, while they are conceptually boolean functions they shouldn't be
  treated as such since they don't really behave like boolean functions. So
  `if (!str{n}cmp())` and `if (str{n}cmp())` checks must not be used. Good
  examples are found in the following functions:
  ```C
  static int set_config_hooks(const char *key, const char *value,
                              struct lxc_conf *lxc_conf, void *data)

          char *copy;

          if (lxc_config_value_empty(value))
                  return lxc_clear_hooks(lxc_conf, key);

          if (strcmp(key + 4, "hook") == 0) {
                  ERROR("lxc.hook must not have a value");
                  return -1;
          }

          copy = strdup(value);
          if (!copy)
                  return -1;

          if (strcmp(key + 9, "pre-start") == 0)
                  return add_hook(lxc_conf, LXCHOOK_PRESTART, copy);
          else if (strcmp(key + 9, "start-host") == 0)
                  return add_hook(lxc_conf, LXCHOOK_START_HOST, copy);
          else if (strcmp(key + 9, "pre-mount") == 0)
                  return add_hook(lxc_conf, LXCHOOK_PREMOUNT, copy);
          else if (strcmp(key + 9, "autodev") == 0)
                  return add_hook(lxc_conf, LXCHOOK_AUTODEV, copy);
          else if (strcmp(key + 9, "mount") == 0)
                  return add_hook(lxc_conf, LXCHOOK_MOUNT, copy);
          else if (strcmp(key + 9, "start") == 0)
                  return add_hook(lxc_conf, LXCHOOK_START, copy);
          else if (strcmp(key + 9, "stop") == 0)
                  return add_hook(lxc_conf, LXCHOOK_STOP, copy);
          else if (strcmp(key + 9, "post-stop") == 0)
                  return add_hook(lxc_conf, LXCHOOK_POSTSTOP, copy);
          else if (strcmp(key + 9, "clone") == 0)
                  return add_hook(lxc_conf, LXCHOOK_CLONE, copy);
          else if (strcmp(key + 9, "destroy") == 0)
                  return add_hook(lxc_conf, LXCHOOK_DESTROY, copy);

          free(copy);
          return -1;
  }
  ```

## 12) Do Not Use C99 Variable Length Arrays (VLA)

- They are made optional and there is no guarantee that future C standards
  will support them.

## 13) Use Standard libc Macros When Exiting

- libc provides `EXIT_FAILURE` and `EXIT_SUCCESS`. Use them whenever possible
  in the child of `fork()`ed process or when exiting from a `main()` function.

## 14) Use `goto`s

`goto`s are an essential language construct of C and are perfect to perform
cleanup operations or simplify the logic of functions. However, here are the
rules to use them:
- use descriptive `goto` labels.
  For example, if you know that this label is only used as an error path you
  should use something like `on_error` instead of `out` as label name.
- **only** jump downwards unless you are handling `EAGAIN` errors and want to
  avoid `do-while` constructs.
- An example of a good usage of `goto` is:
  ```C
  static int set_config_idmaps(const char *key, const char *value,
                             struct lxc_conf *lxc_conf, void *data)
  {
          unsigned long hostid, nsid, range;
          char type;
          int ret;
          struct lxc_list *idmaplist = NULL;
          struct id_map *idmap = NULL;

          if (lxc_config_value_empty(value))
                  return lxc_clear_idmaps(lxc_conf);

          idmaplist = malloc(sizeof(*idmaplist));
          if (!idmaplist)
                  goto on_error;

          idmap = malloc(sizeof(*idmap));
          if (!idmap)
                  goto on_error;
          memset(idmap, 0, sizeof(*idmap));

          ret = parse_idmaps(value, &type, &nsid, &hostid, &range);
          if (ret < 0) {
                  ERROR("Failed to parse id mappings");
                  goto on_error;
          }

          INFO("Read uid map: type %c nsid %lu hostid %lu range %lu", type, nsid, hostid, range);
          if (type == 'u')
                  idmap->idtype = ID_TYPE_UID;
          else if (type == 'g')
                  idmap->idtype = ID_TYPE_GID;
          else
                  goto on_error;

          idmap->hostid = hostid;
          idmap->nsid = nsid;
          idmap->range = range;
          idmaplist->elem = idmap;
          lxc_list_add_tail(&lxc_conf->id_map, idmaplist);

          if (!lxc_conf->root_nsuid_map && idmap->idtype == ID_TYPE_UID)
                  if (idmap->nsid == 0)
                          lxc_conf->root_nsuid_map = idmap;


          if (!lxc_conf->root_nsgid_map && idmap->idtype == ID_TYPE_GID)
                  if (idmap->nsid == 0)
                          lxc_conf->root_nsgid_map = idmap;

          idmap = NULL;

          return 0;

  on_error:
          free(idmaplist);
          free(idmap);

          return -1;
  }
  ```

## 15) Use Booleans instead of integers

- When something can be conceptualized in a binary way use a boolean not
  an integer.

## 16) Cleanup Functions Must Handle The Object's Null Type And Being Passed Already Cleaned Up Objects

- If you implement a custom cleanup function to e.g. free a complex type
  you declared you must ensure that the object's null type is handled and
  treated as a NOOP. For example:
  ```C
  void lxc_free_array(void **array, lxc_free_fn element_free_fn)
  {
          void **p;
          for (p = array; p && *p; p++)
                  element_free_fn(*p);
          free((void*)array);
  }
  ```
- Cleanup functions should also expect to be passed already cleaned up objects.
  One way to handle this cleanly is to initialize the cleaned up variable to
  a special value that signals the function that the element has already been
  freed on the next call. For example, the following function cleans up file
  descriptors and sets the already closed file descriptors to `-EBADF`. On the
  next call it can simply check whether the file descriptor is positive and
  move on if it isn't:
  ```C
  static void lxc_put_attach_clone_payload(struct attach_clone_payload *p)
  {
          if (p->ipc_socket >= 0) {
                  shutdown(p->ipc_socket, SHUT_RDWR);
                  close(p->ipc_socket);
                  p->ipc_socket = -EBADF;
          }

          if (p->pty_fd >= 0) {
                  close(p->pty_fd);
                  p->pty_fd = -EBADF;
          }

          if (p->init_ctx) {
                  lxc_proc_put_context_info(p->init_ctx);
                  p->init_ctx = NULL;
          }
  }
  ```

## 17) Cast to `(void)` When Intentionally Ignoring Return Values

- There are cases where you do not care about the return value of a function.
  Please cast the return value to `(void)` when doing so.
- Standard library functions or functions which are known to be ignored by
  default do not need to be cast to `(void)`. Classical candidates are
  `close()` and `fclose()`.
- A good example is:
  ```C
  for (i = 0; hierarchies[i]; i++) {
          char *fullpath;
          char *path = hierarchies[i]->fullcgpath;

          ret = chowmod(path, destuid, nsgid, 0755);
          if (ret < 0)
                  return -1;

          /* failures to chown() these are inconvenient but not
           * detrimental we leave these owned by the container launcher,
           * so that container root can write to the files to attach.  we
           * chmod() them 664 so that container systemd can write to the
           * files (which systemd in wily insists on doing).
           */

          if (hierarchies[i]->version == cgroup_super_magic) {
                  fullpath = must_make_path(path, "tasks", null);
                  (void)chowmod(fullpath, destuid, nsgid, 0664);
                  free(fullpath);
          }

          fullpath = must_make_path(path, "cgroup.procs", null);
          (void)chowmod(fullpath, destuid, 0, 0664);
          free(fullpath);

          if (hierarchies[i]->version != cgroup2_super_magic)
                  continue;

          fullpath = must_make_path(path, "cgroup.subtree_control", null);
          (void)chowmod(fullpath, destuid, nsgid, 0664);
          free(fullpath);

          fullpath = must_make_path(path, "cgroup.threads", null);
          (void)chowmod(fullpath, destuid, nsgid, 0664);
          free(fullpath);
  }
  ```

## 18) Use `for (;;)` instead of `while (1)` or `while (true)`

- Let's be honest, it is really the only sensible way to do this.

## 19) Use The Set Of Supported DCO Statements

- Signed-off-by: Random J Developer <random@developer.org>
  - You did write this code or have the right to contribute it to LXC.
- Acked-by: Random J Developer <random@developer.org>
  - You did read the code and think it is correct. This is usually only used by
    maintainers or developers that have made significant contributions and can
    vouch for the correctness of someone else's code.
- Reviewed-by: Random J Developer <random@developer.org>
  - You did review the code and vouch for its correctness, i.e. you'd be
    prepared to fix bugs it might cause. This is usually only used by
    maintainers or developers that have made significant contributions and can
    vouch for the correctness of someone else's code.
- Co-developed-by: Random J Developer <random@developer.org>
  - The code can not be reasonably attributed to a single developer, i.e.
    you worked on this together.
- Tested-by: Random J Developer <random@developer.org>
  - You verified that the code fixes a given bug or is behaving as advertised.
- Reported-by: Random J Developer <random@developer.org>
  - You found and reported the bug.
- Suggested-by: Random J Developer <random@developer.org>
  - You wrote the code but someone contributed the idea. This line is usually
    overlooked but it is a sign of good etiquette and coding ethics: if someone
    helped you solve a problem or had a clever idea do not silently claim it by
    slapping your Signed-off-by underneath. Be honest and add a Suggested-by.

## 20) Commit Message Outline

- You **must** stick to the 80chars limit especially in the title of the commit
  message.
- Please use English commit messages only.
- use meaningful commit messages.
- Use correct spelling and grammar.
  If you are not a native speaker and/or feel yourself struggling with this it
  is perfectly fine to point this out and there's no need to apologize. Usually
  developers will be happy to pull your branch and adopt the commit message.
- Please always use the affected file (without the file type suffix) or module
  as a prefix in the commit message.
- Examples of good commit messages are:
  ```Diff
  commit b87243830e3b5e95fa31a17cf1bfebe55353bf13
  Author: Felix Abecassis <fabecassis@nvidia.com>
  Date:   Fri Feb 2 06:19:13 2018 -0800

      hooks: change the semantic of NVIDIA_VISIBLE_DEVICES=""

      With LXC, you can override the value of an environment variable to
      null, but you can't unset an existing variable.

      The NVIDIA hook was previously activated when NVIDIA_VISIBLE_DEVICES
      was set to null. As a result, it was not possible to disable the hook
      by overriding the environment variable in the configuration.

      The hook can now be disabled by setting NVIDIA_VISIBLE_DEVICES to
      null or to the new special value "void".

      Signed-off-by: Felix Abecassis <fabecassis@nvidia.com>


  commit d6337a5f9dc7311af168aa3d586fdf239f5a10d3
  Author: Christian Brauner <christian.brauner@ubuntu.com>
  Date:   Wed Jan 31 16:25:11 2018 +0100

      cgroups: get controllers on the unified hierarchy

      Signed-off-by: Christian Brauner <christian.brauner@ubuntu.com>

  ```
## 21) Use `_exit()` To Terminate `fork()`ed Child Processes

- When `fork()`ing off a child process use `_exit()` to terminate it instead of
  `exit()`. The `exit()` function is not thread-safe and thus not suited for
  the shared library which must ensure that it is thread-safe.

## 22) Keep Arrays of `struct`s Aligned Horizontally When Initializing

- Arrays of `struct`s are:
  ```C
  struct foo_struct {
        int n;
        int m;
        int p;
  };

  struct foo_struct new_instance[] = {
          { 1, 2, 3 },
          { 4, 5, 6 },
          { 7, 8, 9 },
  };
  ```
- Leave a single space after the opening `{` and before closing `}` of the
  largest member of the last column.
- Always leave a single space between the largest member of the current column
  and the member in the next column.
- A good example is
  ```C
  struct signame {
          int num;
          const char *name;
  };

  static const struct signame signames[] = {
          { SIGHUP,    "HUP"    },
          { SIGINT,    "INT"    },
          { SIGQUIT,   "QUIT"   },
          { SIGILL,    "ILL"    },
          { SIGABRT,   "ABRT"   },
          { SIGFPE,    "FPE"    },
          { SIGKILL,   "KILL"   },
          { SIGSEGV,   "SEGV"   },
          { SIGPIPE,   "PIPE"   },
          { SIGALRM,   "ALRM"   },
          { SIGTERM,   "TERM"   },
          { SIGUSR1,   "USR1"   },
          { SIGUSR2,   "USR2"   },
          { SIGCHLD,   "CHLD"   },
          { SIGCONT,   "CONT"   },
          { SIGSTOP,   "STOP"   },
          { SIGTSTP,   "TSTP"   },
          { SIGTTIN,   "TTIN"   },
          { SIGTTOU,   "TTOU"   },
  #ifdef SIGTRAP
          { SIGTRAP,   "TRAP"   },
  #endif
  #ifdef SIGIOT
          { SIGIOT,    "IOT"    },
  #endif
  #ifdef SIGEMT
          { SIGEMT,    "EMT"    },
  #endif
  #ifdef SIGBUS
          { SIGBUS,    "BUS"    },
  #endif
  #ifdef SIGSTKFLT
          { SIGSTKFLT, "STKFLT" },
  #endif
  #ifdef SIGCLD
          { SIGCLD,    "CLD"    },
  #endif
  #ifdef SIGURG
          { SIGURG,    "URG"    },
  #endif
  #ifdef SIGXCPU
          { SIGXCPU,   "XCPU"   },
  #endif
  #ifdef SIGXFSZ
          { SIGXFSZ,   "XFSZ"   },
  #endif
  #ifdef SIGVTALRM
          { SIGVTALRM, "VTALRM" },
  #endif
  #ifdef SIGPROF
          { SIGPROF,   "PROF"   },
  #endif
  #ifdef SIGWINCH
          { SIGWINCH,  "WINCH"  },
  #endif
  #ifdef SIGIO
          { SIGIO,     "IO"     },
  #endif
  #ifdef SIGPOLL
          { SIGPOLL,   "POLL"   },
  #endif
  #ifdef SIGINFO
          { SIGINFO,   "INFO"   },
  #endif
  #ifdef SIGLOST
          { SIGLOST,   "LOST"   },
  #endif
  #ifdef SIGPWR
          { SIGPWR,    "PWR"    },
  #endif
  #ifdef SIGUNUSED
          { SIGUNUSED, "UNUSED" },
  #endif
  #ifdef SIGSYS
          { SIGSYS,    "SYS"    },
  #endif
  };
  ```

## 23) Use `strlcpy()` instead of `strncpy()`

When copying strings always use `strlcpy()` instead of `strncpy()`. The
advantage of `strlcpy()` is that it will always append a `\0` byte to the
string.

Unless you have a valid reason to accept truncation you must check whether
truncation has occurred, treat it as an error, and handle the error
appropriately.

## 24) Use `strlcat()` instead of `strncat()`

When concatenating strings always use `strlcat()` instead of `strncat()`. The
advantage of `strlcat()` is that it will always append a `\0` byte to the
string.

Unless you have a valid reason to accept truncation you must check whether
truncation has occurred, treat it as an error, and handle the error
appropriately.

## 25) Use `__fallthrough__` in switch statements

If LXC detects that the compiler is new enough it will tell it to check
`switch` statements for non-documented fallthroughs. Please always place
a `__fallthrough__` after a `case` which falls through the next one.

```c
int lxc_attach_run_command(void *payload)
{
	int ret = -1;
	lxc_attach_command_t *cmd = payload;

	ret = execvp(cmd->program, cmd->argv);
	if (ret < 0) {
		switch (errno) {
		case ENOEXEC:
			ret = 126;
			break;
		case ENOENT:
			ret = 127;
			break;
		}
	}

	SYSERROR("Failed to exec \"%s\"", cmd->program);
	return ret;
}
```

## 24) Never use `fgets()`

LXC does not allow the use of `fgets()`. Use `getline()` or other methods
instead.

## 25) Never allocate memory on the stack

This specifically forbids any usage of `alloca()` in the codebase.

## 26) Use cleanup macros supported by `gcc` and `clang`

LXC has switched from manually cleaning up resources to using cleanup macros
supported by `gcc` and `clang`:
```c
__attribute__((__cleanup__(<my-cleanup-function-wrapper>)))
```
We do not allow manually cleanups anymore if there are appropriate macros.
Currently the following macros are supported:
```c
/* close file descriptor */
__do_close_prot_errno

/* free allocated memory */
__do_free __attribute__((__cleanup__(__auto_free__)))

/* close FILEs */
__do_fclose __attribute__((__cleanup__(__auto_fclose__)))

/* close DIRs */
__do_closedir __attribute__((__cleanup__(__auto_closedir__)))
```
For example:
```c
void remount_all_slave(void)
{
	__do_free char *line = NULL;
	__do_fclose FILE *f = NULL;
	__do_close_prot_errno int memfd = -EBADF, mntinfo_fd = -EBADF;
	int ret;
	ssize_t copied;
	size_t len = 0;

	mntinfo_fd = open("/proc/self/mountinfo", O_RDONLY | O_CLOEXEC);
	if (mntinfo_fd < 0) {
		SYSERROR("Failed to open \"/proc/self/mountinfo\"");
		return;
	}

	memfd = memfd_create(".lxc_mountinfo", MFD_CLOEXEC);
	if (memfd < 0) {
		char template[] = P_tmpdir "/.lxc_mountinfo_XXXXXX";

		if (errno != ENOSYS) {
			SYSERROR("Failed to create temporary in-memory file");
			return;
		}

		memfd = lxc_make_tmpfile(template, true);
		if (memfd < 0) {
			WARN("Failed to create temporary file");
			return;
		}
	}

again:
	copied = lxc_sendfile_nointr(memfd, mntinfo_fd, NULL, LXC_SENDFILE_MAX);
	if (copied < 0) {
		if (errno == EINTR)
			goto again;

		SYSERROR("Failed to copy \"/proc/self/mountinfo\"");
		return;
	}

	ret = lseek(memfd, 0, SEEK_SET);
	if (ret < 0) {
		SYSERROR("Failed to reset file descriptor offset");
		return;
	}

	f = fdopen(memfd, "r");
	if (!f) {
		SYSERROR("Failed to open copy of \"/proc/self/mountinfo\" to mark all shared. Continuing");
		return;
	}

	/*
	 * After a successful fdopen() memfd will be closed when calling
	 * fclose(f). Calling close(memfd) afterwards is undefined.
	 */
	move_fd(memfd);

	while (getline(&line, &len, f) != -1) {
		char *opts, *target;

		target = get_field(line, 4);
		if (!target)
			continue;

		opts = get_field(target, 2);
		if (!opts)
			continue;

		null_endofword(opts);
		if (!strstr(opts, "shared"))
			continue;

		null_endofword(target);
		ret = mount(NULL, target, NULL, MS_SLAVE, NULL);
		if (ret < 0) {
			SYSERROR("Failed to make \"%s\" MS_SLAVE", target);
			ERROR("Continuing...");
			continue;
		}
		TRACE("Remounted \"%s\" as MS_SLAVE", target);
	}
	TRACE("Remounted all mount table entries as MS_SLAVE");
}
```
