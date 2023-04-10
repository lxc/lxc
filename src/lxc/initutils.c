/* SPDX-License-Identifier: LGPL-2.1+ */

#include "config.h"

#include <pthread.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "compiler.h"
#include "error.h"
#include "file_utils.h"
#include "initutils.h"
#include "macro.h"
#include "memory_utils.h"
#include "process_utils.h"

#if !HAVE_STRLCPY
#include "strlcpy.h"
#endif

static char *copy_global_config_value(char *p)
{
	int len = strlen(p);
	char *retbuf;

	if (len < 1)
		return NULL;

	if (p[len-1] == '\n') {
		p[len-1] = '\0';
		len--;
	}

	retbuf = malloc(len + 1);
	if (!retbuf)
		return NULL;

	(void)strlcpy(retbuf, p, len + 1);
	return retbuf;
}

const char *lxc_global_config_value(const char *option_name)
{
	static const char * const options[][2] = {
		{ "lxc.bdev.lvm.vg",        DEFAULT_VG      },
		{ "lxc.bdev.lvm.thin_pool", DEFAULT_THIN_POOL },
		{ "lxc.bdev.zfs.root",      DEFAULT_ZFSROOT },
		{ "lxc.bdev.rbd.rbdpool",   DEFAULT_RBDPOOL },
		{ "lxc.lxcpath",            NULL            },
		{ "lxc.default_config",     NULL            },
		{ "lxc.cgroup.pattern",     NULL            },
		{ "lxc.cgroup.use",         NULL            },
		{ NULL, NULL },
	};

	/* placed in the thread local storage pool for non-bionic targets */
	static thread_local const char *values[sizeof(options) / sizeof(options[0])] = {0};

	/* user_config_path is freed as soon as it is used */
	char *user_config_path = NULL;

	/*
	 * The following variables are freed at bottom unconditionally.
	 * So NULL the value if it is to be returned to the caller
	 */
	char *user_default_config_path = NULL;
	char *user_lxc_path = NULL;
	char *user_cgroup_pattern = NULL;

	if (geteuid() > 0) {
		const char *user_home = getenv("HOME");
		if (!user_home)
			user_home = "/";

		user_config_path = malloc(sizeof(char) * (22 + strlen(user_home)));
		user_default_config_path = malloc(sizeof(char) * (26 + strlen(user_home)));
		user_lxc_path = malloc(sizeof(char) * (19 + strlen(user_home)));

		sprintf(user_config_path, "%s/.config/lxc/lxc.conf", user_home);
		sprintf(user_default_config_path, "%s/.config/lxc/default.conf", user_home);
		sprintf(user_lxc_path, "%s/.local/share/lxc/", user_home);
	}
	else {
		user_config_path = strdup(LXC_GLOBAL_CONF);
		user_default_config_path = strdup(LXC_DEFAULT_CONFIG);
		user_lxc_path = strdup(LXCPATH);
		if (!strequal(DEFAULT_CGROUP_PATTERN, ""))
			user_cgroup_pattern = strdup(DEFAULT_CGROUP_PATTERN);
	}

	const char * const (*ptr)[2];
	size_t i;
	FILE *fin = NULL;

	for (i = 0, ptr = options; (*ptr)[0]; ptr++, i++) {
		if (strequal(option_name, (*ptr)[0]))
			break;
	}
	if (!(*ptr)[0]) {
		free(user_config_path);
		free(user_default_config_path);
		free(user_lxc_path);
		free(user_cgroup_pattern);
		errno = EINVAL;
		return NULL;
	}

	if (values[i]) {
		free(user_config_path);
		free(user_default_config_path);
		free(user_lxc_path);
		free(user_cgroup_pattern);
		return values[i];
	}

	fin = fopen_cloexec(user_config_path, "r");
	free(user_config_path);
	if (fin) {
		__do_free char *line = NULL;
		size_t len = 0;
		char *slider1, *slider2;

		while (getline(&line, &len, fin) > 0) {
			if (*line == '#')
				continue;

			slider1 = strstr(line, option_name);
			if (!slider1)
				continue;

			/* see if there was just white space in front
			 * of the option name
			 */
			for (slider2 = line; slider2 < slider1; slider2++)
				if (*slider2 != ' ' && *slider2 != '\t')
					break;

			if (slider2 < slider1)
				continue;

			slider1 = strchr(slider1, '=');
			if (!slider1)
				continue;

			/* see if there was just white space after
			 * the option name
			 */
			for (slider2 += strlen(option_name); slider2 < slider1;
			     slider2++)
				if (*slider2 != ' ' && *slider2 != '\t')
					break;

			if (slider2 < slider1)
				continue;

			slider1++;
			while (*slider1 && (*slider1 == ' ' || *slider1 == '\t'))
				slider1++;

			if (!*slider1)
				continue;

			if (strequal(option_name, "lxc.lxcpath")) {
				free(user_lxc_path);
				user_lxc_path = copy_global_config_value(slider1);
				remove_trailing_slashes(user_lxc_path);
				values[i] = move_ptr(user_lxc_path);
				goto out;
			}

			values[i] = copy_global_config_value(slider1);
			goto out;
		}
	}

	/* could not find value, use default */
	if (strequal(option_name, "lxc.lxcpath")) {
		remove_trailing_slashes(user_lxc_path);
		values[i] = move_ptr(user_lxc_path);
	} else if (strequal(option_name, "lxc.default_config")) {
		values[i] = move_ptr(user_default_config_path);
	} else if (strequal(option_name, "lxc.cgroup.pattern")) {
		values[i] = move_ptr(user_cgroup_pattern);
	} else {
		values[i] = (*ptr)[1];
	}

	/* special case: if default value is NULL,
	 * and there is no config, don't view that
	 * as an error... */
	if (!values[i])
		errno = 0;

out:
	if (fin)
		fclose(fin);

	free(user_cgroup_pattern);
	free(user_default_config_path);
	free(user_lxc_path);

	return values[i];
}

/*
 * Sets the process title to the specified title. Note that this may fail if
 * the kernel doesn't support PR_SET_MM_MAP (kernels <3.18).
 */
int setproctitle(char *title)
{
	__do_fclose FILE *f = NULL;
	int i, fd, len;
	char *buf_ptr, *tmp_proctitle;
	char buf[LXC_LINELEN];
	int ret = 0;
	ssize_t bytes_read = 0;
	static char *proctitle = NULL;

	/*
	 * We don't really need to know all of this stuff, but unfortunately
	 * PR_SET_MM_MAP requires us to set it all at once, so we have to
	 * figure it out anyway.
	 */
	uint64_t start_data, end_data, start_brk, start_code, end_code,
	    start_stack, arg_start, arg_end, env_start, env_end, brk_val;
	struct prctl_mm_map prctl_map;

	f = fopen_cloexec("/proc/self/stat", "r");
	if (!f)
		return -1;

	fd = fileno(f);
	if (fd < 0)
		return -1;

	bytes_read = lxc_read_nointr(fd, buf, sizeof(buf) - 1);
	if (bytes_read <= 0)
		return -1;

	buf[bytes_read] = '\0';

	/*
	 * executable names may contain spaces, so we search backwards for the
	 * ), which is the kernel's marker for "end of executable name". this
	 * skips the first two fields.
	 */
	buf_ptr = strrchr(buf, ')')+2;

	/* Skip the next 23 fields, column 26-28 are start_code, end_code,
	 * and start_stack */
	buf_ptr = strchr(buf_ptr, ' ');
	for (i = 0; i < 22; i++) {
		if (!buf_ptr)
			return -1;
		buf_ptr = strchr(buf_ptr + 1, ' ');
	}
	if (!buf_ptr)
		return -1;

	i = sscanf(buf_ptr, "%" PRIu64 " %" PRIu64 " %" PRIu64, &start_code, &end_code, &start_stack);
	if (i != 3)
		return -1;

	/* Skip the next 19 fields, column 45-51 are start_data to arg_end */
	for (i = 0; i < 19; i++) {
		if (!buf_ptr)
			return -1;
		buf_ptr = strchr(buf_ptr + 1, ' ');
	}

	if (!buf_ptr)
		return -1;

	i = sscanf(buf_ptr, "%" PRIu64 " %" PRIu64 " %" PRIu64 " %*u %*u %" PRIu64 " %" PRIu64, &start_data,
		   &end_data, &start_brk, &env_start, &env_end);
	if (i != 5)
		return -1;

	/* Include the null byte here, because in the calculations below we
	 * want to have room for it. */
	len = strlen(title) + 1;

	tmp_proctitle = realloc(proctitle, len);
	if (!tmp_proctitle)
		return -1;

	proctitle = tmp_proctitle;

	arg_start = (unsigned long)proctitle;
	arg_end = arg_start + len;

	brk_val = syscall(__NR_brk, 0);

	prctl_map = (struct prctl_mm_map){
	    .start_code = start_code,
	    .end_code = end_code,
	    .start_stack = start_stack,
	    .start_data = start_data,
	    .end_data = end_data,
	    .start_brk = start_brk,
	    .brk = brk_val,
	    .arg_start = arg_start,
	    .arg_end = arg_end,
	    .env_start = env_start,
	    .env_end = env_end,
	    .auxv = NULL,
	    .auxv_size = 0,
	    .exe_fd = -1,
	};

	ret = prctl(PR_SET_MM, prctl_arg(PR_SET_MM_MAP), prctl_arg(&prctl_map),
		    prctl_arg(sizeof(prctl_map)), prctl_arg(0));
	if (ret == 0)
		(void)strlcpy((char *)arg_start, title, len);

	return ret;
}

static void prevent_forking(void)
{
	__do_free char *line = NULL;
	__do_fclose FILE *f = NULL;
	char path[PATH_MAX];
	size_t len = 0;

	f = fopen("/proc/self/cgroup", "re");
	if (!f)
		return;

	while (getline(&line, &len, f) != -1) {
		__do_close int fd = -EBADF;
		int ret;
		char *p, *p2;

		p = strchr(line, ':');
		if (!p)
			continue;
		p++;
		p2 = strchr(p, ':');
		if (!p2)
			continue;
		*p2 = '\0';

		/* This is a cgroup v2 entry. Skip it. */
		if ((p2 - p) == 0)
			continue;

		if (strcmp(p, "pids") != 0)
			continue;
		p2++;

		p2 += lxc_char_left_gc(p2, strlen(p2));
		p2[lxc_char_right_gc(p2, strlen(p2))] = '\0';

		ret = snprintf(path, sizeof(path),
			       "/sys/fs/cgroup/pids/%s/pids.max", p2);
		if (ret < 0 || (size_t)ret >= sizeof(path)) {
			fprintf(stderr, "Failed to create string\n");
			return;
		}

		fd = open(path, O_WRONLY | O_CLOEXEC);
		if (fd < 0) {
			fprintf(stderr, "Failed to open \"%s\"\n", path);
			return;
		}

		ret = write(fd, "1", 1);
		if (ret != 1)
			fprintf(stderr, "Failed to write to \"%s\"\n", path);

		return;
	}
}

static void kill_children(pid_t pid)
{
	__do_fclose FILE *f = NULL;
	char path[PATH_MAX];
	int ret;

	ret = snprintf(path, sizeof(path), "/proc/%d/task/%d/children", pid, pid);
	if (ret < 0 || (size_t)ret >= sizeof(path)) {
		fprintf(stderr, "Failed to create string\n");
		return;
	}

	f = fopen(path, "re");
	if (!f) {
		fprintf(stderr, "Failed to open %s\n", path);
		return;
	}

	while (!feof(f)) {
		pid_t find_pid;

		if (fscanf(f, "%d ", &find_pid) != 1) {
			fprintf(stderr, "Failed to retrieve pid\n");
			return;
		}

		(void)kill_children(find_pid);
		(void)kill(find_pid, SIGKILL);
	}
}

static void remove_self(void)
{
	int ret;
	ssize_t n;
	char path[PATH_MAX] = {0};

	n = readlink("/proc/self/exe", path, sizeof(path));
	if (n < 0 || n >= PATH_MAX)
		return;
	path[n] = '\0';

	ret = umount2(path, MNT_DETACH);
	if (ret < 0)
		return;

	ret = unlink(path);
	if (ret < 0)
		return;
}

static sig_atomic_t was_interrupted;

static void interrupt_handler(int sig)
{
	if (!was_interrupted)
		was_interrupted = sig;
}

static int close_inherited(void)
{
	int fddir;
	DIR *dir;
	struct dirent *direntp;

restart:
	dir = opendir("/proc/self/fd");
	if (!dir)
		return -errno;

	fddir = dirfd(dir);

	while ((direntp = readdir(dir))) {
		int fd, ret;

		if (strcmp(direntp->d_name, ".") == 0)
			continue;

		if (strcmp(direntp->d_name, "..") == 0)
			continue;

		ret = lxc_safe_int(direntp->d_name, &fd);
		if (ret < 0)
			continue;

		if (fd == STDERR_FILENO || fd == fddir)
			break;

		if (close(fd)) {
			closedir(dir);
			return -errno;
		}

		closedir(dir);
		goto restart;
	}

	closedir(dir);
	return 0;
}

__noreturn int lxc_container_init(int argc, char *const *argv, bool quiet)
{
	int i, logfd, ret;
	pid_t pid;
	struct sigaction act;
	sigset_t mask, omask;
	int have_status = 0, exit_with = 1, shutdown = 0;

	/* Mask all the signals so we are safe to install a signal handler and
	 * to fork.
	 */
	ret = sigfillset(&mask);
	if (ret < 0)
		exit(EXIT_FAILURE);

	ret = sigdelset(&mask, SIGILL);
	if (ret < 0)
		exit(EXIT_FAILURE);

	ret = sigdelset(&mask, SIGSEGV);
	if (ret < 0)
		exit(EXIT_FAILURE);

	ret = sigdelset(&mask, SIGBUS);
	if (ret < 0)
		exit(EXIT_FAILURE);

	ret = pthread_sigmask(SIG_SETMASK, &mask, &omask);
	if (ret < 0)
		exit(EXIT_FAILURE);

	ret = sigfillset(&act.sa_mask);
	if (ret < 0)
		exit(EXIT_FAILURE);

	ret = sigdelset(&act.sa_mask, SIGILL);
	if (ret < 0)
		exit(EXIT_FAILURE);

	ret = sigdelset(&act.sa_mask, SIGSEGV);
	if (ret < 0)
		exit(EXIT_FAILURE);

	ret = sigdelset(&act.sa_mask, SIGBUS);
	if (ret < 0)
		exit(EXIT_FAILURE);

	ret = sigdelset(&act.sa_mask, SIGSTOP);
	if (ret < 0)
		exit(EXIT_FAILURE);

	ret = sigdelset(&act.sa_mask, SIGKILL);
	if (ret < 0)
		exit(EXIT_FAILURE);

	act.sa_flags = 0;
	act.sa_handler = interrupt_handler;

	for (i = 1; i < NSIG; i++) {
		/* Exclude some signals: ILL, SEGV and BUS are likely to reveal
		 * a bug and we want a core. STOP and KILL cannot be handled
		 * anyway: they're here for documentation. 32 and 33 are not
		 * defined.
		 */
		if (i == SIGILL || i == SIGSEGV || i == SIGBUS ||
		    i == SIGSTOP || i == SIGKILL || i == 32 || i == 33)
			continue;

		ret = sigaction(i, &act, NULL);
		if (ret < 0) {
			if (errno == EINVAL)
				continue;

			if (!quiet)
				fprintf(stderr, "Failed to change signal action\n");
			exit(EXIT_FAILURE);
		}
	}

	remove_self();

	pid = fork();
	if (pid < 0)
		exit(EXIT_FAILURE);

	if (!pid) {
		/* restore default signal handlers */
		for (i = 1; i < NSIG; i++) {
			sighandler_t sigerr;

			if (i == SIGILL || i == SIGSEGV || i == SIGBUS ||
			    i == SIGSTOP || i == SIGKILL || i == 32 || i == 33)
				continue;

			sigerr = signal(i, SIG_DFL);
			if (sigerr == SIG_ERR && !quiet)
				fprintf(stderr, "Failed to reset to default action for signal \"%d\": %d\n", i, pid);
		}

		ret = pthread_sigmask(SIG_SETMASK, &omask, NULL);
		if (ret < 0) {
			if (quiet)
				fprintf(stderr, "Failed to set signal mask\n");
			exit(EXIT_FAILURE);
		}

		(void)setsid();

		(void)ioctl(STDIN_FILENO, TIOCSCTTY, 0);

		ret = execvp(argv[0], argv);
		if (!quiet)
			fprintf(stderr, "Failed to exec \"%s\"\n", argv[0]);
		exit(ret);
	}
	logfd = open("/dev/console", O_WRONLY | O_NOCTTY | O_CLOEXEC);
	if (logfd >= 0) {
		ret = dup3(logfd, STDERR_FILENO, O_CLOEXEC);
		if (ret < 0)
			exit(EXIT_FAILURE);
	}

	(void)setproctitle("init");

	/* Let's process the signals now. */
	ret = sigdelset(&omask, SIGALRM);
	if (ret < 0)
		exit(EXIT_FAILURE);

	ret = pthread_sigmask(SIG_SETMASK, &omask, NULL);
	if (ret < 0) {
		if (!quiet)
			fprintf(stderr, "Failed to set signal mask\n");
		exit(EXIT_FAILURE);
	}

	ret = close_range(STDERR_FILENO + 1, UINT_MAX, CLOSE_RANGE_UNSHARE);
	if (ret) {
		/*
		 * Fallback to close_inherited() when the syscall is not
		 * available or when CLOSE_RANGE_UNSHARE isn't supported.
		 * On a regular kernel CLOSE_RANGE_UNSHARE should always be
		 * available but openSUSE Leap 15.3 seems to have a partial
		 * backport without CLOSE_RANGE_UNSHARE support.
		 */
		if (errno == ENOSYS || errno == EINVAL)
			ret = close_inherited();
	}
	if (ret) {
		fprintf(stderr, "Aborting attach to prevent leaking file descriptors into container\n");
		exit(EXIT_FAILURE);
	}

	for (;;) {
		int status;
		pid_t waited_pid;

		switch (was_interrupted) {
		case 0:
		/* Some applications send SIGHUP in order to get init to reload
		 * its configuration. We don't want to forward this onto the
		 * application itself, because it probably isn't expecting this
		 * signal since it was expecting init to do something with it.
		 *
		 * Instead, let's explicitly ignore it here. The actual
		 * terminal case is handled in the monitor's handler, which
		 * sends this task a SIGTERM in the case of a SIGHUP, which is
		 * what we want.
		 */
		case SIGHUP:
			break;
		case SIGPWR:
		case SIGTERM:
			if (!shutdown) {
				pid_t mypid = lxc_raw_getpid();

				shutdown = 1;
				prevent_forking();
				if (mypid != 1) {
					kill_children(mypid);
				} else {
					ret = kill(-1, SIGTERM);
					if (ret < 0 && !quiet)
						fprintf(stderr, "Failed to send SIGTERM to all children\n");
				}
				alarm(1);
			}
			break;
		case SIGALRM: {
			pid_t mypid = lxc_raw_getpid();

			prevent_forking();
			if (mypid != 1) {
				kill_children(mypid);
			} else {
				ret = kill(-1, SIGKILL);
				if (ret < 0 && !quiet)
					fprintf(stderr, "Failed to send SIGTERM to all children\n");
			}
			break;
		}
		default:
			kill(pid, was_interrupted);
			break;
		}
		ret = EXIT_SUCCESS;

		was_interrupted = 0;
		waited_pid = wait(&status);
		if (waited_pid < 0) {
			if (errno == ECHILD)
				goto out;

			if (errno == EINTR)
				continue;

			if (!quiet)
				fprintf(stderr, "Failed to wait on child %d\n", pid);
			ret = -1;
			goto out;
		}

		/* Reset timer each time a process exited. */
		if (shutdown)
			alarm(1);

		/* Keep the exit code of the started application (not wrapped
		 * pid) and continue to wait for the end of the orphan group.
		 */
		if (waited_pid == pid && !have_status) {
			exit_with = lxc_error_set_and_log(waited_pid, status);
			have_status = 1;
		}
	}
out:
	if (ret < 0)
		exit(EXIT_FAILURE);
	exit(exit_with);
}
