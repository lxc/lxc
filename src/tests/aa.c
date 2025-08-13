/* liblxcapi
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "config.h"

/* Test apparmor rules */
#include <lxc/lxccontainer.h>
#include "utils.h"

#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#define MYNAME "test-aa"
#define MYNAME2 "test-aa-o1"

static char *read_file(char *fname) {
	FILE *f = fopen(fname, "r");
	ssize_t ret;
	size_t len = 0;
	char *v = NULL;

	if (!f) {
		fprintf(stderr, "Failed to open %s: %m\n", fname);
		return NULL;
	}
	ret = getline(&v, &len, f);
	if (ret == -1) {
		fprintf(stderr, "Failed reading a line from %s: %m\n", fname);
		free(v);
		if (f)
			fclose(f);
		return NULL;
	}
	if (f)
		fclose(f);
	return v;
}

static void try_to_remove(void)
{
	struct lxc_container *c, *c2;
	c = lxc_container_new(MYNAME, NULL);
	if (c) {
		if (c->is_defined(c))
			c->destroy(c);
		lxc_container_put(c);
	}
	c2 = lxc_container_new(MYNAME2, NULL);
	if (c2) {
		if (c2->is_defined(c2))
			c2->destroy(c2);
		lxc_container_put(c2);
	}
}

static int test_attach_write_file(void* payload)
{
	char *fnam = payload;
	FILE *f;

	f = fopen(fnam, "w");
	if (f) {
		printf("yes\n");
		fclose(f);
		fflush(NULL);
		return 1;
	}
	printf("no\n");
	fflush(NULL);
	return 0;
}

/*
 * try opening a file attached to a container.  Return 0 on open fail.  Return
 * 1 if the file open succeeded.  Return -1 if attach itself failed - perhaps an
 * older kernel.
 */
static int do_test_file_open(struct lxc_container *c, char *fnam)
{
	int fret = -1;
	int ret;
	pid_t pid;
	int pipefd[2];
	char result[1024];
	lxc_attach_options_t attach_options = LXC_ATTACH_OPTIONS_DEFAULT;

	ret = pipe(pipefd);
	if (ret < 0) {
		fprintf(stderr, "pipe failed %d\n", ret);
		return fret;
	}
	attach_options.stdout_fd = pipefd[1];
	attach_options.attach_flags &= ~(LXC_ATTACH_LSM_EXEC|LXC_ATTACH_DROP_CAPABILITIES);
	attach_options.attach_flags |= LXC_ATTACH_LSM_NOW;
	ret = c->attach(c, test_attach_write_file, fnam, &attach_options, &pid);
	if (ret < 0) {
		fprintf(stderr, "attach failed\n");
		goto err1;
	}

	ret = read(pipefd[0], result, sizeof(result)-1);
	if (ret < 0) {
		fprintf(stderr, "read failed %d\n", ret);
		goto err2;
	}

	fret = 1;
	if (strncmp(result, "no", 2) == 0)
		fret = 0;

err2:
	(void)wait_for_pid(pid);
err1:
	close(pipefd[0]);
	close(pipefd[1]);
	return fret;
}

char *files_to_allow[] = { "/sys/class/net/lo/ifalias",
		"/proc/sys/kernel/shmmax",
		NULL };

char *files_to_deny[] = {
		"/sys/kernel/uevent_helper",
		"/proc/sys/fs/file-nr",
		"/sys/kernel/mm/ksm/pages_to_scan",
		"/proc/sys/kernel/sysrq",
		NULL };

static bool test_aa_policy(struct lxc_container *c)
{
	int i, ret;

	for (i = 0; files_to_deny[i]; i++) {
		ret = do_test_file_open(c, files_to_deny[i]);
		if (ret < 0) {
			fprintf(stderr, "attach failed; skipping test\n");
			return true;
		}
		if (ret > 0) {
			fprintf(stderr, "failed - opened %s\n",
					files_to_deny[i]);
			return false;
		}
		fprintf(stderr, "passed with %s\n", files_to_deny[i]);
	}

	for (i = 0; files_to_allow[i]; i++) {
		ret = do_test_file_open(c, files_to_allow[i]);
		if (ret < 0) {
			fprintf(stderr, "attach failed; skipping test\n");
			return true;
		}
		if (ret == 0) {
			fprintf(stderr, "failed - could not open %s\n",
					files_to_allow[i]);
			return false;
		}
		fprintf(stderr, "passed with %s\n", files_to_allow[i]);
	}

	return true;
}

int main(int argc, char *argv[])
{
	struct lxc_container *c, *c2= NULL;
	char *v = NULL;

	try_to_remove();
	c = lxc_container_new(MYNAME, NULL);
	if (!c) {
		fprintf(stderr, "%s: %d: failed to load first container\n", __FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}

	if (c->is_defined(c)) {
		fprintf(stderr, "%d: %s thought it was defined\n", __LINE__, MYNAME);
		goto err;
	}
	if (!c->set_config_item(c, "lxc.net.0.type", "empty")) {
		fprintf(stderr, "%s: %d: failed to set network type\n", __FILE__, __LINE__);
		goto err;
	}
	c->save_config(c, NULL);
	if (!c->createl(c, "busybox", NULL, NULL, 0, NULL)) {
		fprintf(stderr, "%s: %d: failed to create container\n", __FILE__, __LINE__);
		goto err;
	}

	c->clear_config_item(c, "lxc.mount.auto");
	c->set_config_item(c, "lxc.mount.entry", "proc proc proc");
	c->set_config_item(c, "lxc.mount.entry", "sysfs sys sysfs");
	c->save_config(c, NULL);

	c->want_daemonize(c, true);
	if (!c->startl(c, 0, NULL)) {
		fprintf(stderr, "Error starting container\n");
		goto err;
	}

	if (!test_aa_policy(c)) {
		c->stop(c);
		goto err;
	}

	c->stop(c);

	c2 = c->clone(c, MYNAME2, NULL, LXC_CLONE_SNAPSHOT, "overlayfs", NULL, 0, NULL);
	if (!c2) {
		fprintf(stderr, "Error cloning " MYNAME " to " MYNAME2 "\n");
		goto err;
	}

	c2->want_daemonize(c2, true);
	if (!c2->startl(c2, 0, NULL)) {
		fprintf(stderr, "Error starting container\n");
		goto err;
	}

	char pidstr[50];
	snprintf(pidstr, 50, "/proc/%d/attr/current", c2->init_pid(c2));
	v = read_file(pidstr);
	if (!v) {
		fprintf(stderr, "Failed to read the apparmor profile name from '%s'\n", pidstr);
		goto err;
	}

	fprintf(stderr, "apparmor policy of clone: %s\n", v);
	char *exp1 = "lxc-";
	if (strncmp(v, exp1, strlen(exp1)) != 0) {
		fprintf(stderr, "Wrong profile: %s", v);
		goto err;
	}
	if (strstr(v, "(enforce)") == NULL) {
		fprintf(stderr, "Wrong profile: %s", v);
		goto err;
	}

	c2->stop(c2);

	free(v);
	try_to_remove();
	exit(EXIT_SUCCESS);

err:
	free(v);
	try_to_remove();
	exit(EXIT_FAILURE);
}
