/* liblxcapi
 *
 * Copyright © 2014 Serge Hallyn <serge.hallyn@ubuntu.com>.
 * Copyright © 2014 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* Test apparmor rules */
#include <lxc/lxccontainer.h>
#include "lxc/utils.h"

#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#define MYNAME "test-aa"

static void try_to_remove(void)
{
	struct lxc_container *c;
	c = lxc_container_new(MYNAME, NULL);
	if (c) {
		if (c->is_defined(c))
			c->destroy(c);
		lxc_container_put(c);
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
 * 1 if the file open succeeded.  Return -1 if attach itself failed - perhas an
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
	wait_for_pid(pid);
err1:
	close(pipefd[0]);
	close(pipefd[1]);
	return fret;
}

char *files_to_allow[] = { "/sys/class/net/lo/ifalias",
		"/proc/sys/kernel/shmmax",
		NULL };

char *files_to_deny[] = { "/proc/mem", "/proc/kmem",
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
	struct lxc_container *c;
	try_to_remove();
	c = lxc_container_new(MYNAME, NULL);
	if (!c) {
		fprintf(stderr, "%s: %d: failed to load first container\n", __FILE__, __LINE__);
		exit(1);
	}

	if (c->is_defined(c)) {
		fprintf(stderr, "%d: %s thought it was defined\n", __LINE__, MYNAME);
		goto err;
	}
	if (!c->set_config_item(c, "lxc.network.type", "empty")) {
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

	try_to_remove();
	exit(0);

err:
	try_to_remove();
	exit(1);
}
