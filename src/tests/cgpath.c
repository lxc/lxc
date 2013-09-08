/* liblxcapi
 *
 * Copyright © 2012 Serge Hallyn <serge.hallyn@ubuntu.com>.
 * Copyright © 2012 Canonical Ltd.
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
#include "../lxc/lxccontainer.h"

#include <limits.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <errno.h>
#include "../lxc/cgroup.h"
#include "../lxc/lxc.h"
#include "../lxc/commands.h"

#define MYNAME "lxctest1"

#define TSTERR(fmt, ...) do { \
	fprintf(stderr, "%s:%d " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
} while (0)

/*
 * test_running_container: test cgroup functions against a running container
 *
 * @group : name of the container group or NULL for default "lxc"
 * @name  : name of the container
 */
static int test_running_container(const char *lxcpath,
				  const char *group, const char *name)
{
	int ret = -1;
	struct lxc_container *c = NULL;
	char *cgrelpath;
	char *cgabspath;
	char  relpath[PATH_MAX+1];
	char  abspath[PATH_MAX+1];
	char  value[NAME_MAX], value_save[NAME_MAX];

	sprintf(relpath, "%s/%s", group ? group : "lxc", name);

	if ((c = lxc_container_new(name, lxcpath)) == NULL) {
		TSTERR("container %s couldn't instantiate", name);
		goto err1;
	}
	if (!c->is_defined(c)) {
		TSTERR("container %s does not exist", name);
		goto err2;
	}

	cgrelpath = lxc_cmd_get_cgroup_path(c->name, c->config_path, "freezer");
	if (!cgrelpath) {
		TSTERR("lxc_cmd_get_cgroup_path returned NULL");
		goto err2;
	}
	if (!strstr(cgrelpath, relpath)) {
		TSTERR("lxc_cmd_get_cgroup_path %s not in %s", relpath, cgrelpath);
		goto err3;
	}

	/* test get/set value using memory.swappiness file */
	ret = lxc_cgroup_get("memory.swappiness", value, sizeof(value),
			     c->name, c->config_path);
	if (ret < 0) {
		TSTERR("lxc_cgroup_get failed");
		goto err3;
	}
	strcpy(value_save, value);

	ret = lxc_cgroup_set("memory.swappiness", "100", c->name, c->config_path);
	if (ret < 0) {
		TSTERR("lxc_cgroup_set_bypath failed");
		goto err3;
	}
	ret = lxc_cgroup_get("memory.swappiness", value, sizeof(value),
			     c->name, c->config_path);
	if (ret < 0) {
		TSTERR("lxc_cgroup_get failed");
		goto err3;
	}
	if (strcmp(value, "100\n")) {
		TSTERR("lxc_cgroup_set_bypath failed to set value >%s<", value);
		goto err3;
	}

	/* restore original value */
	ret = lxc_cgroup_set("memory.swappiness", value_save,
			     c->name, c->config_path);
	if (ret < 0) {
		TSTERR("lxc_cgroup_set failed");
		goto err3;
	}
	ret = lxc_cgroup_get("memory.swappiness", value, sizeof(value),
			     c->name, c->config_path);
	if (ret < 0) {
		TSTERR("lxc_cgroup_get failed");
		goto err3;
	}
	if (strcmp(value, value_save)) {
		TSTERR("lxc_cgroup_set failed to set value >%s<", value);
		goto err3;
	}

	cgabspath = lxc_cgroup_path_get("freezer", c->name, c->config_path);
	if (!cgabspath) {
		TSTERR("lxc_cgroup_path_get returned NULL");
		goto err3;
	}
	sprintf(abspath, "%s/%s/%s", "freezer", group ? group : "lxc", c->name);
	if (!strstr(cgabspath, abspath)) {
		TSTERR("lxc_cgroup_path_get %s not in %s", abspath, cgabspath);
		goto err4;
	}

	free(cgabspath);
	cgabspath = lxc_cgroup_path_get("freezer.state", c->name, c->config_path);
	if (!cgabspath) {
		TSTERR("lxc_cgroup_path_get returned NULL");
		goto err3;
	}
	sprintf(abspath, "%s/%s/%s", "freezer", group ? group : "lxc", c->name);
	if (!strstr(cgabspath, abspath)) {
		TSTERR("lxc_cgroup_path_get %s not in %s", abspath, cgabspath);
		goto err4;
	}

	ret = 0;
err4:
	free(cgabspath);
err3:
	free(cgrelpath);
err2:
	lxc_container_put(c);
err1:
	return ret;
}

static int test_container(const char *lxcpath,
			  const char *group, const char *name,
			  const char *template)
{
	int ret;
	struct lxc_container *c = NULL;

	if (lxcpath) {
		ret = mkdir(lxcpath, 0755);
		if (ret < 0 && errno != EEXIST) {
			TSTERR("failed to mkdir %s %s", lxcpath, strerror(errno));
			goto out1;
		}
	}
	ret = -1;

	if ((c = lxc_container_new(name, lxcpath)) == NULL) {
		TSTERR("instantiating container %s", name);
		goto out1;
	}
	if (c->is_defined(c)) {
		c->stop(c);
		c->destroy(c);
		c = lxc_container_new(name, lxcpath);
	}
	c->set_config_item(c, "lxc.network.type", "empty");
	if (!c->createl(c, template, NULL, NULL, 0, NULL)) {
		TSTERR("creating container %s", name);
		goto out2;
	}
	c->load_config(c, NULL);
	c->want_daemonize(c);
	if (!c->startl(c, 0, NULL)) {
		TSTERR("starting container %s", name);
		goto out3;
	}

	ret = test_running_container(lxcpath, group, name);

	c->stop(c);
out3:
	c->destroy(c);
out2:
	lxc_container_put(c);
out1:
	return ret;
}

int main()
{
	int ret = EXIT_FAILURE;

	/* won't require privilege necessarily once users are classified by
	 * pam_cgroup */
	if (geteuid() != 0) {
		TSTERR("requires privilege");
		exit(0);
	}

	#if TEST_ALREADY_RUNNING_CT

	/*
	 * This is useful for running with valgrind to test for memory
	 * leaks. The container should already be running, we can't start
	 * the container ourselves because valgrind gets confused by lxc's
	 * internal calls to clone.
	 */
	if (test_running_container(NULL, NULL, "bb01") < 0)
		goto out;
	printf("Running container cgroup tests...Passed\n");

	#else

	if (test_container(NULL, NULL, MYNAME, "busybox") < 0)
		goto out;
	printf("Container creation tests...Passed\n");

	if (test_container("/var/lib/lxctest2", NULL, MYNAME, "busybox") < 0)
		goto out;
	printf("Container creation with LXCPATH tests...Passed\n");

	#endif

	ret = EXIT_SUCCESS;
out:
	return ret;
}
