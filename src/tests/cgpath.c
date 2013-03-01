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

#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <errno.h>
#include "../lxc/cgroup.h"
#include "../lxc/lxc.h"

#define MYNAME "lxctest1"
#define MYNAME2 "lxctest2"

#define TSTERR(x) do { \
	fprintf(stderr, "%d: %s\n", __LINE__, x); \
} while (0)

int main()
{
	struct lxc_container *c = NULL, *c2 = NULL;
	char *path;
	int len;
	int ret, retv = -1;

	/* won't require privilege necessarily once users are classified by
	 * pam_cgroup */
	if (geteuid() != 0) {
		TSTERR("requires privilege");
		exit(0);
	}

	printf("Basic cgroup path tests...\n");
	path = lxc_cgroup_path_create(NULL, MYNAME);
	len = strlen(path);
	if (!path || !len) {
		TSTERR("zero result from lxc_cgroup_path_create");
		exit(1);
	}
	if (!strstr(path, "lxc/" MYNAME)) {
		TSTERR("lxc_cgroup_path_create NULL lxctest1");
		exit(1);
	}
	free(path);

	path = lxc_cgroup_path_create("ab", MYNAME);
	len = strlen(path);
	if (!path || !len) {
		TSTERR("zero result from lxc_cgroup_path_create");
		exit(1);
	}
	if (!strstr(path, "ab/" MYNAME)) {
		TSTERR("lxc_cgroup_path_create ab lxctest1");
		exit(1);
	}
	free(path);
	printf("... passed\n");

	printf("Container creation tests...\n");

	if ((c = lxc_container_new(MYNAME, NULL)) == NULL) {
		TSTERR("instantiating first container");
		exit(1);
	}
	if (c->is_defined(c)) {
		c->stop(c);
		c->destroy(c);
		c = lxc_container_new(MYNAME, NULL);
	}
	c->set_config_item(c, "lxc.network.type", "empty");
	if (!c->createl(c, "ubuntu", NULL)) {
		TSTERR("creating first container");
		exit(1);
	}
	c->load_config(c, NULL);
	c->want_daemonize(c);
	if (!c->startl(c, 0, NULL)) {
		TSTERR("starting first container");
		goto out;
	}
	printf("first container passed.  Now two containers...\n");

	char *nsgroup;
#define ALTBASE "/var/lib/lxctest2"
	ret = mkdir(ALTBASE, 0755);

	ret = lxc_cgroup_path_get(&nsgroup, "freezer", MYNAME, c->get_config_path(c));
	if (ret < 0 || !strstr(nsgroup, "lxc/" MYNAME)) {
		TSTERR("getting first cgroup path from lxc_command");
		goto out;
	}

	/* start second container */
	if ((c2 = lxc_container_new(MYNAME2, ALTBASE)) == NULL) {
		TSTERR("instantiating first container");
		goto out;
	}
	if (c2->is_defined(c2)) {
		c2->stop(c2);
		c2->destroy(c2);
		c2 = lxc_container_new(MYNAME2, ALTBASE);
	}
	c2->set_config_item(c2, "lxc.network.type", "empty");
	if (!c2->createl(c2, "ubuntu", NULL)) {
		TSTERR("creating first container");
		goto out;
	}

	c2->load_config(c2, NULL);
	c2->want_daemonize(c2);
	if (!c2->startl(c2, 0, NULL)) {
		TSTERR("starting first container");
		goto out;
	}

	ret = lxc_cgroup_path_get(&nsgroup, "freezer", MYNAME2, c2->get_config_path(c2));
	if (ret < 0 || !strstr(nsgroup, "lxc/" MYNAME2)) {
		TSTERR("getting second cgroup path from lxc_command");
		goto out;
	}

	const char *dirpath;
	if (lxc_get_cgpath(&dirpath, NULL, c2->name, c2->config_path) < 0) {
		TSTERR("getting second container's cgpath");
		return -1;
	}

	if (lxc_cgroup_nrtasks(dirpath) < 1) {
		TSTERR("getting nrtasks");
		goto out;
	}
	printf("...passed\n");

	retv = 0;
out:
	if (c2) {
		c2->stop(c2);
		c2->destroy(c2);
	}
	if (c) {
		c->stop(c);
		c->destroy(c);
	}
	return retv;
}
