/* liblxcapi
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "config.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <lxc/lxccontainer.h>

#include "state.h"

#define MYNAME "lxctest1"

int main(int argc, char *argv[])
{
	struct lxc_container *c;
	int len, ret;
	char v3[2048];

	if ((c = lxc_container_new(MYNAME, NULL)) == NULL) {
		fprintf(stderr, "%d: error opening lxc_container %s\n", __LINE__, MYNAME);
		ret = 1;
		goto out;
	}

	c->set_config_item(c, "lxc.net.0.type", "veth");

	len = c->get_keys(c, NULL, NULL, 0);
	if (len < 0) {
		fprintf(stderr, "%d: failed to get length of all keys (%d)\n", __LINE__, len);
		ret = 1;
		goto out;
	}

	ret = c->get_keys(c, NULL, v3, len+1);
	if (ret != len) {
		fprintf(stderr, "%d: failed to get keys (%d)\n", __LINE__, ret);
		ret = 1;
		goto out;
	}
	printf("get_keys returned %d\n%s", ret, v3);

	ret = c->get_keys(c, "lxc.net.0", v3, 2000);
	if (ret < 0) {
		fprintf(stderr, "%d: failed to get nic 0 keys(%d)\n", __LINE__, ret);
		ret = 1;
		goto out;
	}
	printf("get_keys for nic 1 returned %d\n%s", ret, v3);

	ret = c->get_keys(c, "lxc.apparmor", v3, 2000);
	if (ret < 0) {
		fprintf(stderr, "%d: failed to get keys(%d)\n", __LINE__, ret);
		ret = 1;
		goto out;
	}
	printf("get_keys returned %d\n%s", ret, v3);

	ret = c->get_keys(c, "lxc.selinux", v3, 2000);
	if (ret < 0) {
		fprintf(stderr, "%d: failed to get keys(%d)\n", __LINE__, ret);
		ret = 1;
		goto out;
	}
	printf("get_keys returned %d\n%s", ret, v3);

	ret = c->get_keys(c, "lxc.mount", v3, 2000);
	if (ret < 0) {
		fprintf(stderr, "%d: failed to get keys(%d)\n", __LINE__, ret);
		ret = 1;
		goto out;
	}
	printf("get_keys returned %d\n%s", ret, v3);

	ret = c->get_keys(c, "lxc.rootfs", v3, 2000);
	if (ret < 0) {
		fprintf(stderr, "%d: failed to get keys(%d)\n", __LINE__, ret);
		ret = 1;
		goto out;
	}
	printf("get_keys returned %d\n%s", ret, v3);

	ret = c->get_keys(c, "lxc.uts", v3, 2000);
	if (ret < 0) {
		fprintf(stderr, "%d: failed to get keys(%d)\n", __LINE__, ret);
		ret = 1;
		goto out;
	}
	printf("get_keys returned %d\n%s", ret, v3);

	ret = c->get_keys(c, "lxc.hook", v3, 2000);
	if (ret < 0) {
		fprintf(stderr, "%d: failed to get keys(%d)\n", __LINE__, ret);
		ret = 1;
		goto out;
	}
	printf("get_keys returned %d\n%s", ret, v3);

	ret = c->get_keys(c, "lxc.cap", v3, 2000);
	if (ret < 0) {
		fprintf(stderr, "%d: failed to get keys(%d)\n", __LINE__, ret);
		ret = 1;
		goto out;
	}
	printf("get_keys returned %d\n%s", ret, v3);

	ret = c->get_keys(c, "lxc.console", v3, 2000);
	if (ret < 0) {
		fprintf(stderr, "%d: failed to get keys(%d)\n", __LINE__, ret);
		ret = 1;
		goto out;
	}
	printf("get_keys returned %d\n%s", ret, v3);

	ret = c->get_keys(c, "lxc.seccomp", v3, 2000);
	if (ret < 0) {
		fprintf(stderr, "%d: failed to get keys(%d)\n", __LINE__, ret);
		ret = 1;
		goto out;
	}
	printf("get_keys returned %d\n%s", ret, v3);

	ret = c->get_keys(c, "lxc.signal", v3, 2000);
	if (ret < 0) {
		fprintf(stderr, "%d: failed to get keys(%d)\n", __LINE__, ret);
		ret = 1;
		goto out;
	}
	printf("get_keys returned %d\n%s", ret, v3);

	ret = c->get_keys(c, "lxc.start", v3, 2000);
	if (ret < 0) {
		fprintf(stderr, "%d: failed to get keys(%d)\n", __LINE__, ret);
		ret = 1;
		goto out;
	}
	printf("get_keys returned %d\n%s", ret, v3);

	ret = c->get_keys(c, "lxc.monitor", v3, 2000);
	if (ret < 0) {
		fprintf(stderr, "%d: failed to get keys(%d)\n", __LINE__, ret);
		ret = 1;
		goto out;
	}
	printf("get_keys returned %d\n%s", ret, v3);

	ret = c->get_keys(c, "lxc.cgroup", v3, 2000);
	if (ret < 0) {
		fprintf(stderr, "%d: failed to get keys(%d)\n", __LINE__, ret);
		ret = 1;
		goto out;
	}
	printf("get_keys returned %d\n%s", ret, v3);

	ret = 0;

out:
	lxc_container_put(c);
	exit(ret);
}
