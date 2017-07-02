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
#include <lxc/lxccontainer.h>

#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "lxc/state.h"
#include "lxctest.h"

#define MYNAME "lxctest1"

int main(int argc, char *argv[])
{
	int ret = EXIT_FAILURE;
	struct lxc_container *c;
	char v1[2], v2[256], v3[2048];

	if ((c = lxc_container_new("testxyz", NULL)) == NULL) {
		fprintf(stderr, "%d: error opening lxc_container %s\n", __LINE__, MYNAME);
		exit(EXIT_FAILURE);
	}

	/* EXPECT SUCCESS: lxc.syslog with valid value. */
	if (!c->set_config_item(c, "lxc.syslog", "local0")) {
		lxc_error("%s\n", "Failed to set lxc.syslog.\n");
		goto out;
	}
	ret = c->get_config_item(c, "lxc.syslog", v2, 255);
	if (ret < 0) {
		lxc_error("Failed to retrieve lxc.syslog: %d.\n", ret);
		goto out;
	}
	if (strcmp(v2, "local0") != 0) {
		lxc_error("Expected: local0 == %s.\n", v2);
		goto out;
	}
	lxc_debug("Retrieving value for lxc.syslog correctly returned: %s.\n", v2);

	/* EXPECT FAILURE: lxc.syslog with invalid value. */
	if (c->set_config_item(c, "lxc.syslog", "NONSENSE")) {
		lxc_error("%s\n", "Succeeded int setting lxc.syslog to invalid value \"NONSENSE\".\n");
		goto out;
	}
	lxc_debug("%s\n", "Successfully failed to set lxc.syslog to invalid value.\n");

	if (!c->set_config_item(c, "lxc.hook.pre-start", "hi there")) {
		fprintf(stderr, "%d: failed to set hook.pre-start\n", __LINE__);
		goto out;
	}
	ret = c->get_config_item(c, "lxc.hook.pre-start", v2, 255);
	if (ret < 0) {
		fprintf(stderr, "%d: get_config_item(lxc.hook.pre-start) returned %d\n", __LINE__, ret);
		goto out;
	}
	fprintf(stderr, "lxc.hook.pre-start returned %d %s\n", ret, v2);

	ret = c->get_config_item(c, "lxc.network", v2, 255);
	if (ret < 0) {
		fprintf(stderr, "%d: get_config_item returned %d\n", __LINE__, ret);
		goto out;
	}
	fprintf(stderr, "%d: get_config_item(lxc.network) returned %d %s\n", __LINE__, ret, v2);


	/* REMOVE IN LXC 3.0
	   legacy lxc.tty key
	 */
	if (!c->set_config_item(c, "lxc.tty", "4")) {
		fprintf(stderr, "%d: failed to set tty\n", __LINE__);
		goto out;
	}
	ret = c->get_config_item(c, "lxc.tty", v2, 255);
	if (ret < 0) {
		fprintf(stderr, "%d: get_config_item(lxc.tty) returned %d\n", __LINE__, ret);
		goto out;
	}
	fprintf(stderr, "lxc.tty returned %d %s\n", ret, v2);

	if (!c->set_config_item(c, "lxc.arch", "x86")) {
		fprintf(stderr, "%d: failed to set arch\n", __LINE__);
		goto out;
	}
	ret = c->get_config_item(c, "lxc.arch", v2, 255);
	if (ret < 0) {
		fprintf(stderr, "%d: get_config_item(lxc.arch) returned %d\n", __LINE__, ret);
		goto out;
	}
	printf("lxc.arch returned %d %s\n", ret, v2);

	if (!c->set_config_item(c, "lxc.init_uid", "100")) {
		fprintf(stderr, "%d: failed to set init_uid\n", __LINE__);
		goto out;
	}
	ret = c->get_config_item(c, "lxc.init_uid", v2, 255);
	if (ret < 0) {
		fprintf(stderr, "%d: get_config_item(lxc.init_uid) returned %d\n", __LINE__, ret);
		goto out;
	}
	printf("lxc.init_uid returned %d %s\n", ret, v2);

	if (!c->set_config_item(c, "lxc.init_gid", "100")) {
		fprintf(stderr, "%d: failed to set init_gid\n", __LINE__);
		goto out;
	}
	ret = c->get_config_item(c, "lxc.init_gid", v2, 255);
	if (ret < 0) {
		fprintf(stderr, "%d: get_config_item(lxc.init_gid) returned %d\n", __LINE__, ret);
		goto out;
	}
	printf("lxc.init_gid returned %d %s\n", ret, v2);

#define HNAME "hostname1"
	// demonstrate proper usage:
	char *alloced;
	if (!c->set_config_item(c, "lxc.utsname", HNAME)) {
		fprintf(stderr, "%d: failed to set utsname\n", __LINE__);
		goto out;
	}

	int len;
	len = c->get_config_item(c, "lxc.utsname", NULL, 0);  // query the size of the string
	if (len < 0) {
		fprintf(stderr, "%d: get_config_item(lxc.utsname) returned %d\n", __LINE__, len);
		goto out;
	}
	printf("lxc.utsname returned %d\n", len);

	// allocate the length of string + 1 for trailing \0
	alloced = malloc(len+1);
	if (!alloced) {
		fprintf(stderr, "%d: failed to allocate %d bytes for utsname\n", __LINE__, len);
		goto out;
	}
	// now pass in the malloc'd array, and pass in length of string + 1: again
	// because we need room for the trailing \0
	ret = c->get_config_item(c, "lxc.utsname", alloced, len+1);
	if (ret < 0) {
		fprintf(stderr, "%d: get_config_item(lxc.utsname) returned %d\n", __LINE__, ret);
		goto out;
	}
	if (strcmp(alloced, HNAME) != 0 || ret != len) {
		fprintf(stderr, "lxc.utsname returned wrong value: %d %s not %d %s\n", ret, alloced, len, HNAME);
		goto out;
	}
	printf("lxc.utsname returned %d %s\n", len, alloced);
	free(alloced);

	if (!c->set_config_item(c, "lxc.mount.entry", "hi there")) {
		fprintf(stderr, "%d: failed to set mount.entry\n", __LINE__);
		goto out;
	}
	ret = c->get_config_item(c, "lxc.mount.entry", v2, 255);
	if (ret < 0) {
		fprintf(stderr, "%d: get_config_item(lxc.mount.entry) returned %d\n", __LINE__, ret);
		goto out;
	}
	printf("lxc.mount.entry returned %d %s\n", ret, v2);

	ret = c->get_config_item(c, "lxc.limit", v3, 2047);
	if (ret != 0) {
		fprintf(stderr, "%d: get_config_item(limit) returned %d\n", __LINE__, ret);
		goto out;
	}

	if (!c->set_config_item(c, "lxc.limit.nofile", "1234:unlimited")) {
		fprintf(stderr, "%d: failed to set limit.nofile\n", __LINE__);
		goto out;
	}
	ret = c->get_config_item(c, "lxc.limit.nofile", v2, 255);
	if (ret < 0) {
		fprintf(stderr, "%d: get_config_item(lxc.limit.nofile) returned %d\n", __LINE__, ret);
		goto out;
	}
	if (strcmp(v2, "1234:unlimited")) {
		fprintf(stderr, "%d: lxc.limit.nofile returned wrong value: %d %s not 14 1234:unlimited\n", __LINE__, ret, v2);
		goto out;
	}
	printf("lxc.limit.nofile returned %d %s\n", ret, v2);

	if (!c->set_config_item(c, "lxc.limit.stack", "unlimited")) {
		fprintf(stderr, "%d: failed to set limit.stack\n", __LINE__);
		goto out;
	}
	ret = c->get_config_item(c, "lxc.limit.stack", v2, 255);
	if (ret < 0) {
		fprintf(stderr, "%d: get_config_item(lxc.limit.stack) returned %d\n", __LINE__, ret);
		goto out;
	}
	if (strcmp(v2, "unlimited")) {
		fprintf(stderr, "%d: lxc.limit.stack returned wrong value: %d %s not 9 unlimited\n", __LINE__, ret, v2);
		goto out;
	}
	printf("lxc.limit.stack returned %d %s\n", ret, v2);

#define LIMIT_STACK "lxc.limit.stack = unlimited\n"
#define ALL_LIMITS "lxc.limit.nofile = 1234:unlimited\n" LIMIT_STACK
	ret = c->get_config_item(c, "lxc.limit", v3, 2047);
	if (ret != sizeof(ALL_LIMITS)-1) {
		fprintf(stderr, "%d: get_config_item(limit) returned %d\n", __LINE__, ret);
		goto out;
	}
	if (strcmp(v3, ALL_LIMITS)) {
		fprintf(stderr, "%d: lxc.limit returned wrong value: %d %s not %d %s\n", __LINE__, ret, v3, (int)sizeof(ALL_LIMITS)-1, ALL_LIMITS);
		goto out;
	}
	printf("lxc.limit returned %d %s\n", ret, v3);

	if (!c->clear_config_item(c, "lxc.limit.nofile")) {
		fprintf(stderr, "%d: failed clearing limit.nofile\n", __LINE__);
		goto out;
	}
	ret = c->get_config_item(c, "lxc.limit", v3, 2047);
	if (ret != sizeof(LIMIT_STACK)-1) {
		fprintf(stderr, "%d: get_config_item(limit) returned %d\n", __LINE__, ret);
		goto out;
	}
	if (strcmp(v3, LIMIT_STACK)) {
		fprintf(stderr, "%d: lxc.limit returned wrong value: %d %s not %d %s\n", __LINE__, ret, v3, (int)sizeof(LIMIT_STACK)-1, LIMIT_STACK);
		goto out;
	}
	printf("lxc.limit returned %d %s\n", ret, v3);

	if (!c->set_config_item(c, "lxc.aa_profile", "unconfined")) {
		fprintf(stderr, "%d: failed to set aa_profile\n", __LINE__);
		goto out;
	}
	ret = c->get_config_item(c, "lxc.aa_profile", v2, 255);
	if (ret < 0) {
		fprintf(stderr, "%d: get_config_item(lxc.aa_profile) returned %d\n", __LINE__, ret);
		goto out;
	}
	printf("lxc.aa_profile returned %d %s\n", ret, v2);

	lxc_container_put(c);

	// new test with real container
	if ((c = lxc_container_new(MYNAME, NULL)) == NULL) {
		fprintf(stderr, "%d: error opening lxc_container %s\n", __LINE__, MYNAME);
		goto out;
	}
	c->destroy(c);
	lxc_container_put(c);

	if ((c = lxc_container_new(MYNAME, NULL)) == NULL) {
		fprintf(stderr, "%d: error opening lxc_container %s\n", __LINE__, MYNAME);
		goto out;
	}
	if (!c->createl(c, "busybox", NULL, NULL, 0, NULL)) {
		fprintf(stderr, "%d: failed to create a trusty container\n", __LINE__);
		goto out;
	}
	lxc_container_put(c);

	/* XXX TODO load_config needs to clear out any old config first */
	if ((c = lxc_container_new(MYNAME, NULL)) == NULL) {
		fprintf(stderr, "%d: error opening lxc_container %s\n", __LINE__, MYNAME);
		goto out;
	}

	ret = c->get_config_item(c, "lxc.cap.drop", NULL, 300);
	if (ret < 5 || ret > 255) {
		fprintf(stderr, "%d: get_config_item(lxc.cap.drop) with NULL returned %d\n", __LINE__, ret);
		goto out;
	}
	ret = c->get_config_item(c, "lxc.cap.drop", v1, 1);
	if (ret < 5 || ret > 255) {
		fprintf(stderr, "%d: get_config_item(lxc.cap.drop) returned %d\n", __LINE__, ret);
		goto out;
	}
	ret = c->get_config_item(c, "lxc.cap.drop", v2, 255);
	if (ret < 0) {
		fprintf(stderr, "%d: get_config_item(lxc.cap.drop) returned %d %s\n", __LINE__, ret, v2);
		goto out;
	}
	printf("%d: get_config_item(lxc.cap.drop) returned %d %s\n", __LINE__, ret, v2);
	ret = c->get_config_item(c, "lxc.network", v2, 255);
	if (ret < 0) {
		fprintf(stderr, "%d: get_config_item(lxc.network) returned %d\n", __LINE__, ret);
		goto out;
	}
	printf("%d: get_config_item(lxc.network) returned %d %s\n", __LINE__, ret, v2);

	if (!c->set_config_item(c, "lxc.network.type", "veth")) {
		fprintf(stderr, "%d: failed to set network.type\n", __LINE__);
		goto out;
	}
	if (!c->set_config_item(c, "lxc.network.link", "lxcbr0")) {
		fprintf(stderr, "%d: failed to set network.link\n", __LINE__);
		goto out;
	}
	if (!c->set_config_item(c, "lxc.network.flags", "up")) {
		fprintf(stderr, "%d: failed to set network.flags\n", __LINE__);
		goto out;
	}
	if (!c->set_config_item(c, "lxc.network.hwaddr", "00:16:3e:xx:xx:xx")) {
		fprintf(stderr, "%d: failed to set network.hwaddr\n", __LINE__);
		goto out;
	}
	if (!c->set_config_item(c, "lxc.network.ipv4", "10.2.3.4")) {
		fprintf(stderr, "%d: failed to set ipv4\n", __LINE__);
		goto out;
	}

	ret = c->get_config_item(c, "lxc.network.0.ipv4", v2, 255);
	if (ret <= 0) {
		fprintf(stderr, "%d: lxc.network.0.ipv4 returned %d\n", __LINE__, ret);
		goto out;
	}
	if (!c->clear_config_item(c, "lxc.network.0.ipv4")) {
		fprintf(stderr, "%d: failed clearing all ipv4 entries\n", __LINE__);
		goto out;
	}
	ret = c->get_config_item(c, "lxc.network.0.ipv4", v2, 255);
	if (ret != 0) {
		fprintf(stderr, "%d: after clearing ipv4 entries get_item(lxc.network.0.ipv4 returned %d\n", __LINE__, ret);
		goto out;
	}

	if (!c->set_config_item(c, "lxc.network.ipv4.gateway", "10.2.3.254")) {
		fprintf(stderr, "%d: failed to set ipv4.gateway\n", __LINE__);
		goto out;
	}

	ret = c->get_config_item(c, "lxc.network.0.ipv4.gateway", v2, 255);
	if (ret <= 0) {
		fprintf(stderr, "%d: lxc.network.0.ipv4.gateway returned %d\n", __LINE__, ret);
		goto out;
	}
	if (!c->set_config_item(c, "lxc.network.0.ipv4.gateway", "")) {
		fprintf(stderr, "%d: failed clearing ipv4.gateway\n", __LINE__);
		goto out;
	}
	ret = c->get_config_item(c, "lxc.network.0.ipv4.gateway", v2, 255);
	if (ret != 0) {
		fprintf(stderr, "%d: after clearing ipv4.gateway get_item(lxc.network.0.ipv4.gateway returned %d\n", __LINE__, ret);
		goto out;
	}

	ret = c->get_config_item(c, "lxc.network.0.link", v2, 255);
	if (ret < 0) {
		fprintf(stderr, "%d: get_config_item returned %d\n", __LINE__, ret);
		goto out;
	}
	printf("%d: get_config_item (link) returned %d %s\n", __LINE__, ret, v2);
	ret = c->get_config_item(c, "lxc.network.0.name", v2, 255);
	if (ret < 0) {
		fprintf(stderr, "%d: get_config_item returned %d\n", __LINE__, ret);
		goto out;
	}
	printf("%d: get_config_item (name) returned %d %s\n", __LINE__, ret, v2);

	if (!c->clear_config_item(c, "lxc.network")) {
		fprintf(stderr, "%d: clear_config_item failed\n", __LINE__);
		goto out;
	}
	ret = c->get_config_item(c, "lxc.network", v2, 255);
	if (ret != 0) {
		fprintf(stderr, "%d: network was not actually cleared (get_network returned %d)\n", __LINE__, ret);
		goto out;
	}

	ret = c->get_config_item(c, "lxc.cgroup", v3, 2047);
	if (ret < 0) {
		fprintf(stderr, "%d: get_config_item(cgroup.devices) returned %d\n", __LINE__, ret);
		goto out;
	}
	printf("%d: get_config_item (cgroup.devices) returned %d %s\n", __LINE__, ret, v3);

	ret = c->get_config_item(c, "lxc.cgroup.devices.allow", v3, 2047);
	if (ret < 0) {
		fprintf(stderr, "%d: get_config_item(cgroup.devices.devices.allow) returned %d\n", __LINE__, ret);
		goto out;
	}
	printf("%d: get_config_item (cgroup.devices.devices.allow) returned %d %s\n", __LINE__, ret, v3);

	if (!c->clear_config_item(c, "lxc.cgroup")) {
		fprintf(stderr, "%d: failed clearing lxc.cgroup\n", __LINE__);
		goto out;
	}
	if (!c->clear_config_item(c, "lxc.cap.drop")) {
		fprintf(stderr, "%d: failed clearing lxc.cap.drop\n", __LINE__);
		goto out;
	}
	if (!c->clear_config_item(c, "lxc.mount.entry")) {
		fprintf(stderr, "%d: failed clearing lxc.mount.entry\n", __LINE__);
		goto out;
	}
	if (!c->clear_config_item(c, "lxc.hook")) {
		fprintf(stderr, "%d: failed clearing lxc.hook\n", __LINE__);
		goto out;
	}

	if (!lxc_config_item_is_supported("lxc.arch")) {
		fprintf(stderr, "%d: failed to report \"lxc.arch\" as supported configuration item\n", __LINE__);
		goto out;
	}

	if (lxc_config_item_is_supported("lxc.nonsense")) {
		fprintf(stderr, "%d: failed to detect \"lxc.nonsense\" as unsupported configuration item\n", __LINE__);
		goto out;
	}

	printf("All get_item tests passed\n");
	ret = EXIT_SUCCESS;
out:
	c->destroy(c);
	lxc_container_put(c);
	exit(ret);
}
