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
#include "lxc/state.h"

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

	c->set_config_item(c, "lxc.network.type", "veth");

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

	ret = c->get_keys(c, "lxc.network.0", v3, 2000);
	if (ret < 0) {
		fprintf(stderr, "%d: failed to get nic 0 keys(%d)\n", __LINE__, ret);
		ret = 1;
		goto out;
	}
	printf("get_keys for nic 1 returned %d\n%s", ret, v3);
	ret = 0;

out:
	lxc_container_put(c);
	exit(ret);
}
