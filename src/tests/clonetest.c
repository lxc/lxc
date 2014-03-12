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

#define MYNAME "clonetest1"
#define MYNAME2 "clonetest2"

int main(int argc, char *argv[])
{
	struct lxc_container *c = NULL, *c2 = NULL, *c3 = NULL;
	int ret = 1;

	c = lxc_container_new(MYNAME, NULL);
	c2 = lxc_container_new(MYNAME2, NULL);
	if (c) {
		c->destroy(c);
		lxc_container_put(c);
		c = NULL;
	}
	if (c2) {
		c2->destroy(c2);
		lxc_container_put(c2);
		c2 = NULL;
	}

	if ((c = lxc_container_new(MYNAME, NULL)) == NULL) {
		fprintf(stderr, "%d: error opening lxc_container %s\n", __LINE__, MYNAME);
		ret = 1;
		goto out;
	}
	c->save_config(c, NULL);
	if (!c->createl(c, "busybox", NULL, NULL, 0, NULL)) {
		fprintf(stderr, "%d: failed to create a container\n", __LINE__);
		goto out;
	}
	c->load_config(c, NULL);

	if (!c->is_defined(c)) {
		fprintf(stderr, "%d: %s thought it was not defined\n", __LINE__, MYNAME);
		goto out;
	}

	c2 = c->clone(c, MYNAME2, NULL, 0, NULL, NULL, 0, NULL);
	if (!c2) {
		fprintf(stderr, "%d: %s clone returned NULL\n", __LINE__, MYNAME2);
		goto out;
	}

	if (!c2->is_defined(c2)) {
		fprintf(stderr, "%d: %s not defined after clone\n", __LINE__, MYNAME2);
		goto out;
	}

	fprintf(stderr, "directory backing store tests passed\n");

	// now test with lvm
	// Only do this if clonetestlvm1 exists - user has to set this up
	// in advance
	c2->destroy(c2);
	lxc_container_put(c2);
	c->destroy(c);
	lxc_container_put(c);
	c = NULL;

	c2 = lxc_container_new("clonetestlvm2", NULL);
	if (c2) {
		if (c2->is_defined(c2))
			c2->destroy(c2);
		lxc_container_put(c2);
	}
	c2 = lxc_container_new("clonetest-o1", NULL);
	if (c2) {
		if (c2->is_defined(c2))
			c2->destroy(c2);
		lxc_container_put(c2);
	}
	c2 = lxc_container_new("clonetest-o2", NULL);
	if (c2) {
		if (c2->is_defined(c2))
			c2->destroy(c2);
		lxc_container_put(c2);
	}
	c2 = NULL;

	// lvm-copied
	c = lxc_container_new("clonetestlvm1", NULL);
	if (!c) {
		fprintf(stderr, "failed loading clonetestlvm1\n");
		goto out;
	}
	if (!c->is_defined(c)) {
		fprintf(stderr, "clonetestlvm1 does not exist, skipping lvm tests\n");
		ret = 0;
		goto out;
	}

	if ((c2 = c->clone(c, "clonetestlvm2", NULL, 0, NULL, NULL, 0, NULL)) == NULL) {
		fprintf(stderr, "lvm clone failed\n");
		goto out;
	}

	lxc_container_put(c2);

	// lvm-snapshot
	c2 = lxc_container_new("clonetestlvm3", NULL);
	if (c2) {
		if (c2->is_defined(c2))
			c2->destroy(c2);
		lxc_container_put(c2);
		c2 = NULL;
	}

	if ((c2 = c->clone(c, "clonetestlvm3", NULL, LXC_CLONE_SNAPSHOT, NULL, NULL, 0, NULL)) == NULL) {
		fprintf(stderr, "lvm clone failed\n");
		goto out;
	}
	lxc_container_put(c2);
	lxc_container_put(c);
	c = c2 = NULL;

	if ((c = lxc_container_new(MYNAME, NULL)) == NULL) {
		fprintf(stderr, "error opening original container for overlay test\n");
		goto out;
	}

	// Now create an overlayfs clone of a dir-backed container
	if ((c2 = c->clone(c, "clonetest-o1", NULL, LXC_CLONE_SNAPSHOT, "overlayfs", NULL, 0, NULL)) == NULL) {
		fprintf(stderr, "overlayfs clone of dir failed\n");
		goto out;
	}

	// Now create an overlayfs clone of the overlayfs clone
	if ((c3 = c2->clone(c2, "clonetest-o2", NULL, LXC_CLONE_SNAPSHOT, "overlayfs", NULL, 0, NULL)) == NULL) {
		fprintf(stderr, "overlayfs clone of overlayfs failed\n");
		goto out;
	}

	fprintf(stderr, "all clone tests passed for %s\n", c->name);
	ret = 0;

out:
	if (c3) {
		lxc_container_put(c3);
	}
	if (c2) {
		c2->destroy(c2);
		lxc_container_put(c2);
	}
	if (c) {
		c->destroy(c);
		lxc_container_put(c);
	}
	exit(ret);
}
