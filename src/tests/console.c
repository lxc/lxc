/* liblxcapi
 *
 * Copyright © 2013 Oracle.
 *
 * Authors:
 * Dwight Engen <dwight.engen@oracle.com>
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

#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define TTYCNT      4
#define TTYCNT_STR "4"
#define TSTNAME    "lxcconsoletest"
#define MAXCONSOLES 512

#define TSTERR(fmt, ...) do { \
	fprintf(stderr, "%s:%d " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
} while (0)

static void test_console_close_all(int ttyfd[MAXCONSOLES],
				   int masterfd[MAXCONSOLES])
{
	int i;

	for (i = 0; i < MAXCONSOLES; i++) {
		if (masterfd[i] != -1) {
			close(masterfd[i]);
			masterfd[i] = -1;
		}
		if (ttyfd[i] != -1) {
			close(ttyfd[i]);
			ttyfd[i] = -1;
		}
	}
}

static int test_console_running_container(struct lxc_container *c)
{
	int nrconsoles, i, ret = -1;
	int ttynum  [MAXCONSOLES];
	int ttyfd   [MAXCONSOLES];
	int masterfd[MAXCONSOLES];

	for (i = 0; i < MAXCONSOLES; i++)
		ttynum[i] = ttyfd[i] = masterfd[i] = -1;

	ttynum[0] = 1;
	ret = c->console_getfd(c, &ttynum[0], &masterfd[0]);
	if (ret < 0) {
		TSTERR("console allocate failed");
		goto err1;
	}
	ttyfd[0] = ret;
	if (ttynum[0] != 1) {
		TSTERR("console allocate got bad ttynum %d", ttynum[0]);
		goto err2;
	}

	/* attempt to alloc same ttynum */
	ret = c->console_getfd(c, &ttynum[0], &masterfd[1]);
	if (ret != -1) {
		TSTERR("console allocate should fail for allocated ttynum %d", ttynum[0]);
		goto err2;
	}
	close(masterfd[0]); masterfd[0] = -1;
	close(ttyfd[0]); ttyfd[0] = -1;

	/* ensure we can allocate all consoles, we do this a few times to
	 * show that the closes are freeing up the allocated slots
	 */
	for (i = 0; i < 10; i++) {
		for (nrconsoles = 0; nrconsoles < MAXCONSOLES; nrconsoles++) {
			ret = c->console_getfd(c, &ttynum[nrconsoles], &masterfd[nrconsoles]);
			if (ret < 0)
				break;
			ttyfd[nrconsoles] = ret;
		}
		if (nrconsoles != TTYCNT) {
			TSTERR("didn't allocate all consoles %d != %d", nrconsoles, TTYCNT);
			goto err2;
		}
		test_console_close_all(ttyfd, masterfd);
	}
	ret = 0;

err2:
	test_console_close_all(ttyfd, masterfd);
err1:
	return ret;
}

/* test_container: test console function
 *
 * @lxcpath  : the lxcpath in which to create the container
 * @group    : name of the container group or NULL for default "lxc"
 * @name     : name of the container
 * @template : template to use when creating the container
 */
static int test_console(const char *lxcpath,
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
	if (!c->createl(c, template, NULL, NULL, 0, NULL)) {
		TSTERR("creating container %s", name);
		goto out2;
	}
	c->load_config(c, NULL);
	c->set_config_item(c, "lxc.tty", TTYCNT_STR);
	c->save_config(c, NULL);
	c->want_daemonize(c, true);
	if (!c->startl(c, 0, NULL)) {
		TSTERR("starting container %s", name);
		goto out3;
	}

	ret = test_console_running_container(c);

	c->stop(c);
out3:
	c->destroy(c);
out2:
	lxc_container_put(c);
out1:
	return ret;
}

int main(int argc, char *argv[])
{
	int ret;
	ret = test_console(NULL, NULL, TSTNAME, "busybox");
	if (ret < 0)
		goto err1;

	ret = test_console("/var/lib/lxctest2", NULL, TSTNAME, "busybox");
	if (ret < 0)
		goto err1;
	printf("All tests passed\n");
err1:
	return ret;
}
