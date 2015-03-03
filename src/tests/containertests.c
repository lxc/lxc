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

#define MYNAME "lxctest1"

static int destroy_busybox(void)
{
	int status, ret;
	pid_t pid = fork();

	if (pid < 0) {
		perror("fork");
		return -1;
	}
	if (pid == 0) {
		ret = execlp("lxc-destroy", "lxc-destroy", "-f", "-n", MYNAME, NULL);
		// Should not return
		perror("execl");
		exit(1);
	}
again:
	ret = waitpid(pid, &status, 0);
	if (ret == -1) {
		if (errno == EINTR)
			goto again;
		perror("waitpid");
		return -1;
	}
	if (ret != pid)
		goto again;
	if (!WIFEXITED(status))  { // did not exit normally
		fprintf(stderr, "%d: lxc-create exited abnormally\n", __LINE__);
		return -1;
	}
	return WEXITSTATUS(status);
}

static int create_busybox(void)
{
	int status, ret;
	pid_t pid = fork();

	if (pid < 0) {
		perror("fork");
		return -1;
	}
	if (pid == 0) {
		ret = execlp("lxc-create", "lxc-create", "-t", "busybox", "-n", MYNAME, NULL);
		// Should not return
		perror("execl");
		exit(1);
	}
again:
	ret = waitpid(pid, &status, 0);
	if (ret == -1) {
		if (errno == EINTR)
			goto again;
		perror("waitpid");
		return -1;
	}
	if (ret != pid)
		goto again;
	if (!WIFEXITED(status))  { // did not exit normally
		fprintf(stderr, "%d: lxc-create exited abnormally\n", __LINE__);
		return -1;
	}
	return WEXITSTATUS(status);
}

int main(int argc, char *argv[])
{
	struct lxc_container *c;
	int ret = 0;
	const char *s;
	bool b;
	char *str;

	ret = 1;
	/* test refcounting */
	c = lxc_container_new(MYNAME, NULL);
	if (!c) {
		fprintf(stderr, "%d: error creating lxc_container %s\n", __LINE__, MYNAME);
		goto out;
	}
	if (!lxc_container_get(c)) {
		fprintf(stderr, "%d: error getting refcount\n", __LINE__);
		goto out;
	}
	/* peek in, inappropriately, make sure refcount is a we'd like */
	if (c->numthreads != 2) {
		fprintf(stderr, "%d: refcount is %d, not %d\n", __LINE__, c->numthreads, 2);
		goto out;
	}
	if (strcmp(c->name, MYNAME) != 0) {
		fprintf(stderr, "%d: container has wrong name (%s not %s)\n", __LINE__, c->name, MYNAME);
		goto out;
	}
	str = c->config_file_name(c);
#define CONFIGFNAM LXCPATH "/" MYNAME "/config"
	if (!str || strcmp(str, CONFIGFNAM)) {
		fprintf(stderr, "%d: got wrong config file name (%s, not %s)\n", __LINE__, str, CONFIGFNAM);
		goto out;
	}
	free(str);
	free(c->configfile);
	c->configfile = NULL;
	str = c->config_file_name(c);
	if (str) {
		fprintf(stderr, "%d: config file name was not NULL as it should have been\n", __LINE__);
		goto out;
	}
	if (lxc_container_put(c) != 0) {
		fprintf(stderr, "%d: c was freed on non-final put\n", __LINE__);
		goto out;
	}
	if (c->numthreads != 1) {
		fprintf(stderr, "%d: refcount is %d, not %d\n", __LINE__, c->numthreads, 1);
		goto out;
	}
	if (lxc_container_put(c) != 1) {
		fprintf(stderr, "%d: c was not freed on final put\n", __LINE__);
		goto out;
	}

	/* test a real container */
	c = lxc_container_new(MYNAME, NULL);
	if (!c) {
		fprintf(stderr, "%d: error creating lxc_container %s\n", __LINE__, MYNAME);
		ret = 1;
		goto out;
	}

	b = c->is_defined(c);
	if (b) {
		fprintf(stderr, "%d: %s thought it was defined\n", __LINE__, MYNAME);
		goto out;
	}

	s = c->state(c);
	if (s && strcmp(s, "STOPPED") != 0) {
	// liblxc says a container is STOPPED if it doesn't exist.  That's because
	// the container may be an application container - it's not wrong, just
	// sometimes unintuitive.
		fprintf(stderr, "%d: %s thinks it is in state %s\n", __LINE__, c->name, s);
		goto out;
	}

	// create a container
	// the liblxc api does not support creation - it probably will eventually,
	// but not yet.
	// So we just call out to lxc-create.  We'll create a busybox container.
	ret = create_busybox();
	if (ret) {
		fprintf(stderr, "%d: failed to create a busybox container\n", __LINE__);
		goto out;
	}

	b = c->is_defined(c);
	if (!b) {
		fprintf(stderr, "%d: %s thought it was not defined\n", __LINE__, MYNAME);
		goto out;
	}

	s = c->state(c);
	if (!s || strcmp(s, "STOPPED")) {
		fprintf(stderr, "%d: %s is in state %s, not in STOPPED.\n", __LINE__, c->name, s ? s : "undefined");
		goto out;
	}

	b = c->load_config(c, NULL);
	if (!b) {
		fprintf(stderr, "%d: %s failed to read its config\n", __LINE__, c->name);
		goto out;
	}

	// test wait states
	int numstates = lxc_get_wait_states(NULL);
	if (numstates != MAX_STATE) {
		fprintf(stderr, "%d: lxc_get_wait_states gave %d not %d\n", __LINE__, numstates, MAX_STATE);
		goto out;
	}
	const char **sstr = malloc(numstates * sizeof(const char *));
	numstates = lxc_get_wait_states(sstr);
	int i;
	for (i=0; i<numstates; i++) {
		fprintf(stderr, "got state %d %s\n", i, sstr[i]);
	}
	free(sstr);

	/* non-daemonized is tested in 'startone' */
	c->want_daemonize(c, true);
	if (!c->startl(c, 0, NULL, NULL)) {
		fprintf(stderr, "%d: %s failed to start daemonized\n", __LINE__, c->name);
		goto out;
	}

	if (!c->wait(c, "RUNNING", -1)) {
		fprintf(stderr, "%d: failed waiting for state RUNNING\n", __LINE__);
		goto out;
	}

	sleep(3);
	s = c->state(c);
	if (!s || strcmp(s, "RUNNING")) {
		fprintf(stderr, "%d: %s is in state %s, not in RUNNING.\n", __LINE__, c->name, s ? s : "undefined");
		goto out;
	}

	fprintf(stderr, "all lxc_container tests passed for %s\n", c->name);
	ret = 0;

out:
	if (c) {
		c->stop(c);
		destroy_busybox();
	}
	lxc_container_put(c);
	exit(ret);
}
