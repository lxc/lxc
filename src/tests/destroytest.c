/* liblxcapi
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "config.h"

#include <lxc/lxccontainer.h>

#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <errno.h>

#define MYNAME "lxctest1"

static int create_container(void)
{
	int status, ret;
	pid_t pid = fork();

	if (pid < 0) {
		perror("fork");
		return -1;
	}

	if (pid == 0) {
		execlp("lxc-create", "lxc-create", "-t", "busybox", "-n", MYNAME, NULL);
		exit(EXIT_FAILURE);
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
	int ret = 1;

	if ((c = lxc_container_new(MYNAME, NULL)) == NULL) {
		fprintf(stderr, "%d: error opening lxc_container %s\n", __LINE__, MYNAME);
		ret = 1;
		goto out;
	}

	if (c->is_defined(c)) {
		fprintf(stderr, "%d: %s thought it was defined\n", __LINE__, MYNAME);
		goto out;
	}

	if (create_container()) {
		fprintf(stderr, "%d: failed to create a container\n", __LINE__);
		goto out;
	}

	if (!c->is_defined(c)) {
		fprintf(stderr, "%d: %s thought it was not defined\n", __LINE__, MYNAME);
		goto out;
	}

	if (!c->destroy(c)) {
		fprintf(stderr, "%d: error deleting %s\n", __LINE__, MYNAME);
		goto out;
	}

	if (c->is_defined(c)) {
		fprintf(stderr, "%d: %s thought it was defined\n", __LINE__, MYNAME);
		goto out;
	}

	fprintf(stderr, "all lxc_container tests passed for %s\n", c->name);
	ret = 0;

out:
	lxc_container_put(c);
	exit(ret);
}
