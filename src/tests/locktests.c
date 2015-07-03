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
#include "lxc/lxclock.h"
#include "config.h"
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>

#define mycontainername "lxctest.sem"
#define TIMEOUT_SECS 3

static void test_two_locks(void)
{
	struct lxc_lock *l;
	pid_t pid;
	int ret, status;
	int p[2];
	char c;

	if (pipe(p) < 0)
		exit(1);
	if ((pid = fork()) < 0)
		exit(1);
	if (pid == 0) {
		if (read(p[0], &c, 1) < 0) {
			perror("read");
			exit(1);
		}
		l = lxc_newlock("/tmp", "lxctest-sem");
		if (!l) {
			fprintf(stderr, "%d: child: failed to create lock\n", __LINE__);
			exit(1);
		}
		if (lxclock(l, 0) < 0) {
			fprintf(stderr, "%d: child: failed to grab lock\n", __LINE__);
			exit(1);
		}
		fprintf(stderr, "%d: child: grabbed lock\n", __LINE__);
		exit(0);
	}
	l = lxc_newlock("/tmp", "lxctest-sem");
	if (!l) {
		fprintf(stderr, "%d: failed to create lock\n", __LINE__);
		exit(1);
	}
	if (lxclock(l, 0) < 0) {
		fprintf(stderr, "%d; failed to get lock\n", __LINE__);
		exit(1);
	}
	if (write(p[1], "a", 1) < 0) {
		perror("write");
		exit(1);
	}
	sleep(3);
	ret = waitpid(pid, &status, WNOHANG);
	if (ret == pid) { // task exited
		if (WIFEXITED(status)) {
			printf("%d exited normally with exit code %d\n", pid,
				WEXITSTATUS(status));
			if (WEXITSTATUS(status) == 0)
				exit(1);
		} else
			printf("%d did not exit normally\n", pid);
		return;
	} else if (ret < 0) {
		perror("waitpid");
		exit(1);
	}
	kill(pid, SIGKILL);
	wait(&status);
	close(p[1]);
	close(p[0]);
	lxcunlock(l);
	lxc_putlock(l);
}

int main(int argc, char *argv[])
{
	int ret;
	struct lxc_lock *lock;

	lock = lxc_newlock(NULL, NULL);
	if (!lock) {
		fprintf(stderr, "%d: failed to get unnamed lock\n", __LINE__);
		exit(1);
	}
	ret = lxclock(lock, 0);
	if (ret) {
		fprintf(stderr, "%d: failed to take unnamed lock (%d)\n", __LINE__, ret);
		exit(1);
	}

	ret = lxcunlock(lock);
	if (ret) {
		fprintf(stderr, "%d: failed to put unnamed lock (%d)\n", __LINE__, ret);
		exit(1);
	}
	lxc_putlock(lock);

	lock = lxc_newlock("/var/lib/lxc", mycontainername);
	if (!lock) {
		fprintf(stderr, "%d: failed to get lock\n", __LINE__);
		exit(1);
	}
	struct stat sb;
	char *pathname = RUNTIME_PATH "/lxc/lock/var/lib/lxc/";
	ret = stat(pathname, &sb);
	if (ret != 0) {
		fprintf(stderr, "%d: filename %s not created\n", __LINE__,
			pathname);
		exit(1);
	}
	lxc_putlock(lock);

	test_two_locks();

	fprintf(stderr, "all tests passed\n");

	exit(ret);
}
