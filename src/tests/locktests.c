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
#include "../lxc/lxclock.h"
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>

#define mycontainername "lxctest.sem"
#define TIMEOUT_SECS 3

int timedout;
int pid_to_kill;

void timeouthandler(int sig)
{
	// timeout received
	timedout = 1;
	kill(pid_to_kill, SIGTERM);
}

void starttimer(int secs)
{
	timedout = 0;
	signal(SIGALRM, timeouthandler);
	alarm(secs);
}
void stoptimer(void)
{
	alarm(0);
	signal(SIGALRM, NULL);
}

int test_one_lock(sem_t *lock)
{
	int ret;
	starttimer(TIMEOUT_SECS);
	ret = lxclock(lock, TIMEOUT_SECS*2);
	stoptimer();
	if (ret == 0) {
		lxcunlock(lock);
		return 0;
	}
	if (timedout)
		fprintf(stderr, "%d: timed out waiting for lock\n", __LINE__);
	else
		fprintf(stderr, "%d: failed to get single lock\n", __LINE__);
	return 1;
}

/*
 * get one lock.  Fork a second task to try to get a second lock,
 * with infinite timeout.  If our alarm hits, kill the second
 * task.  If second task does not
 */
int test_two_locks(sem_t *lock)
{
	int status;
    int ret;

	ret = lxclock(lock, 1);
	if (ret) {
		fprintf(stderr, "%d: Error getting first lock\n", __LINE__);
		return 2;
	}

	pid_to_kill = fork();
	if (pid_to_kill < 0) {
		fprintf(stderr, "%d: Failed to fork\n", __LINE__);
		lxcunlock(lock);
		return 3;
	}

	if (pid_to_kill == 0) { // child
		ret = lxclock(lock, TIMEOUT_SECS*2);
		if (ret == 0) {
			lxcunlock(lock);
			exit(0);
		}
		fprintf(stderr, "%d: child, was not able to get lock\n", __LINE__);
		exit(1);
	}
	starttimer(TIMEOUT_SECS);
	waitpid(pid_to_kill, &status, 0);
	stoptimer();
	if (WIFEXITED(status)) {
		// child exited normally - timeout didn't kill it
		if (WEXITSTATUS(status) == 0)
			fprintf(stderr, "%d: child was able to get the lock\n", __LINE__);
		else
			fprintf(stderr, "%d: child timed out too early\n", __LINE__);
		lxcunlock(lock);
		return 1;
	}
	lxcunlock(lock);
	return 0;
}

/*
 * get one lock.  try to get second lock, but asking for timeout.  If
 * should return failure.  If our own alarm, set at twice the lock
 * request's timeout, hits, then lxclock() did not properly time out.
 */
int test_with_timeout(sem_t *lock)
{
	int status;
	int ret = 0;

	ret = lxclock(lock, 0);
	if (ret) {
		fprintf(stderr, "%d: Error getting first lock\n", __LINE__);
		return 2;
	}
	pid_to_kill = fork();
	if (pid_to_kill < 0) {
		fprintf(stderr, "%d: Error on fork\n", __LINE__);
		lxcunlock(lock);
		return 2;
	}
	if (pid_to_kill == 0) {
		ret = lxclock(lock, TIMEOUT_SECS);
		if (ret == 0) {
			lxcunlock(lock);
			exit(0);
		}
		exit(1);
	}
	starttimer(TIMEOUT_SECS * 2);
	waitpid(pid_to_kill, &status, 0);
	stoptimer();
	if (!WIFEXITED(status)) {
		fprintf(stderr, "%d: lxclock did not honor its timeout\n", __LINE__);
		lxcunlock(lock);
		return 1;
	}
	if (WEXITSTATUS(status) == 0) {
		fprintf(stderr, "%d: child was able to get lock, should have failed with timeout\n", __LINE__);
		ret = 1;
	}
	lxcunlock(lock);
	return ret;
}

int main(int argc, char *argv[])
{
	int ret, sval, r;
	sem_t *lock;

	lock = lxc_newlock(NULL);
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

    sem_destroy(lock);
    free(lock);

	lock = lxc_newlock(mycontainername);
	if (!lock) {
		fprintf(stderr, "%d: failed to get lock\n", __LINE__);
		exit(1);
	}
	r = sem_getvalue(lock, &sval);
	if (!r) {
		fprintf(stderr, "%d: sem value at start is %d\n", __LINE__, sval);
	} else {
		fprintf(stderr, "%d: failed to get initial value\n", __LINE__);
	}

	ret = test_one_lock(lock);
	if (ret) {
		fprintf(stderr, "%d: test failed\n", __LINE__);
		goto out;
	}
	r = sem_getvalue(lock, &sval);
	if (!r) {
		fprintf(stderr, "%d: sem value is %d\n", __LINE__, sval);
	} else {
		fprintf(stderr, "%d: failed to get sem value\n", __LINE__);
	}

	ret = test_two_locks(lock);
	if (ret) {
		fprintf(stderr, "%d: test failed\n", __LINE__);
		goto out;
	}
	r = sem_getvalue(lock, &sval);
	if (!r) {
		fprintf(stderr, "%d: sem value is %d\n", __LINE__, sval);
	} else {
		fprintf(stderr, "%d: failed to get value\n", __LINE__);
	}

	ret = test_with_timeout(lock);
	if (ret) {
		fprintf(stderr, "%d: test failed\n", __LINE__);
		goto out;
	}
	r = sem_getvalue(lock, &sval);
	if (!r) {
		fprintf(stderr, "%d: sem value is %d\n", __LINE__, sval);
	} else {
		fprintf(stderr, "%d: failed to get value\n", __LINE__);
	}

    fprintf(stderr, "all tests passed\n");

out:
	exit(ret);
}
