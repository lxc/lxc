/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Daniel Lezcano <dlezcano at fr.ibm.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/file.h>

#include <lxc.h>
#include <state.h>
#include <log.h>

static char *strstate[] = {
	"STOPPED", "STARTING", "RUNNING", "STOPPING",
	"ABORTING", "FREEZING", "FROZEN",
};

const char *state2str(lxc_state_t state)
{
	if (state < STOPPED || state > MAX_STATE - 1)
		return NULL;
	return strstate[state];
}

lxc_state_t str2state(const char *state)
{
	int i, len;
	len = sizeof(strstate)/sizeof(strstate[0]);
	for (i = 0; i < len; i++)
		if (!strcmp(strstate[i], state))
			return i;
	return -1;
}

int lxc_setstate(const char *name, lxc_state_t state)
{
	int fd, err;
	char file[MAXPATHLEN];
	const char *str = state2str(state);

	if (!str)
		return -1;

	snprintf(file, MAXPATHLEN, LXCPATH "/%s/state", name);

	fd = open(file, O_WRONLY);
	if (fd < 0) {
		lxc_log_syserror("failed to open %s file", file);
		return -1;
	}

	if (flock(fd, LOCK_EX)) {
		lxc_log_syserror("failed to take the lock to %s", file);
		goto out;
	}

	if (ftruncate(fd, 0)) {
		lxc_log_syserror("failed to truncate the file %s", file);
		goto out;
	}

	if (write(fd, str, strlen(str)) < 0) {
		lxc_log_syserror("failed to write state to %s", file);
		goto out;
	}

	err = 0;
out:
	close(fd);

	/* let the event to be propagated, crappy but that works,
	 * otherwise the events will be folded into only one event,
	 * and I want to have them to be one by one in order
	 * to follow the different states of the container.
	 */
 	usleep(200000);

	return -err;
}

int mkstate(const char *name)
{
	int fd;
	char file[MAXPATHLEN];

	snprintf(file, MAXPATHLEN, LXCPATH "/%s/state", name);
	fd = creat(file, S_IRUSR|S_IWUSR);
	if (fd < 0) {
		lxc_log_syserror("failed to create file %s", file);
		return -1;
	}
	close(fd);
	return 0;
}

int rmstate(const char *name)
{
	char file[MAXPATHLEN];
	snprintf(file, MAXPATHLEN, LXCPATH "/%s/state", name);
	unlink(file);
	return 0;
}

lxc_state_t lxc_getstate(const char *name)
{
	int fd, err;
	char file[MAXPATHLEN];

	snprintf(file, MAXPATHLEN, LXCPATH "/%s/state", name);

	fd = open(file, O_RDONLY);
	if (fd < 0) {
		lxc_log_syserror("failed to open %s", file);
		return -1;
	}

	if (flock(fd, LOCK_SH)) {
		lxc_log_syserror("failed to take the lock to %s", file);
		close(fd);
		return -1;
	}

	err = read(fd, file, strlen(file));
	if (err < 0) {
		lxc_log_syserror("failed to read file %s", file);
		close(fd);
		return -1;
	}
	file[err] = '\0';

	close(fd);
	return str2state(file);
}

static int freezer_state(const char *name)
{
	char freezer[MAXPATHLEN];
	char status[MAXPATHLEN];
	FILE *file;
	int err;
	
	snprintf(freezer, MAXPATHLEN,
		 LXCPATH "/%s/freezer.freeze", name);

	file = fopen(freezer, "r");
	if (file < 0) {
		lxc_log_syserror("failed to open %s", freezer);
		return -1;
	}

	err = fscanf(file, "%s", status);
	fclose(file);

	if (err == EOF) {
		lxc_log_syserror("failed to read %s", freezer);
		return -1;
	}

	return str2state(status);
}

lxc_state_t lxc_state(const char *name)
{
	int state = freezer_state(name);
	if (state != FROZEN && state != FREEZING)
		state = lxc_getstate(name);
	return state;
}
