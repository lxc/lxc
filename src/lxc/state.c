/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Daniel Lezcano <daniel.lezcano at free.fr>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/file.h>

#include <lxc/lxc.h>
#include <lxc/log.h>
#include <lxc/start.h>
#include <lxc/cgroup.h>
#include <lxc/monitor.h>
#include "commands.h"
#include "config.h"

lxc_log_define(lxc_state, lxc);

static char *strstate[] = {
	"STOPPED", "STARTING", "RUNNING", "STOPPING",
	"ABORTING", "FREEZING", "FROZEN", "THAWED",
};

const char *lxc_state2str(lxc_state_t state)
{
	if (state < STOPPED || state > MAX_STATE - 1)
		return NULL;
	return strstate[state];
}

lxc_state_t lxc_str2state(const char *state)
{
	size_t len;
	lxc_state_t i;
	len = sizeof(strstate)/sizeof(strstate[0]);
	for (i = 0; i < len; i++)
		if (!strcmp(strstate[i], state))
			return i;

	ERROR("invalid state '%s'", state);
	return -1;
}

static lxc_state_t freezer_state(const char *name, const char *lxcpath)
{
	char *cgabspath = NULL;
	char freezer[MAXPATHLEN];
	char status[MAXPATHLEN];
	FILE *file;
	int ret;

	cgabspath = lxc_cgroup_get_hierarchy_abs_path("freezer", name, lxcpath);
	if (!cgabspath)
		return -1;

	ret = snprintf(freezer, MAXPATHLEN, "%s/freezer.state", cgabspath);
	if (ret < 0 || ret >= MAXPATHLEN)
		goto out;

	file = fopen(freezer, "r");
	if (!file) {
		ret = -1;
		goto out;
	}

	ret = fscanf(file, "%s", status);
	fclose(file);

	if (ret == EOF) {
		SYSERROR("failed to read %s", freezer);
		ret = -1;
		goto out;
	}

	ret = lxc_str2state(status);

out:
	free(cgabspath);
	return ret;
}

lxc_state_t lxc_getstate(const char *name, const char *lxcpath)
{
	lxc_state_t state = freezer_state(name, lxcpath);
	if (state != FROZEN && state != FREEZING)
		state = lxc_cmd_get_state(name, lxcpath);
	return state;
}

static int fillwaitedstates(const char *strstates, int *states)
{
	char *token, *saveptr = NULL;
	char *strstates_dup = strdup(strstates);
	int state;

	if (!strstates_dup)
		return -1;

	token = strtok_r(strstates_dup, "|", &saveptr);
	while (token) {

		state = lxc_str2state(token);
		if (state < 0) {
			free(strstates_dup);
			return -1;
		}

		states[state] = 1;

		token = strtok_r(NULL, "|", &saveptr);
	}
	free(strstates_dup);
	return 0;
}

extern int lxc_wait(const char *lxcname, const char *states, int timeout, const char *lxcpath)
{
	struct lxc_msg msg;
	int state, ret;
	int s[MAX_STATE] = { }, fd;

	if (fillwaitedstates(states, s))
		return -1;

	if (lxc_monitord_spawn(lxcpath))
		return -1;

	fd = lxc_monitor_open(lxcpath);
	if (fd < 0)
		return -1;

	/*
	 * if container present,
	 * then check if already in requested state
	 */
	ret = -1;
	state = lxc_getstate(lxcname, lxcpath);
	if (state < 0) {
		goto out_close;
	} else if ((state >= 0) && (s[state])) {
		ret = 0;
		goto out_close;
	}

	for (;;) {
		int elapsed_time, curtime = 0;
		struct timeval tv;
		int stop = 0;
		int retval;

		if (timeout != -1) {
			retval = gettimeofday(&tv, NULL);
			if (retval)
				goto out_close;
			curtime = tv.tv_sec;
		}
		if (lxc_monitor_read_timeout(fd, &msg, timeout) < 0) {
			/* try again if select interrupted by signal */
			if (errno != EINTR)
				goto out_close;
		}

		if (timeout != -1) {
			retval = gettimeofday(&tv, NULL);
			if (retval)
				goto out_close;
			elapsed_time = tv.tv_sec - curtime;
			if (timeout - elapsed_time <= 0)
				stop = 1;
			timeout -= elapsed_time;
		}

		if (strcmp(lxcname, msg.name)) {
			if (stop) {
				ret = -2;
				goto out_close;
			}
			continue;
		}

		switch (msg.type) {
		case lxc_msg_state:
			if (msg.value < 0 || msg.value >= MAX_STATE) {
				ERROR("Receive an invalid state number '%d'",
					msg.value);
				goto out_close;
			}

			if (s[msg.value]) {
				ret = 0;
				goto out_close;
			}
			break;
		default:
			if (stop) {
				ret = -2;
				goto out_close;
			}
			/* just ignore garbage */
			break;
		}
	}

out_close:
	lxc_monitor_close(fd);
	return ret;
}
