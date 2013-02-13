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
	int i, len;
	len = sizeof(strstate)/sizeof(strstate[0]);
	for (i = 0; i < len; i++)
		if (!strcmp(strstate[i], state))
			return i;

	ERROR("invalid state '%s'", state);
	return -1;
}

static int freezer_state(const char *name)
{
	char *nsgroup;
	char freezer[MAXPATHLEN];
	char status[MAXPATHLEN];
	FILE *file;
	int err;

	err = lxc_cgroup_path_get(&nsgroup, "freezer", name);
	if (err)
		return -1;

	err = snprintf(freezer, MAXPATHLEN, "%s/freezer.state", nsgroup);
	if (err < 0 || err >= MAXPATHLEN)
		return -1;

	file = fopen(freezer, "r");
	if (!file)
		return -1;

	err = fscanf(file, "%s", status);
	fclose(file);

	if (err == EOF) {
		SYSERROR("failed to read %s", freezer);
		return -1;
	}

	return lxc_str2state(status);
}

static lxc_state_t __lxc_getstate(const char *name, const char *lxcpath)
{
	struct lxc_command command = {
		.request = { .type = LXC_COMMAND_STATE },
	};

	int ret, stopped = 0;

	ret = lxc_command(name, &command, &stopped, lxcpath);
	if (ret < 0 && stopped)
		return STOPPED;

	if (ret < 0) {
		ERROR("failed to send command");
		return -1;
	}

	if (!ret) {
		WARN("'%s' has stopped before sending its state", name);
		return -1;
	}

	if (command.answer.ret < 0) {
		ERROR("failed to get state for '%s': %s",
			name, strerror(-command.answer.ret));
		return -1;
	}

	DEBUG("'%s' is in '%s' state", name, lxc_state2str(command.answer.ret));

	return command.answer.ret;
}

lxc_state_t lxc_getstate(const char *name, const char *lxcpath)
{
	int state = freezer_state(name);
	if (state != FROZEN && state != FREEZING)
		state = __lxc_getstate(name, lxcpath);
	return state;
}

/*----------------------------------------------------------------------------
 * functions used by lxc-start mainloop
 * to handle above command request.
 *--------------------------------------------------------------------------*/
extern int lxc_state_callback(int fd, struct lxc_request *request,
			struct lxc_handler *handler)
{
	struct lxc_answer answer;
	int ret;

	answer.ret = handler->state;

	ret = send(fd, &answer, sizeof(answer), 0);
	if (ret < 0) {
		WARN("failed to send answer to the peer");
		goto out;
	}

	if (ret != sizeof(answer)) {
		ERROR("partial answer sent");
		goto out;
	}

out:
	return ret;
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

extern int lxc_wait(const char *lxcname, const char *states, int timeout)
{
	struct lxc_msg msg;
	int state, ret;
	int s[MAX_STATE] = { }, fd;
	/* TODO: add cmdline arg to specify lxcpath */
	char *lxcpath = NULL;

	if (fillwaitedstates(states, s))
		return -1;

	fd = lxc_monitor_open();
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
		if (lxc_monitor_read_timeout(fd, &msg, timeout) < 0)
			goto out_close;

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
