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
#include <libgen.h>
#include <unistd.h>
#include <sys/types.h>

#include <lxc/lxccontainer.h>

#include "lxc.h"
#include "log.h"
#include "arguments.h"
#include "commands.h"
#include "utils.h"

#define OPT_NO_LOCK OPT_USAGE+1
#define OPT_NO_KILL OPT_USAGE+2

lxc_log_define(lxc_stop_ui, lxc);

static int my_parser(struct lxc_arguments* args, int c, char* arg)
{
	switch (c) {
	case 'r': args->reboot = 1; break;
	case 'W': args->nowait = 1; break;
	case 't': args->timeout = atoi(arg); break;
	case 'k': args->hardstop = 1; break;
	case OPT_NO_LOCK: args->nolock = 1; break;
	case OPT_NO_KILL: args->nokill = 1; break;
	}
	return 0;
}

static const struct option my_longopts[] = {
	{"reboot", no_argument, 0, 'r'},
	{"nowait", no_argument, 0, 'W'},
	{"timeout", required_argument, 0, 't'},
	{"kill", no_argument, 0, 'k'},
	{"nokill", no_argument, 0, OPT_NO_KILL},
	{"nolock", no_argument, 0, OPT_NO_LOCK},
	LXC_COMMON_OPTIONS
};

static struct lxc_arguments my_args = {
	.progname = "lxc-stop",
	.help     = "\
--name=NAME\n\
\n\
lxc-stop stops a container with the identifier NAME\n\
\n\
Options :\n\
  -n, --name=NAME   NAME of the container\n\
  -r, --reboot      reboot the container\n\
  -W, --nowait      don't wait for shutdown or reboot to complete\n\
  -t, --timeout=T   wait T seconds before hard-stopping\n\
  -k, --kill        kill container rather than request clean shutdown\n\
      --nolock      Avoid using API locks\n\
      --nokill      Only request clean shutdown, don't force kill after timeout\n",
	.options  = my_longopts,
	.parser   = my_parser,
	.checker  = NULL,
	.timeout  = -2,
};

/* returns -1 on failure, 0 on success */
static int do_reboot_and_check(struct lxc_arguments *a, struct lxc_container *c)
{
	int ret;
	pid_t pid;
	pid_t newpid;
	int timeout = a->timeout;

	pid = c->init_pid(c);
	if (pid == -1)
		return -1;
	if (!c->reboot(c))
		return -1;
	if (a->nowait)
		return 0;
	if (timeout == 0)
		goto out;

	for (;;) {
		/* can we use c-> wait for this, assuming it will
		 * re-enter RUNNING?  For now just sleep */
		int elapsed_time, curtime = 0;
		struct timeval tv;

		newpid = c->init_pid(c);
		if (newpid != -1 && newpid != pid)
			return 0;

		if (timeout != -1) {
			ret = gettimeofday(&tv, NULL);
			if (ret)
				break;
			curtime = tv.tv_sec;
		}

		sleep(1);
		if (timeout != -1) {
			ret = gettimeofday(&tv, NULL);
			if (ret)
				break;
			elapsed_time = tv.tv_sec - curtime;
			if (timeout - elapsed_time <= 0)
				break;
			timeout -= elapsed_time;
		}
	}

out:
	newpid = c->init_pid(c);
	if (newpid == -1 || newpid == pid) {
		printf("Reboot did not complete before timeout\n");
		return -1;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	struct lxc_container *c;
	bool s;
	int ret = 1;

	if (lxc_arguments_parse(&my_args, argc, argv))
		return 1;

	if (lxc_log_init(my_args.name, my_args.log_file, my_args.log_priority,
			 my_args.progname, my_args.quiet, my_args.lxcpath[0]))
		return 1;
	lxc_log_options_no_override();

	/* Set default timeout */
	if (my_args.timeout == -2) {
		if (my_args.hardstop) {
			my_args.timeout = 0;
		}
		else {
			my_args.timeout = 60;
		}
	}

	if (my_args.nowait) {
		my_args.timeout = 0;
	}

	/* some checks */
	if (!my_args.hardstop && my_args.timeout < -1) {
		fprintf(stderr, "invalid timeout\n");
		return 1;
	}

	if (my_args.hardstop && my_args.nokill) {
		fprintf(stderr, "-k can't be used with --nokill\n");
		return 1;
	}

	if (my_args.hardstop && my_args.reboot) {
		fprintf(stderr, "-k can't be used with -r\n");
		return 1;
	}

	if (my_args.hardstop && my_args.timeout) {
		fprintf(stderr, "-k doesn't allow timeouts\n");
		return 1;
	}

	if (my_args.nolock && !my_args.hardstop) {
		fprintf(stderr, "--nolock may only be used with -k\n");
		return 1;
	}

	/* shortcut - if locking is bogus, we should be able to kill
	 * containers at least */
	if (my_args.nolock)
		return lxc_cmd_stop(my_args.name, my_args.lxcpath[0]);

	c = lxc_container_new(my_args.name, my_args.lxcpath[0]);
	if (!c) {
		fprintf(stderr, "Error opening container\n");
		goto out;
	}

	if (!c->may_control(c)) {
		fprintf(stderr, "Insufficent privileges to control %s\n", c->name);
		goto out;
	}

	if (!c->is_running(c)) {
		fprintf(stderr, "%s is not running\n", c->name);
		ret = 2;
		goto out;
	}

	/* kill */
	if (my_args.hardstop) {
		ret = c->stop(c) ? 0 : 1;
		goto out;
	}

	/* reboot */
	if (my_args.reboot) {
		ret = do_reboot_and_check(&my_args, c);
		goto out;
	}

	/* shutdown */
	s = c->shutdown(c, my_args.timeout);
	if (!s) {
		if (my_args.timeout == 0)
			ret = 0;
		else if (my_args.nokill)
			ret = 1;
		else
			ret = c->stop(c) ? 0 : 1;
	} else
		ret = 0;

out:
	lxc_container_put(c);
	if (ret < 0)
		return 1;
	return ret;
}
