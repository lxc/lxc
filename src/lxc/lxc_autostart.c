/* lxc_autostart
 *
 * Copyright © 2013 Stéphane Graber <stgraber@ubuntu.com>
 * Copyright © 2013 Canonical Ltd.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.

 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.

 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <string.h>
#include <unistd.h>

#include <lxc/lxccontainer.h>

#include "arguments.h"
#include "list.h"
#include "log.h"

lxc_log_define(lxc_autostart_ui, lxc);

static int my_parser(struct lxc_arguments* args, int c, char* arg)
{
	switch (c) {
	case 'k': args->hardstop = 1; break;
	case 'L': args->list = 1; break;
	case 'r': args->reboot = 1; break;
	case 's': args->shutdown = 1; break;
	case 'a': args->all = 1; break;
	case 'g': args->groups = arg; break;
	case 't': args->timeout = atoi(arg); break;
	}
	return 0;
}

static const struct option my_longopts[] = {
	{"kill", no_argument, 0, 'k'},
	{"list", no_argument, 0, 'L'},
	{"reboot", no_argument, 0, 'r'},
	{"shutdown", no_argument, 0, 's'},
	{"all", no_argument, 0, 'a'},
	{"groups", required_argument, 0, 'g'},
	{"timeout", required_argument, 0, 't'},
	{"help", no_argument, 0, 'h'},
	LXC_COMMON_OPTIONS
};

static struct lxc_arguments my_args = {
	.progname = "lxc-autostart",
	.help     = "\
\n\
lxc-autostart managed auto-started containers\n\
\n\
Options:\n\
  -k, --kill        kill the containers instead of starting them\n\
  -L, --list        list all affected containers and wait delay\n\
  -r, --reboot      reboot the containers instead of starting them\n\
  -s, --shutdown    shutdown the containers instead of starting them\n\
\n\
  -a, --all         list all auto-started containers (ignore groups)\n\
  -g, --groups      list of groups (comma separated) to select\n\
  -t, --timeout=T   wait T seconds before hard-stopping\n",
	.options  = my_longopts,
	.parser   = my_parser,
	.checker  = NULL,
	.timeout = 60,
};

int lists_contain_common_entry(struct lxc_list *p1, struct lxc_list *p2) {
	struct lxc_list *it1;
	struct lxc_list *it2;

	if (!p1 && !p2)
		return 1;

	if (!p1)
		return 0;

	if (!p2)
		return 0;

	lxc_list_for_each(it1, p1) {
		lxc_list_for_each(it2, p2) {
			if (strcmp(it1->elem, it2->elem) == 0)
				return 1;
		}
	}

	return 0;
}

static struct lxc_list *get_list(char *input, char *delimiter) {
	char *workstr = NULL;
	char *workptr = NULL;
	char *sptr = NULL;
	char *token = NULL;
	struct lxc_list *worklist;
	struct lxc_list *workstr_list;

	workstr_list = malloc(sizeof(*workstr_list));
	lxc_list_init(workstr_list);

	workstr = strdup(input);
	if (!workstr) {
		free(workstr_list);
		return NULL;
	}

	for (workptr = workstr;;workptr = NULL) {
		token = strtok_r(workptr, delimiter, &sptr);
		if (!token) {
			break;
		}

		worklist = malloc(sizeof(*worklist));
		if (!worklist)
			break;

		worklist->elem = strdup(token);
		if (!worklist->elem) {
			free(worklist);
			break;
		}

		lxc_list_add_tail(workstr_list, worklist);
	}

	free(workstr);

	return workstr_list;
}

static struct lxc_list *get_config_list(struct lxc_container *c, char *key) {
	int len = 0;
	char* value = NULL;
	struct lxc_list *config_list = NULL;

	len = c->get_config_item(c, key, NULL, 0);
	if (len < 0)
		return NULL;

	value = (char*) malloc(sizeof(char)*len + 1);
	if (value == NULL)
		return NULL;

	if (c->get_config_item(c, key, value, len + 1) != len) {
		free(value);
		return NULL;
	}

	if (strlen(value) == 0) {
		free(value);
		return NULL;
	}

	config_list = get_list(value, "\n");
	free(value);

	return config_list;
}

static int get_config_integer(struct lxc_container *c, char *key) {
	int len = 0;
	int ret = 0;
	char* value = NULL;

	len = c->get_config_item(c, key, NULL, 0);
	if (len < 0)
		return 0;

	value = (char*) malloc(sizeof(char)*len + 1);
	if (value == NULL)
		return 0;

	if (c->get_config_item(c, key, value, len + 1) != len) {
		free(value);
		return 0;
	}

	ret = atoi(value);
	free(value);

	return ret;
}

static int cmporder(const void *p1, const void *p2) {
	struct lxc_container *c1 = *(struct lxc_container **)p1;
	struct lxc_container *c2 = *(struct lxc_container **)p2;

	int c1_order = get_config_integer(c1, "lxc.start.order");
	int c2_order = get_config_integer(c2, "lxc.start.order");

	if (c1_order == c2_order)
		return strcmp(c1->name, c2->name);
	else
		return (c1_order - c2_order) * -1;
}

int main(int argc, char *argv[])
{
	int count = 0;
	int i = 0;
	int ret = 0;
	struct lxc_container **containers = NULL;
	struct lxc_list *cmd_groups_list = NULL;
	struct lxc_list *c_groups_list = NULL;
	struct lxc_list *it, *next;
	char *const default_start_args[] = {
		"/sbin/init",
		'\0',
	};

	if (lxc_arguments_parse(&my_args, argc, argv))
		return 1;

	if (lxc_log_init(my_args.name, my_args.log_file, my_args.log_priority,
			 my_args.progname, my_args.quiet, my_args.lxcpath[0]))
		return 1;
	lxc_log_options_no_override();

	count = list_defined_containers(NULL, NULL, &containers);

	if (count < 0)
		return 1;

	qsort(&containers[0], count, sizeof(struct lxc_container *), cmporder);

	if (my_args.groups && !my_args.all)
		cmd_groups_list = get_list((char*)my_args.groups, ",");

	for (i = 0; i < count; i++) {
		struct lxc_container *c = containers[i];

		if (!c->may_control(c)) {
			lxc_container_put(c);
			continue;
		}

		if (get_config_integer(c, "lxc.start.auto") != 1) {
			lxc_container_put(c);
			continue;
		}

		if (!my_args.all) {
			/* Filter by group */
			c_groups_list = get_config_list(c, "lxc.group");

			ret = lists_contain_common_entry(cmd_groups_list, c_groups_list);

			if (c_groups_list) {
				lxc_list_for_each_safe(it, c_groups_list, next) {
					lxc_list_del(it);
					free(it->elem);
					free(it);
				}
				free(c_groups_list);
			}

			if (ret == 0) {
				lxc_container_put(c);
				continue;
			}
		}

		c->want_daemonize(c, 1);

		if (my_args.shutdown) {
			/* Shutdown the container */
			if (c->is_running(c)) {
				if (my_args.list)
					printf("%s\n", c->name);
				else {
					if (!c->shutdown(c, my_args.timeout)) {
						if (!c->stop(c)) {
							fprintf(stderr, "Error shutting down container: %s\n", c->name);
						}
					}
				}
			}
		}
		else if (my_args.hardstop) {
			/* Kill the container */
			if (c->is_running(c)) {
				if (my_args.list)
					printf("%s\n", c->name);
				else {
					if (!c->stop(c))
						fprintf(stderr, "Error killing container: %s\n", c->name);
				}
			}
		}
		else if (my_args.reboot) {
			/* Reboot the container */
			if (c->is_running(c)) {
				if (my_args.list)
					printf("%s %d\n", c->name,
					       get_config_integer(c, "lxc.start.delay"));
				else {
					if (!c->reboot(c))
						fprintf(stderr, "Error rebooting container: %s\n", c->name);
					else
						sleep(get_config_integer(c, "lxc.start.delay"));
				}
			}
		}
		else {
			/* Start the container */
			if (!c->is_running(c)) {
				if (my_args.list)
					printf("%s %d\n", c->name,
					       get_config_integer(c, "lxc.start.delay"));
				else {
					if (!c->start(c, 0, default_start_args))
						fprintf(stderr, "Error starting container: %s\n", c->name);
					else
						sleep(get_config_integer(c, "lxc.start.delay"));
				}
			}
		}


		lxc_container_put(c);
	}

	if (cmd_groups_list) {
		lxc_list_for_each_safe(it, cmd_groups_list, next) {
			lxc_list_del(it);
			free(it->elem);
			free(it);
		}
		free(cmd_groups_list);
	}

	free(containers);

	return 0;
}
