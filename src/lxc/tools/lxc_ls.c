/*
 *
 * Copyright © 2016 Christian Brauner <christian.brauner@mailbox.org>.
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

#include "config.h"

#include <getopt.h>
#include <regex.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <termios.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <lxc/lxccontainer.h>

#include "arguments.h"
#include "conf.h"
#include "confile.h"
#include "log.h"
#include "lxc.h"
#include "utils.h"

lxc_log_define(lxc_ls, lxc);

#define LINELEN 1024
/* Per default we only allow five levels of recursion to protect the stack at
 * least a little bit. */
#define MAX_NESTLVL 5

#define LS_FROZEN 1
#define LS_STOPPED 2
#define LS_ACTIVE 3
#define LS_RUNNING 4
#define LS_NESTING 5
#define LS_FILTER 6

#ifndef SOCK_CLOEXEC
#  define SOCK_CLOEXEC                02000000
#endif

/* Store container info. */
struct ls {
	char *name;
	char *state;
	char *groups;
	char *interface;
	char *ipv4;
	char *ipv6;
	unsigned int nestlvl;
	pid_t init;
	double ram;
	double swap;
	bool autostart;
	bool running;
};

/* Keep track of field widths for printing. */
struct lengths {
	unsigned int name_length;
	unsigned int state_length;
	unsigned int groups_length;
	unsigned int interface_length;
	unsigned int ipv4_length;
	unsigned int ipv6_length;
	unsigned int init_length;
	unsigned int ram_length;
	unsigned int swap_length;
	unsigned int autostart_length;
};

static int ls_deserialize(int rpipefd, struct ls **m, size_t *len);
static void ls_field_width(const struct ls *l, const size_t size,
		struct lengths *lht);
static void ls_free(struct ls *l, size_t size);
static void ls_free_arr(char **arr, size_t size);
static int ls_get(struct ls **m, size_t *size, const struct lxc_arguments *args,
		const char *basepath, const char *parent, unsigned int lvl,
		char **lockpath, size_t len_lockpath, char **grps_must,
		size_t grps_must_len);
static char *ls_get_cgroup_item(struct lxc_container *c, const char *item);
static char *ls_get_config_item(struct lxc_container *c, const char *item,
		bool running);
static char *ls_get_groups(struct lxc_container *c, bool running);
static char *ls_get_ips(struct lxc_container *c, const char *inet);
static int ls_recv_str(int fd, char **buf);
static int ls_send_str(int fd, const char *buf);

struct wrapargs {
	const struct lxc_arguments *args;
	char **grps_must;
	size_t grps_must_len;
	int pipefd[2];
	size_t *size;
	const char *parent;
	unsigned int nestlvl;
};

/*
 * Takes struct wrapargs as argument.
 */
static int ls_get_wrapper(void *wrap);

/*
 * To calculate swap usage we should not simply check memory.usage_in_bytes and
 * memory.memsw.usage_in_bytes and then do:
 *	swap = memory.memsw.usage_in_bytes - memory.usage_in_bytes;
 * because we might receive an incorrect/negative value.
 * Instead we check memory.stat and check the "swap" value.
 */
static double ls_get_swap(struct lxc_container *c);
static unsigned int ls_get_term_width(void);
static char *ls_get_interface(struct lxc_container *c);
static bool ls_has_all_grps(const char *has, char **must, size_t must_len);
static struct ls *ls_new(struct ls **ls, size_t *size);

/*
 * Print user-specified fancy format.
 */
static void ls_print_fancy_format(struct ls *l, struct lengths *lht,
		size_t size, const char *fancy_fmt);

/*
 * Only print names of containers.
 */
static void ls_print_names(struct ls *l, struct lengths *lht,
		size_t ls_arr, size_t termwidth);

/*
 * Print default fancy format.
 */
static void ls_print_table(struct ls *l, struct lengths *lht,
		size_t size);

/*
 * id can only be 79 + \0 chars long.
 */
static int ls_remove_lock(const char *path, const char *name,
		char **lockpath, size_t *len_lockpath, bool recalc);
static int ls_serialize(int wpipefd, struct ls *n);
static int my_parser(struct lxc_arguments *args, int c, char *arg);

static const struct option my_longopts[] = {
	{"line", no_argument, 0, '1'},
	{"fancy", no_argument, 0, 'f'},
	{"fancy-format", required_argument, 0, 'F'},
	{"active", no_argument, 0, LS_ACTIVE},
	{"running", no_argument, 0, LS_RUNNING},
	{"frozen", no_argument, 0, LS_FROZEN},
	{"stopped", no_argument, 0, LS_STOPPED},
	{"nesting", optional_argument, 0, LS_NESTING},
	{"groups", required_argument, 0, 'g'},
	{"filter", required_argument, 0, LS_FILTER},
	LXC_COMMON_OPTIONS
};

static struct lxc_arguments my_args = {
	.progname = "lxc-ls",
	.help = "\n\
[-P lxcpath] [--active] [--running] [--frozen] [--stopped] [--nesting] [-g groups] [--filter regex]\n\
[-1] [-P lxcpath] [--active] [--running] [--frozen] [--stopped] [--nesting] [-g groups] [--filter regex]\n\
[-f] [-P lxcpath] [--active] [--running] [--frozen] [--stopped] [--nesting] [-g groups] [--filter regex]\n\
\n\
lxc-ls list containers\n\
\n\
Options :\n\
  -1, --line	     show one entry per line\n\
  -f, --fancy	     column-based output\n\
  -F, --fancy-format column-based output\n\
  --active           list only active containers\n\
  --running          list only running containers\n\
  --frozen           list only frozen containers\n\
  --stopped          list only stopped containers\n\
  --nesting=NUM      list nested containers up to NUM (default is 5) levels of nesting\n\
  --filter=REGEX     filter container names by regular expression\n\
  -g --groups        comma separated list of groups a container must have to be displayed\n",
	.options = my_longopts,
	.parser = my_parser,
	.ls_nesting = 0,
};

int main(int argc, char *argv[])
{
	int ret = EXIT_FAILURE;
	/*
	 * The lxc parser requires that my_args.name is set. So let's satisfy
	 * that condition by setting a dummy name which is never used.
	 */
	my_args.name  = "";
	if (lxc_arguments_parse(&my_args, argc, argv))
		exit(EXIT_FAILURE);

	if (!my_args.log_file)
		my_args.log_file = "none";

	/*
	 * We set the first argument that usually takes my_args.name to NULL so
	 * that the log is only used when the user specifies a file.
	 */
	if (lxc_log_init(NULL, my_args.log_file, my_args.log_priority,
			 my_args.progname, my_args.quiet, my_args.lxcpath[0]))
		exit(EXIT_FAILURE);
	lxc_log_options_no_override();

	struct lengths max_len = {
		/* default header length */
		.name_length = 4,      /* NAME */
		.state_length = 5,     /* STATE */
		.groups_length = 6,    /* GROUPS */
		.interface_length = 9, /* INTERFACE */
		.ipv4_length = 4,      /* IPV4 */
		.ipv6_length = 4,      /* IPV6 */
		.init_length = 3,      /* PID */
		.ram_length = 3,       /* RAM */
		.swap_length = 4,      /* SWAP */
		.autostart_length = 9, /* AUTOSTART */
	};

	char **grps = NULL;
	size_t ngrps = 0;
	if (my_args.groups) {
		grps = lxc_string_split_and_trim(my_args.groups, ',');
		ngrps = lxc_array_len((void **)grps);
	}

	struct ls *ls_arr = NULL;
	size_t ls_size = 0;
	/* &(char *){NULL} is no magic. It's just a compound literal which
	 * avoids having a pointless variable in main() that serves no purpose
	 * here. */
	int status = ls_get(&ls_arr, &ls_size, &my_args, "", NULL, 0, &(char *){NULL}, 0, grps, ngrps);
	if (!ls_arr && status == 0)
		/* We did not fail. There was just nothing to do. */
		exit(EXIT_SUCCESS);
	else if (!ls_arr || status == -1)
		goto out;

	ls_field_width(ls_arr, ls_size, &max_len);
	if (my_args.ls_fancy && !my_args.ls_fancy_format) {
		ls_print_table(ls_arr, &max_len, ls_size);
	} else if (my_args.ls_fancy && my_args.ls_fancy_format) {
		ls_print_fancy_format(ls_arr, &max_len, ls_size, my_args.ls_fancy_format);
	} else {
		unsigned int cols = 0;
		if (!my_args.ls_line)
			cols = ls_get_term_width();
		ls_print_names(ls_arr, &max_len, ls_size, cols);
	}

	ret = EXIT_SUCCESS;

out:
	ls_free(ls_arr, ls_size);
	lxc_free_array((void **)grps, free);

	exit(ret);
}

static void ls_free(struct ls *l, size_t size)
{
	size_t i;
	struct ls *m = NULL;
	for (i = 0, m = l; i < size; i++, m++) {
		free(m->groups);
		free(m->interface);
		free(m->ipv4);
		free(m->ipv6);
		free(m->name);
		free(m->state);
	}
	free(l);
}

static char *ls_get_config_item(struct lxc_container *c, const char *item,
		bool running)
{
	if (running)
		return c->get_running_config_item(c, item);

	size_t len = c->get_config_item(c, item, NULL, 0);
	if (len <= 0)
		return NULL;

	char *val = malloc((len + 1) * sizeof(*val));
	if (!val)
		return NULL;

	if ((size_t)c->get_config_item(c, item, val, len + 1) != len) {
		free(val);
		val = NULL;
	}

	return val;
}

static void ls_free_arr(char **arr, size_t size)
{
	size_t i;
	for (i = 0; i < size; i++)
		free(arr[i]);
	free(arr);
}

static int ls_get(struct ls **m, size_t *size, const struct lxc_arguments *args,
		const char *basepath, const char *parent, unsigned int lvl,
		char **lockpath, size_t len_lockpath, char **grps_must,
		size_t grps_must_len)
{
	/* As ls_get() is non-tail recursive we face the inherent danger of
	 * blowing up the stack at some level of nesting. To have at least some
	 * security we define MAX_NESTLVL to be 5. That should be sufficient for
	 * most users. The argument lvl can be used to keep track of the level
	 * of nesting we are at. If lvl is greater than the allowed default
	 * level or the level the user specified on the command line we return
	 * and unwind the stack. */
	if (lvl > args->ls_nesting)
		return 0;

	int num = 0, ret = -1;
	char **containers = NULL;
	/* If we, at some level of nesting, encounter a stopped container but
	 * want to retrieve nested containers we need to build an absolute path
	 * beginning from it. Initially, at nesting level 0, basepath will
	 * simply be the empty string and path will simply be whatever the
	 * default lxcpath or the path the user gave us is.  Basepath will also
	 * be the empty string in case we encounter a running container since we
	 * can simply attach to its namespace to retrieve nested containers. */
	char *path = lxc_append_paths(basepath, args->lxcpath[0]);
	if (!path)
		goto out;

	if (!dir_exists(path)) {
		ret = 0;
		goto out;
	}

	/* Do not do more work than is necessary right from the start. */
	if (args->ls_active || (args->ls_active && args->ls_frozen))
		num = list_active_containers(path, &containers, NULL);
	else
		num = list_all_containers(path, &containers, NULL);
	if (num == -1) {
		num = 0;
		goto out;
	}

	char *tmp = NULL;
	int check;
	struct ls *l = NULL;
	struct lxc_container *c = NULL;
	size_t i;
	for (i = 0; i < (size_t)num; i++) {
		char *name = containers[i];

		/* Filter container names by regex the user gave us. */
		if (args->ls_filter || args->argc == 1) {
			regex_t preg;
			tmp = args->ls_filter ? args->ls_filter : args->argv[0];
			check = regcomp(&preg, tmp, REG_NOSUB | REG_EXTENDED);
			if (check == REG_ESPACE) /* we're out of memory */
				goto out;
			else if (check != 0)
				continue;
			check = regexec(&preg, name, 0, NULL, 0);
			regfree(&preg);
			if (check != 0)
				continue;
		}

 		errno = 0;
		c = lxc_container_new(name, path);
 		if ((errno == ENOMEM) && !c)
 			goto out;
 		else if (!c)
 			continue;

		if (!c->is_defined(c))
			goto put_and_next;

		/* This does not allocate memory so no worries about freeing it
		 * when we goto next or out. */
		const char *state_tmp = c->state(c);
		if (!state_tmp)
			state_tmp = "UNKNOWN";

		if (args->ls_running && !c->is_running(c))
			goto put_and_next;

		if (args->ls_frozen && !args->ls_active && strcmp(state_tmp, "FROZEN"))
			goto put_and_next;

		if (args->ls_stopped && strcmp(state_tmp, "STOPPED"))
			goto put_and_next;

		bool running = c->is_running(c);

		char *grp_tmp = ls_get_groups(c, running);
		if (!ls_has_all_grps(grp_tmp, grps_must, grps_must_len)) {
			free(grp_tmp);
			goto put_and_next;
		}

		/* Now it makes sense to allocate memory. */
		l = ls_new(m, size);
		if (!l) {
			free(grp_tmp);
			goto put_and_next;
		}

		/* How deeply nested are we? */
		l->nestlvl = lvl;

		l->groups = grp_tmp;

		l->running = running;

		if (parent && args->ls_nesting && (args->ls_line || !args->ls_fancy))
			/* Prepend the name of the container with all its parents when
			 * the user requests it. */
			l->name = lxc_append_paths(parent, name);
		else
			/* Otherwise simply record the name. */
			l->name = strdup(name);
		if (!l->name)
			goto put_and_next;

		/* Do not record stuff the user did not explictly request. */
		if (args->ls_fancy) {
			/* Maybe we should even consider the name sensitive and
			 * hide it when you're not allowed to control the
			 * container. */
			if (!c->may_control(c))
				goto put_and_next;

			l->state = strdup(state_tmp);
			if (!l->state)
				goto put_and_next;

			tmp = ls_get_config_item(c, "lxc.start.auto", running);
			if (tmp)
				l->autostart = atoi(tmp);
			free(tmp);

			if (running) {
				l->init = c->init_pid(c);

				l->interface = ls_get_interface(c);

				l->ipv4 = ls_get_ips(c, "inet");

				l->ipv6 = ls_get_ips(c, "inet6");

				tmp = ls_get_cgroup_item(c, "memory.usage_in_bytes");
				if (tmp) {
					l->ram = strtoull(tmp, NULL, 0);
					l->ram = l->ram / 1024 /1024;
					free(tmp);
				}

				l->swap = ls_get_swap(c);
			}
		}

		/* Get nested containers: Only do this after we have gathered
		 * all other information we need. */
		if (args->ls_nesting && running) {
			struct wrapargs wargs = (struct wrapargs){.args = NULL};
			/* Open a socket so that the child can communicate with us. */
			check = socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, wargs.pipefd);
			if (check == -1)
				goto put_and_next;

			/* Set the next nesting level. */
			wargs.nestlvl = lvl + 1;
			/* Send in the parent for the next nesting level. */
			wargs.parent = l->name;
			wargs.args = args;
			wargs.grps_must = grps_must;
			wargs.grps_must_len = grps_must_len;

			pid_t out;

			lxc_attach_options_t aopt = LXC_ATTACH_OPTIONS_DEFAULT;
			aopt.env_policy = LXC_ATTACH_CLEAR_ENV;

			/* fork(): Attach to the namespace of the container and
			 * run ls_get() in it which is called in ls_get_wrapper(). */
			check = c->attach(c, ls_get_wrapper, &wargs, &aopt, &out);
			/* close the socket */
			close(wargs.pipefd[1]);

			/* Retrieve all information we want from the child. */
			if (check == 0)
				if (ls_deserialize(wargs.pipefd[0], m, size) == -1)
					goto put_and_next;

			/* Wait for the child to finish. */
			wait_for_pid(out);

			/* We've done all the communication we need so shutdown
			 * the socket and close it. */
			shutdown(wargs.pipefd[0], SHUT_RDWR);
			close(wargs.pipefd[0]);
		} else if (args->ls_nesting && !running) {
			/* This way of extracting the rootfs is not safe since
			 * it will return very different things depending on the
			 * storage backend that is used for the container. We
			 * need a path-extractor function. We face the same
			 * problem with the ovl_mkdir() function in
			 * lxcoverlay.{c,h}. */
			char *curr_path = ls_get_config_item(c, "lxc.rootfs", running);
			if (!curr_path)
				goto put_and_next;

			/* Since the container is not running and we cannot
			 * attach to it we need another strategy to retrieve
			 * nested containers. What we do is simply create a
			 * growing path which will lead us into the rootfs of
			 * the next container where it stores its containers. */
			char *newpath = lxc_append_paths(basepath, curr_path);
			free(curr_path);
			if (!newpath)
				goto put_and_next;

			/* We want to remove all locks we create under
			 * /run/lxc/lock so we create a string pointing us to
			 * the lock path for the current container. */
			if (ls_remove_lock(path, name, lockpath, &len_lockpath, true) == -1)
				goto put_and_next;

			ls_get(m, size, args, newpath, l->name, lvl + 1, lockpath, len_lockpath, grps_must, grps_must_len);
			free(newpath);

			/* Remove the lock. No need to check for failure here. */
			ls_remove_lock(path, name, lockpath, &len_lockpath, false);
		}

put_and_next:
		lxc_container_put(c);
	}
	ret = 0;

out:
	ls_free_arr(containers, num);
	free(path);
	/* lockpath is shared amongst all non-fork()ing recursive calls to
	 * ls_get() so only free it on the uppermost level. */
	if (lvl == 0)
		free(*lockpath);

	return ret;
}

static char *ls_get_cgroup_item(struct lxc_container *c, const char *item)
{
	size_t len = c->get_cgroup_item(c, item, NULL, 0);
	if (len <= 0)
		return NULL;

	char *val = malloc((len + 1) * sizeof(*val));
	if (!val)
		return NULL;

	if ((size_t)c->get_cgroup_item(c, item, val, len + 1) != len) {
		free(val);
		val = NULL;
	}

	return val;
}

static char *ls_get_groups(struct lxc_container *c, bool running)
{
	size_t len = 0;
	char *val = NULL;

	if (running)
		val = c->get_running_config_item(c, "lxc.group");
	else
		len = c->get_config_item(c, "lxc.group", NULL, 0);

	if (!val && (len > 0)) {
		val = malloc((len + 1) * sizeof(*val));
		if ((size_t)c->get_config_item(c, "lxc.group", val, len + 1) != len) {
			free(val);
			return NULL;
		}
	}

	if (val) {
		char *tmp;
		if ((tmp = strrchr(val, '\n')))
			*tmp = '\0';

		tmp = lxc_string_replace("\n", ", ", val);
		free(val);
		val = tmp;
	}

	return val;
}

static char *ls_get_ips(struct lxc_container *c, const char *inet)
{
	char *ips = NULL;
	char **iptmp = c->get_ips(c, NULL, inet, 0);
	if (iptmp)
		ips = lxc_string_join(", ", (const char **)iptmp, false);

	lxc_free_array((void **)iptmp, free);

	return ips;
}

static char *ls_get_interface(struct lxc_container *c)
{
	char **interfaces = c->get_interfaces(c);
	if (!interfaces)
		return NULL;

	char *interface = lxc_string_join(", ", (const char **)interfaces, false);

	lxc_free_array((void **)interfaces, free);

	return interface;
}

/*
 * To calculate swap usage we should not simply check memory.usage_in_bytes and
 * memory.memsw.usage_in_bytes and then do:
 *	swap = memory.memsw.usage_in_bytes - memory.usage_in_bytes;
 * because we might receive an incorrect/negative value.
 * Instead we check memory.stat and check the "swap" value.
 */
static double ls_get_swap(struct lxc_container *c)
{
	unsigned long long int num = 0;
	char *stat = ls_get_cgroup_item(c, "memory.stat");
	if (!stat)
		goto out;

	char *swap = strstr(stat, "\nswap");
	if (!swap)
		goto out;

	swap = 1 + swap + 4 + 1; // start_of_swap_value = '\n' + strlen(swap) + ' '

	char *tmp = strchr(swap, '\n'); // find end of swap value
	if (!tmp)
		goto out;

	*tmp = '\0';

	num = strtoull(swap, NULL, 0);
	num = num / 1024 / 1024;

out:
	free(stat);

	return num;
}

static unsigned int ls_get_term_width(void)
{
	struct winsize ws;
	if (((ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == -1) &&
	     (ioctl(STDERR_FILENO, TIOCGWINSZ, &ws) == -1) &&
	     (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == -1)) ||
	    (ws.ws_col == 0))
		return 0;

	return ws.ws_col;
}

static bool ls_has_all_grps(const char *has, char **must, size_t must_len)
{
	bool bret = false;

	if (!has && must)
		return false;
	else if (!must)
		return true;

	char **tmp_has = lxc_string_split_and_trim(has, ',');
	size_t tmp_has_len = lxc_array_len((void **)tmp_has);

	/* Don't do any unnecessary work. */
	if (must_len > tmp_has_len)
		goto out;

	size_t i, j;
	for (i = 0; i < must_len; i++) {
		for (j = 0; j < tmp_has_len; j++)
			if (strcmp(must[i], tmp_has[j]) == 0)
				break;
		if (j == tmp_has_len)
			break;
	}
	if (i == must_len)
		bret = true;

out:
	lxc_free_array((void **)tmp_has, free);

	return bret;
}

static struct ls *ls_new(struct ls **ls, size_t *size)
{
	struct ls *m, *n;

	n = realloc(*ls, (*size + 1) * sizeof(struct ls));
	if (!n)
		return NULL;

	*ls = n;
	m = *ls + *size;
	(*size)++;

	*m = (struct ls){.name = NULL, .init = -1};

	return m;
}

static void ls_print_names(struct ls *l, struct lengths *lht,
		size_t size, size_t termwidth)
{
	/* If list is empty do nothing. */
	if (size == 0)
		return;

	size_t i, len = 0;
	struct ls *m = NULL;
	for (i = 0, m = l; i < size; i++, m++) {
		printf("%-*s", lht->name_length, m->name ? m->name : "-");
		len += lht->name_length;
		if ((len + lht->name_length) >= termwidth) {
			printf("\n");
			len = 0;
		} else {
			printf(" ");
			len++;
		}
	}
	if (len > 0)
		printf("\n");
}

static void ls_print_fancy_format(struct ls *l, struct lengths *lht,
		size_t size, const char *fancy_fmt)
{
	/* If list is empty do nothing. */
	if (size == 0)
		return;

	char **tmp = lxc_string_split_and_trim(fancy_fmt, ',');
	if (!tmp)
		return;

	char **s;
	/* Check for invalid keys. */
	for (s = tmp; s && *s; s++) {
		if (strcasecmp(*s, "NAME") && strcasecmp(*s, "STATE") &&
				strcasecmp(*s, "PID") && strcasecmp(*s, "RAM") &&
				strcasecmp(*s, "SWAP") && strcasecmp(*s, "AUTOSTART") &&
				strcasecmp(*s, "GROUPS") && strcasecmp(*s, "INTERFACE") &&
				strcasecmp(*s, "IPV4") && strcasecmp(*s, "IPV6")) {
			fprintf(stderr, "Invalid key: %s\n", *s);
			return;
		}
	}

	/* print header */
	for (s = tmp; s && *s; s++) {
		if (strcasecmp(*s, "NAME") == 0)
			printf("%-*s ", lht->name_length, "NAME");
		else if (strcasecmp(*s, "STATE") == 0)
			printf("%-*s ", lht->state_length, "STATE");
		else if (strcasecmp(*s, "PID") == 0)
			printf("%-*s ", lht->init_length, "PID");
		else if (strcasecmp(*s, "RAM") == 0)
			printf("%-*s ", lht->ram_length + 2, "RAM");
		else if (strcasecmp(*s, "SWAP") == 0)
			printf("%-*s ", lht->swap_length + 2, "SWAP");
		else if (strcasecmp(*s, "AUTOSTART") == 0)
			printf("%-*s ", lht->autostart_length, "AUTOSTART");
		else if (strcasecmp(*s, "GROUPS") == 0)
			printf("%-*s ", lht->groups_length, "GROUPS");
		else if (strcasecmp(*s, "INTERFACE") == 0)
			printf("%-*s ", lht->interface_length, "INTERFACE");
		else if (strcasecmp(*s, "IPV4") == 0)
			printf("%-*s ", lht->ipv4_length, "IPV4");
		else if (strcasecmp(*s, "IPV6") == 0)
			printf("%-*s ", lht->ipv6_length, "IPV6");
	}
	printf("\n");

	struct ls *m = NULL;
	size_t i;
	for (i = 0, m = l; i < size; i++, m++) {
		for (s = tmp; s && *s; s++) {
			if (strcasecmp(*s, "NAME") == 0) {
				if (m->nestlvl > 0) {
					printf("%*s", m->nestlvl, "\\");
					printf("%-*s ", lht->name_length - m->nestlvl, m->name ? m->name : "-");
				} else {
					printf("%-*s ", lht->name_length, m->name ? m->name : "-");
				}
			} else if (strcasecmp(*s, "STATE") == 0) {
				printf("%-*s ", lht->state_length, m->state ? m->state : "-");
			} else if (strcasecmp(*s, "PID") == 0) {
				if (m->init > 0)
					printf("%-*d ", lht->init_length, m->init);
				else
					printf("%-*s ", lht->init_length, "-");
			} else if (strcasecmp(*s, "RAM") == 0) {
				if ((m->ram >= 0) && m->running)
					printf("%*.2fMB ", lht->ram_length, m->ram);
				else
					printf("%-*s   ", lht->ram_length, "-");
			} else if (strcasecmp(*s, "SWAP") == 0) {
				if ((m->swap >= 0) && m->running)
					printf("%*.2fMB ", lht->swap_length, m->swap);
				else
					printf("%-*s   ", lht->swap_length, "-");
			} else if (strcasecmp(*s, "AUTOSTART") == 0) {
				printf("%-*d ", lht->autostart_length, m->autostart);
			} else if (strcasecmp(*s, "GROUPS") == 0) {
				printf("%-*s ", lht->groups_length, m->groups ? m->groups : "-");
			} else if (strcasecmp(*s, "INTERFACE") == 0) {
				printf("%-*s ", lht->interface_length, m->interface ? m->interface : "-");
			} else if (strcasecmp(*s, "IPV4") == 0) {
				printf("%-*s ", lht->ipv4_length, m->ipv4 ? m->ipv4 : "-");
			} else if (strcasecmp(*s, "IPV6") == 0) {
				printf("%-*s ", lht->ipv6_length, m->ipv6 ? m->ipv6 : "-");
			}
		}
		printf("\n");
	}
}

static void ls_print_table(struct ls *l, struct lengths *lht,
		size_t size)
{
	/* If list is empty do nothing. */
	if (size == 0)
		return;

	struct ls *m = NULL;

	/* print header */
	printf("%-*s ", lht->name_length, "NAME");
	printf("%-*s ", lht->state_length, "STATE");
	printf("%-*s ", lht->autostart_length, "AUTOSTART");
	printf("%-*s ", lht->groups_length, "GROUPS");
	printf("%-*s ", lht->ipv4_length, "IPV4");
	printf("%-*s ", lht->ipv6_length, "IPV6");
	printf("\n");

	size_t i;
	for (i = 0, m = l; i < size; i++, m++) {
		if (m->nestlvl > 0) {
			printf("%*s", m->nestlvl, "\\");
			printf("%-*s ", lht->name_length - m->nestlvl, m->name ? m->name : "-");
		} else {
		     printf("%-*s ", lht->name_length, m->name ? m->name : "-");
		}
		printf("%-*s ", lht->state_length, m->state ? m->state : "-");
		printf("%-*d ", lht->autostart_length, m->autostart);
		printf("%-*s ", lht->groups_length, m->groups ? m->groups : "-");
		printf("%-*s ", lht->ipv4_length, m->ipv4 ? m->ipv4 : "-");
		printf("%-*s ", lht->ipv6_length, m->ipv6 ? m->ipv6 : "-");
		printf("\n");
	}
}

static int my_parser(struct lxc_arguments *args, int c, char *arg)
{
	char *invalid;
	unsigned long int m, n = MAX_NESTLVL;
	switch (c) {
	case '1':
		args->ls_line = true;
		break;
	case 'f':
		args->ls_fancy = true;
		break;
	case LS_ACTIVE:
		args->ls_active = true;
		break;
	case LS_FROZEN:
		args->ls_frozen = true;
		break;
	case LS_RUNNING:
		args->ls_running = true;
		break;
	case LS_STOPPED:
		args->ls_stopped = true;
		break;
	case LS_NESTING:
		/* In case strtoul() receives a string that represents a
		 * negative number it will return ULONG_MAX - the number that
		 * the string represents if the number the string represents is
		 * < ULONG_MAX and ULONG_MAX otherwise. But it will consider
		 * this valid input and not set errno. So we check manually if
		 * the first character of num_string == '-'. Otherwise the
		 * default level remains set. */
		if (arg && !(*arg == '-')) {
			errno = 0;
			m = strtoul(arg, &invalid, 0);
			/* ls_nesting has type unsigned int. */
			if (!errno && (*invalid == '\0') && (m <= UINT_MAX))
				n = m;
		}
		args->ls_nesting = n;
		break;
	case 'g':
		args->groups = arg;
		break;
	case LS_FILTER:
		args->ls_filter = arg;
		break;
	case 'F':
		args->ls_fancy_format = arg;
		break;
	}

	return 0;
}

static int ls_get_wrapper(void *wrap)
{
	int ret = -1;
	size_t len = 0;
	struct wrapargs *wargs = (struct wrapargs *)wrap;
	struct ls *m = NULL, *n = NULL;

	/* close pipe */
	close(wargs->pipefd[0]);

	/* &(char *){NULL} is no magic. It's just a compound literal which
	 * allows us to avoid keeping a pointless variable around. */
	ls_get(&m, &len, wargs->args, "", wargs->parent, wargs->nestlvl, &(char *){NULL}, 0, wargs->grps_must, wargs->grps_must_len);
	if (!m)
		goto out;

	/* send length */
	if (lxc_write_nointr(wargs->pipefd[1], &len, sizeof(len)) <= 0)
		goto out;

	size_t i;
	for (i = 0, n = m; i < len; i++, n++) {
		if (ls_serialize(wargs->pipefd[1], n) == -1)
			goto out;
	}
	ret = 0;

out:
	shutdown(wargs->pipefd[1], SHUT_RDWR);
	close(wargs->pipefd[1]);
	ls_free(m, len);

	return ret;
}

static int ls_remove_lock(const char *path, const char *name,
		char **lockpath, size_t *len_lockpath, bool recalc)
{
	/* Avoid doing unnecessary work if we can. */
	if (recalc) {
		size_t newlen = strlen(path) + strlen(name) + strlen(RUNTIME_PATH) + /* / + lxc + / + lock + / + / = */ 11 + 1;
		if (newlen > *len_lockpath) {
			char *tmp = realloc(*lockpath, newlen * 2);
			if (!tmp)
				return -1;
			*lockpath = tmp;
			*len_lockpath = newlen * 2;
		}
	}

	int check = snprintf(*lockpath, *len_lockpath, "%s/lxc/lock/%s/%s", RUNTIME_PATH, path, name);
	if (check < 0 || (size_t)check >= *len_lockpath)
		return -1;

	lxc_rmdir_onedev(*lockpath, NULL);

	return 0;
}

static int ls_send_str(int fd, const char *buf)
{
	size_t slen = 0;
	if (buf)
		slen = strlen(buf);
	if (lxc_write_nointr(fd, &slen, sizeof(slen)) != sizeof(slen))
		return -1;
	if (slen > 0) {
		if (lxc_write_nointr(fd, buf, slen) != (ssize_t)slen)
			return -1;
	}
	return 0;
}

static int ls_serialize(int wpipefd, struct ls *n)
{
	ssize_t nbytes = sizeof(n->ram);
	if (lxc_write_nointr(wpipefd, &n->ram, (size_t)nbytes) != nbytes)
		return -1;

	nbytes = sizeof(n->swap);
	if (lxc_write_nointr(wpipefd, &n->swap, (size_t)nbytes) != nbytes)
		return -1;

	nbytes = sizeof(n->init);
	if (lxc_write_nointr(wpipefd, &n->init, (size_t)nbytes) != nbytes)
		return -1;

	nbytes = sizeof(n->autostart);
	if (lxc_write_nointr(wpipefd, &n->autostart, (size_t)nbytes) != nbytes)
		return -1;

	nbytes = sizeof(n->running);
	if (lxc_write_nointr(wpipefd, &n->running, (size_t)nbytes) != nbytes)
		return -1;

	nbytes = sizeof(n->nestlvl);
	if (lxc_write_nointr(wpipefd, &n->nestlvl, (size_t)nbytes) != nbytes)
		return -1;

	/* NAME */
	if (ls_send_str(wpipefd, n->name) < 0)
		return -1;

	/* STATE */
	if (ls_send_str(wpipefd, n->state) < 0)
		return -1;

	/* GROUPS */
	if (ls_send_str(wpipefd, n->groups) < 0)
		return -1;

	/* INTERFACE */
	if (ls_send_str(wpipefd, n->interface) < 0)
		return -1;

	/* IPV4 */
	if (ls_send_str(wpipefd, n->ipv4) < 0)
		return -1;

	/* IPV6 */
	if (ls_send_str(wpipefd, n->ipv6) < 0)
		return -1;

	return 0;
}

static int ls_recv_str(int fd, char **buf)
{
	size_t slen = 0;
	if (lxc_read_nointr(fd, &slen, sizeof(slen)) != sizeof(slen))
		return -1;
	if (slen > 0) {
		*buf = malloc(sizeof(char) * (slen + 1));
		if (!*buf)
			return -1;
		if (lxc_read_nointr(fd, *buf, slen) != (ssize_t)slen)
			return -1;
		(*buf)[slen] = '\0';
	}
	return 0;
}

static int ls_deserialize(int rpipefd, struct ls **m, size_t *len)
{
	struct ls *n;
	size_t sublen = 0;
	ssize_t nbytes = 0;

	/* get length */
	nbytes = sizeof(sublen);
	if (lxc_read_nointr(rpipefd, &sublen, (size_t)nbytes) != nbytes)
		return -1;

	while (sublen-- > 0) {
		n = ls_new(m, len);
		if (!n)
			return -1;

		nbytes = sizeof(n->ram);
		if (lxc_read_nointr(rpipefd, &n->ram, (size_t)nbytes) != nbytes)
			return -1;

		nbytes = sizeof(n->swap);
		if (lxc_read_nointr(rpipefd, &n->swap, (size_t)nbytes) != nbytes)
			return -1;

		nbytes = sizeof(n->init);
		if (lxc_read_nointr(rpipefd, &n->init, (size_t)nbytes) != nbytes)
			return -1;

		nbytes = sizeof(n->autostart);
		if (lxc_read_nointr(rpipefd, &n->autostart, (size_t)nbytes) != nbytes)
			return -1;

		nbytes = sizeof(n->running);
		if (lxc_read_nointr(rpipefd, &n->running, (size_t)nbytes) != nbytes)
			return -1;

		nbytes = sizeof(n->nestlvl);
		if (lxc_read_nointr(rpipefd, &n->nestlvl, (size_t)nbytes) != nbytes)
			return -1;

		/* NAME */
		if (ls_recv_str(rpipefd, &n->name) < 0)
			return -1;

		/* STATE */
		if (ls_recv_str(rpipefd, &n->state) < 0)
			return -1;

		/* GROUPS */
		if (ls_recv_str(rpipefd, &n->groups) < 0)
			return -1;

		/* INTERFACE */
		if (ls_recv_str(rpipefd, &n->interface) < 0)
			return -1;

		/* IPV4 */
		if (ls_recv_str(rpipefd, &n->ipv4) < 0)
			return -1;

		/* IPV6 */
		if (ls_recv_str(rpipefd, &n->ipv6) < 0)
			return -1;
	}

	return 0;
}

static void ls_field_width(const struct ls *l, const size_t size,
		struct lengths *lht)
{
	const struct ls *m;
	size_t i, len = 0;
	for (i = 0, m = l; i < size; i++, m++) {
		if (m->name) {
			len = strlen(m->name) + m->nestlvl;
			if (len > lht->name_length)
				lht->name_length = len;
		}

		if (m->state) {
			len = strlen(m->state);
			if (len > lht->state_length)
				lht->state_length = len;
		}

		if (m->interface) {
			len = strlen(m->interface);
			if (len > lht->interface_length)
				lht->interface_length = len;
		}

		if (m->groups) {
			len = strlen(m->groups);
			if (len > lht->groups_length)
				lht->groups_length = len;
		}
		if (m->ipv4) {
			len = strlen(m->ipv4);
			if (len > lht->ipv4_length)
				lht->ipv4_length = len;
		}

		if (m->ipv6) {
			len = strlen(m->ipv6);
			if (len > lht->ipv6_length)
				lht->ipv6_length = len;
		}

		if ((len = snprintf(NULL, 0, "%.2f", m->ram)) > lht->ram_length)
			lht->ram_length = len;

		if ((len = snprintf(NULL, 0, "%.2f", m->swap)) > lht->swap_length)
			lht->swap_length = len;

		if (m->init != -1) {
			if ((len = snprintf(NULL, 0, "%d", m->init)) > lht->init_length)
				lht->init_length = len;
		}
	}
}
