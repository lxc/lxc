/*
 *
 * Copyright © 2013 Serge Hallyn <serge.hallyn@ubuntu.com>.
 * Copyright © 2013 Canonical Ltd.
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

#include <ctype.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <lxc/lxccontainer.h>
#include <sys/types.h>

#include "arguments.h"
#include "log.h"
#include "lxc.h"
#include "utils.h"
#include "bdev/bdev.h"

lxc_log_define(lxc_create_ui, lxc);

static uint64_t get_fssize(char *s)
{
	uint64_t ret;
	char *end;

	ret = strtoull(s, &end, 0);
	if (end == s)
	{
		fprintf(stderr, "Invalid blockdev size '%s', using default size\n", s);
		return 0;
	}
	while (isblank(*end))
		end++;
	if (*end == '\0')
		ret *= 1024ULL * 1024ULL; // MB by default
	else if (*end == 'b' || *end == 'B')
		ret *= 1ULL;
	else if (*end == 'k' || *end == 'K')
		ret *= 1024ULL;
	else if (*end == 'm' || *end == 'M')
		ret *= 1024ULL * 1024ULL;
	else if (*end == 'g' || *end == 'G')
		ret *= 1024ULL * 1024ULL * 1024ULL;
	else if (*end == 't' || *end == 'T')
		ret *= 1024ULL * 1024ULL * 1024ULL * 1024ULL;
	else
	{
		fprintf(stderr, "Invalid blockdev unit size '%c' in '%s', using default size\n", *end, s);
		return 0;
	}
	return ret;
}

static int my_parser(struct lxc_arguments* args, int c, char* arg)
{
	switch (c) {
	case 'B': args->bdevtype = arg; break;
	case 'f': args->configfile = arg; break;
	case 't': args->template = arg; break;
	case '0': args->lvname = arg; break;
	case '1': args->vgname = arg; break;
	case '2': args->thinpool = arg; break;
	case '3': args->fstype = arg; break;
	case '4': args->fssize = get_fssize(arg); break;
	case '5': args->zfsroot = arg; break;
	case '6': args->dir = arg; break;
	case '7': args->rbdname = arg; break;
	case '8': args->rbdpool = arg; break;
	}
	return 0;
}

static const struct option my_longopts[] = {
	{"bdev", required_argument, 0, 'B'},
	{"config", required_argument, 0, 'f'},
	{"template", required_argument, 0, 't'},
	{"lvname", required_argument, 0, '0'},
	{"vgname", required_argument, 0, '1'},
	{"thinpool", required_argument, 0, '2'},
	{"fstype", required_argument, 0, '3'},
	{"fssize", required_argument, 0, '4'},
	{"zfsroot", required_argument, 0, '5'},
	{"dir", required_argument, 0, '6'},
	{"rbdname", required_argument, 0, '7'},
	{"rbdpool", required_argument, 0, '8'},
	LXC_COMMON_OPTIONS
};

static void create_helpfn(const struct lxc_arguments *args)
{
	char *argv[3], *path;
	pid_t pid;

	if (!args->template)
		return;

	pid = fork();
	if (pid) {
		wait_for_pid(pid);
		return;
	}

	path = get_template_path(args->template);

	argv[0] = path;
	argv[1] = "-h";
	argv[2] = NULL;

	execv(path, argv);
	ERROR("Error executing %s -h", path);
	exit(EXIT_FAILURE);
}

static struct lxc_arguments my_args = {
	.progname = "lxc-create",
	.helpfn   = create_helpfn,
	.help     = "\
--name=NAME --template=TEMPLATE [OPTION...]\n\
\n\
lxc-create creates a container\n\
\n\
Options :\n\
  -n, --name=NAME               NAME of the container\n\
  -f, --config=CONFIG           Initial configuration file\n\
  -t, --template=TEMPLATE       Template to use to setup container\n\
  -B, --bdev=BDEV               Backing store type to use\n\
      --dir=DIR                 Place rootfs directory under DIR\n\
\n\
  BDEV options for LVM (with -B/--bdev lvm):\n\
      --lvname=LVNAME           Use LVM lv name LVNAME\n\
                                (Default: container name)\n\
      --vgname=VG               Use LVM vg called VG\n\
                                (Default: lxc)\n\
      --thinpool=TP             Use LVM thin pool called TP\n\
                                (Default: lxc)\n\
\n\
  BDEV options for Ceph RBD (with -B/--bdev rbd) :\n\
      --rbdname=RBDNAME         Use Ceph RBD name RBDNAME\n\
                                (Default: container name)\n\
      --rbdpool=POOL            Use Ceph RBD pool name POOL\n\
                                (Default: lxc)\n\
\n\
  BDEV option for ZFS (with -B/--bdev zfs) :\n\
      --zfsroot=PATH            Create zfs under given zfsroot\n\
                                (Default: tank/lxc)\n\
\n\
  BDEV options for LVM or Loop (with -B/--bdev lvm/loop) :\n\
      --fstype=TYPE             Create fstype TYPE\n\
                                (Default: ext3)\n\
      --fssize=SIZE[U]          Create filesystem of\n\
                                size SIZE * unit U (bBkKmMgGtT)\n\
                                (Default: 1G, default unit: M)\n",
	.options  = my_longopts,
	.parser   = my_parser,
	.checker  = NULL,
};

static bool validate_bdev_args(struct lxc_arguments *a)
{
	if (strcmp(a->bdevtype, "best") != 0) {
		if (a->fstype || a->fssize) {
			if (strcmp(a->bdevtype, "lvm") != 0 &&
			    strcmp(a->bdevtype, "loop") != 0 &&
			    strcmp(a->bdevtype, "rbd") != 0) {
				fprintf(stderr, "filesystem type and size are only valid with block devices\n");
				return false;
			}
		}
		if (strcmp(a->bdevtype, "lvm") != 0) {
			if (a->lvname || a->vgname || a->thinpool) {
				fprintf(stderr, "--lvname, --vgname and --thinpool are only valid with -B lvm\n");
				return false;
			}
		}
		if (strcmp(a->bdevtype, "rbd") != 0) {
			if (a->rbdname || a->rbdpool) {
				fprintf(stderr, "--rbdname and --rbdpool are only valid with -B rbd\n");
				return false;
			}
		}
		if (strcmp(a->bdevtype, "zfs") != 0) {
			if (a->zfsroot) {
				fprintf(stderr, "zfsroot is only valid with -B zfs\n");
				return false;
			}
		}
	}
	return true;
}

int main(int argc, char *argv[])
{
	struct lxc_container *c;
	struct bdev_specs spec;
	int flags = 0;

	if (lxc_arguments_parse(&my_args, argc, argv))
		exit(EXIT_FAILURE);

	if (!my_args.log_file)
		my_args.log_file = "none";

	if (lxc_log_init(my_args.name, my_args.log_file, my_args.log_priority,
			 my_args.progname, my_args.quiet, my_args.lxcpath[0]))
		exit(EXIT_FAILURE);
	lxc_log_options_no_override();

	if (!my_args.template) {
		fprintf(stderr, "A template must be specified.\n");
		fprintf(stderr, "Use \"none\" if you really want a container without a rootfs.\n");
		exit(EXIT_FAILURE);
	}

	if (strcmp(my_args.template, "none") == 0)
		my_args.template = NULL;

	memset(&spec, 0, sizeof(spec));
	if (!my_args.bdevtype)
		my_args.bdevtype = "_unset";

	if (!validate_bdev_args(&my_args))
		exit(EXIT_FAILURE);

	if (strcmp(my_args.bdevtype, "none") == 0)
		my_args.bdevtype = "dir";

	// Final check whether the user gave use a valid bdev type.
	if (strcmp(my_args.bdevtype, "best") &&
	    strcmp(my_args.bdevtype, "_unset") &&
	    !is_valid_bdev_type(my_args.bdevtype)) {
		fprintf(stderr, "%s is not a valid backing storage type.\n", my_args.bdevtype);
		exit(EXIT_FAILURE);
	}

	if (geteuid()) {
		if (mkdir_p(my_args.lxcpath[0], 0755)) {
			exit(EXIT_FAILURE);
		}
		if (access(my_args.lxcpath[0], O_RDWR) < 0) {
			fprintf(stderr, "You lack access to %s\n", my_args.lxcpath[0]);
			exit(EXIT_FAILURE);
		}
		if (strcmp(my_args.bdevtype, "dir") && strcmp(my_args.bdevtype, "_unset") &&
				strcmp(my_args.bdevtype, "btrfs")) {
			fprintf(stderr, "Unprivileged users cannot create %s containers", my_args.bdevtype);
			exit(EXIT_FAILURE);
		}
	}


	c = lxc_container_new(my_args.name, my_args.lxcpath[0]);
	if (!c) {
		fprintf(stderr, "Failed to create lxc container.\n");
		exit(EXIT_FAILURE);
	}
	if (c->is_defined(c)) {
		lxc_container_put(c);
		fprintf(stderr, "Container already exists\n");
		exit(EXIT_FAILURE);
	}
	if (my_args.configfile)
		c->load_config(c, my_args.configfile);
	else
		c->load_config(c, lxc_global_config_value("lxc.default_config"));

	if (my_args.fstype)
		spec.fstype = my_args.fstype;
	if (my_args.fssize)
		spec.fssize = my_args.fssize;

	if ((strcmp(my_args.bdevtype, "zfs") == 0) || (strcmp(my_args.bdevtype, "best") == 0)) {
		if (my_args.zfsroot)
			spec.zfs.zfsroot = my_args.zfsroot;
	}

	if ((strcmp(my_args.bdevtype, "lvm") == 0) || (strcmp(my_args.bdevtype, "best") == 0)) {
		if (my_args.lvname)
			spec.lvm.lv = my_args.lvname;
		if (my_args.vgname)
			spec.lvm.vg = my_args.vgname;
		if (my_args.thinpool)
			spec.lvm.thinpool = my_args.thinpool;
	}

	if ((strcmp(my_args.bdevtype, "rbd") == 0) || (strcmp(my_args.bdevtype, "best") == 0)) {
		if (my_args.rbdname)
			spec.rbd.rbdname = my_args.rbdname;
		if (my_args.rbdpool)
			spec.rbd.rbdpool = my_args.rbdpool;
	}

	if (my_args.dir)
		spec.dir = my_args.dir;

	if (strcmp(my_args.bdevtype, "_unset") == 0)
		my_args.bdevtype = NULL;

	if (my_args.quiet)
		flags = LXC_CREATE_QUIET;

	if (!c->create(c, my_args.template, my_args.bdevtype, &spec, flags, &argv[optind])) {
		ERROR("Error creating container %s", c->name);
		lxc_container_put(c);
		exit(EXIT_FAILURE);
	}

	lxc_container_put(c);
	INFO("container %s created", c->name);
	exit(EXIT_SUCCESS);
}
