/* SPDX-License-Identifier: GPL-2.0-only */

#include <string.h>
#include <stdio.h>

#define PREFIX "lxc-"

int lxc_attach_main(int argc, char *argv[]);
int lxc_autostart_main(int argc, char *argv[]);
int lxc_cgroup_main(int argc, char *argv[]);
int lxc_checkpoint_main(int argc, char *argv[]);
int lxc_config_main(int argc, char *argv[]);
int lxc_console_main(int argc, char *argv[]);
int lxc_copy_main(int argc, char *argv[]);
int lxc_create_main(int argc, char *argv[]);
int lxc_destroy_main(int argc, char *argv[]);
int lxc_device_main(int argc, char *argv[]);
int lxc_execute_main(int argc, char *argv[]);
int lxc_freeze_main(int argc, char *argv[]);
int lxc_info_main(int argc, char *argv[]);
int lxc_ls_main(int argc, char *argv[]);
int lxc_monitor_main(int argc, char *argv[]);
int lxc_snapshot_main(int argc, char *argv[]);
int lxc_start_main(int argc, char *argv[]);
int lxc_stop_main(int argc, char *argv[]);
int lxc_top_main(int argc, char *argv[]);
int lxc_unfreeze_main(int argc, char *argv[]);
int lxc_unshare_main(int argc, char *argv[]);
int lxc_wait_main(int argc, char *argv[]);

static const struct {
	const char *cmd;
	int (*main)(int argc, char *argv[]);
} applets[] = {
	{ "attach", lxc_attach_main },
	{ "autostart", lxc_autostart_main },
	{ "cgroup", lxc_cgroup_main },
	{ "checkpoint", lxc_checkpoint_main },
	{ "config", lxc_config_main },
	{ "console", lxc_console_main },
	{ "copy", lxc_copy_main },
	{ "create", lxc_create_main },
	{ "destroy", lxc_destroy_main },
	{ "device", lxc_device_main },
	{ "execute", lxc_execute_main },
	{ "freeze", lxc_freeze_main },
	{ "info", lxc_info_main },
	{ "ls", lxc_ls_main },
	{ "monitor", lxc_monitor_main },
	{ "snapshot", lxc_snapshot_main },
	{ "start", lxc_start_main },
	{ "stop", lxc_stop_main },
	{ "top", lxc_top_main },
	{ "unfreeze", lxc_unfreeze_main },
	{ "unshare", lxc_unshare_main },
	{ "wait", lxc_wait_main }
};

const int applets_nmemb = (int)(sizeof(applets)/sizeof(applets[0]));

int main(int argc, char *argv[])
{
	const char *cmd;
	int i;

	if (argc < 1)
		goto err0;

	cmd = strrchr(argv[0], '/');
	cmd = cmd ? cmd + 1 : argv[0];


	if (!strcmp(cmd, "lxc")) {
		if (argc < 2)
			goto err0;
		cmd = argv[1];
		argc -= 1;
		argv += 1;
		if (!strcmp(cmd, "-h") || !strcmp(cmd, "--help"))
			goto err0;
	} else if (!strncmp(cmd, PREFIX, strlen(PREFIX))) {
		cmd += strlen(PREFIX);
	} else {
		goto err0;
	}

	for (i = 0; i < applets_nmemb; i++) {
		if (!strcmp(applets[i].cmd, cmd))
			return applets[i].main(argc, argv);
	}

	fprintf(stderr, "Unsupported command '%s'\n", cmd);
	goto err1;

err0:	fprintf(stderr, "This is a multi-call binary, argv[0] is expected to be\n"
			"  a name of the requested command prefixed with '%s'\n"
			"or\n"
			"  'lxc' and the command should be the 1st argument.\n\n"
			"For example calling this program as '%sls' or 'lxc' "
			"with the argument 'ls' lists containers.\n\n",
			PREFIX, PREFIX);
err1:	fprintf(stderr, "Known commands:\n");
	for (i = 0; i < applets_nmemb; i++) {
		fprintf(stderr, "%s ", applets[i].cmd);
	}
	putc('\n', stderr);
	return 1;
}
