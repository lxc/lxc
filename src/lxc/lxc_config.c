#include <stdio.h>
#include "config.h"
#include "lxccontainer.h"

struct lxc_config_items {
	char *name;
	const char *(*fn)(void);
};

struct lxc_config_items items[] =
{
	{ .name = "lxcpath", .fn = &lxc_get_default_config_path, },
	{ .name = "lvm_vg", .fn = &lxc_get_default_lvm_vg, },
	{ .name = "zfsroot", .fn = &lxc_get_default_zfs_root, },
	{ .name = NULL, },
};

void usage(char *me)
{
	printf("Usage: %s -l: list all available configuration items\n", me);
	printf("       %s item: print configuration item\n", me);
	exit(1);
}

void list_config_items(void)
{
	struct lxc_config_items *i;

	for (i = &items[0]; i->name; i++)
		printf("%s\n", i->name);
	exit(0);
}

int main(int argc, char *argv[])
{
	struct lxc_config_items *i;

	if (argc < 2)
		usage(argv[0]);
	if (strcmp(argv[1], "-l") == 0)
		list_config_items();
	for (i = &items[0]; i->name; i++) {
		if (strcmp(argv[1], i->name) == 0) {
			printf("%s\n", i->fn());
			exit(0);
		}
	}
	printf("Unknown configuration item: %s\n", argv[1]);
	exit(-1);
}
