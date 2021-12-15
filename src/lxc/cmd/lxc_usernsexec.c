/* SPDX-License-Identifier: LGPL-2.1+ */

#include "config.h"
#include "lxc.h"

static void usage(const char *name)
{
	printf("usage: %s [-h] [-m <uid-maps>] [-s] -- [command [arg ..]]\n", name);
	printf("\n");
	printf("  -h            this message\n");
	printf("\n");
	printf("  -m <uid-maps> uid maps to use\n");
	printf("\n");
	printf("  -s:           map self\n");
	printf("  uid-maps: [u|g|b]:ns_id:host_id:range\n");
	printf("            [u|g|b]: map user id, group id, or both\n");
	printf("            ns_id: the base id in the new namespace\n");
	printf("            host_id: the base id in the parent namespace\n");
	printf("            range: how many ids to map\n");
	printf("  Note: This program uses newuidmap(2) and newgidmap(2).\n");
	printf("        As such, /etc/subuid and /etc/subgid must grant the\n");
	printf("        calling user permission to use the mapped ranges\n");
}

int main(int argc, char *argv[])
{

	int ret, status;

	ret = lxc_usernsexec(argc, argv, &status);
	if (ret < 0) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}
	if (ret > 0)
		exit(EXIT_FAILURE);

	if (!WIFEXITED(status))
		exit(EXIT_FAILURE);
	_exit(WEXITSTATUS(status));
}
