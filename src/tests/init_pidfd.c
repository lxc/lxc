// SPDX-License-Identifier: LGPL-2.1+
#include <stdio.h>
#include <unistd.h>
#include <lxc/lxccontainer.h>

int main(int argc, char **argv)
{
	struct lxc_container *c;
	int fd;

	if (argc != 2)
		return 1;
	c = lxc_container_new(argv[1], NULL);
	if (!c)
		return 1;
	fd = c->init_pidfd(c);
	lxc_container_put(c);
	if (fd < 0) {
		fprintf(stderr, "Failed to obtain restored init pidfd\n");
		return 1;
	}
	close(fd);
	return 0;
}
