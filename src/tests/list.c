/* list.c
 *
 * Copyright © 2013 Canonical, Inc
 * Author: Serge Hallyn <serge.hallyn@ubuntu.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <lxc/lxccontainer.h>

int main(int argc, char *argv[])
{
	char *lxcpath = NULL;
	struct lxc_container **clist;
	char **names;
	int i, n, n2;

	if (argc > 1)
		lxcpath = argv[1];

	printf("Counting defined containers only\n");
	n = list_defined_containers(lxcpath, NULL, NULL);
	printf("Found %d defined containers\n", n);
	printf("Looking for defined containers only\n");
	n2 = list_defined_containers(lxcpath, NULL, &clist);
	if (n2 != n)
		printf("Warning: first call returned %d, second %d\n", n, n2);
	for (i=0; i<n2; i++) {
		struct lxc_container *c = clist[i];
		printf("Found defined container %s\n", c->name);
		lxc_container_put(c);
	}
	if (n2 > 0)
		free(clist);

	printf("Looking for defined names only\n");
	n2 = list_defined_containers(lxcpath, &names, NULL);
	if (n2 != n)
		printf("Warning: first call returned %d, second %d\n", n, n2);
	for (i=0; i<n2; i++) {
		printf("Found defined container %s\n", names[i]);
		free(names[i]);
	}
	if (n2 > 0)
		free(names);

	printf("Looking for defined names and containers\n");
	n2 = list_defined_containers(lxcpath, &names, &clist);
	if (n2 != n)
		printf("Warning: first call returned %d, second %d\n", n, n2);
	for (i=0; i<n2; i++) {
		struct lxc_container *c = clist[i];
		printf("Found defined container %s, name was %s\n", c->name, names[i]);
		free(names[i]);
		lxc_container_put(c);
	}
	if (n2 > 0) {
		free(names);
		free(clist);
	}


	printf("Counting active containers only\n");
	n = list_active_containers(lxcpath, NULL, NULL);
	printf("Found %d active containers\n", n);
	printf("Looking for active containers only\n");
	n2 = list_active_containers(lxcpath, NULL, &clist);
	if (n2 != n)
		printf("Warning: first call returned %d, second %d\n", n, n2);
	for (i=0; i<n2; i++) {
		printf("Found active container %s\n", clist[i]->name);
		lxc_container_put(clist[i]);
	}
	if (n2 > 0)
		free(clist);

	printf("Looking for active names only\n");
	n2 = list_active_containers(lxcpath, &names, NULL);
	if (n2 != n)
		printf("Warning: first call returned %d, second %d\n", n, n2);
	for (i=0; i<n2; i++) {
		printf("Found active container %s\n", names[i]);
		free(names[i]);
	}
	if (n2 > 0)
		free(names);

	printf("Looking for active names and containers\n");
	n2 = list_active_containers(lxcpath, &names, &clist);
	if (n2 != n)
		printf("Warning: first call returned %d, second %d\n", n, n2);
	for (i=0; i<n2; i++) {
		struct lxc_container *c = clist[i];
		printf("Found active container %s, name was %s\n", c->name, names[i]);
		free(names[i]);
		lxc_container_put(c);
	}
	if (n2 > 0) {
		free(names);
		free(clist);
	}

	exit(0);
}
