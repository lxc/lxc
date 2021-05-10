/* liblxcapi
 *
 * Copyright © 2021 Christian Brauner <christian.brauner@ubuntu.com>.
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

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "lxc/lxccontainer.h"

#include "lxctest.h"
#include "../lxc/lxc.h"
#include "../lxc/memory_utils.h"

#ifndef HAVE_STRLCPY
#include "include/strlcpy.h"
#endif

static const char *const arches[] = {
    "arm",   "armel",	"armhf",   "armv7l",	"athlon",  "i386",   "i486",
    "i586",  "i686",	"linux32", "mips",	"mipsel",  "ppc",    "powerpc",
    "x86",   "aarch64", "amd64",   "arm64",	"linux64", "mips64", "mips64el",
    "ppc64", "ppc64el", "ppc64le", "powerpc64", "s390x",   "x86_64",
};

static bool parse_valid_architectures(void)
{
	__put_lxc_container struct lxc_container *c = NULL;

	c = lxc_container_new("parse-arch", NULL);
	if (!c)
		return test_error_ret(false, "Failed to create container \"parse_arch\"");

	for (size_t i = 0; i < ARRAY_SIZE(arches); i++) {
		const char *arch = arches[i];

		if (!c->set_config_item(c, "lxc.arch", arch))
			return test_error_ret(false, "Failed to set \"lxc.arch=%s\"", arch);

		if (!c->clear_config_item(c, "lxc.arch"))
			return test_error_ret(false, "Failed to clear \"lxc.arch=%s\"", arch);
	}

	return true;
}

int main(int argc, char *argv[])
{
	if (!parse_valid_architectures())
		exit(EXIT_FAILURE);

	exit(EXIT_SUCCESS);
}
