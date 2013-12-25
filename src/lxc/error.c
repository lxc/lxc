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
#include <stdlib.h>
#include <sys/wait.h>

#include "error.h"
#include "log.h"

lxc_log_define(lxc_error, lxc);

/*---------------------------------------------------------------------------*/
/* lxc_error_set_and_log
 * function is here to convert
 * the reported status to an exit code as detailed here:
 *
 *   0-126       exit code of the application
 *   128+n       signal n received by the application
 *   255         lxc error
 */
extern int  lxc_error_set_and_log(int pid, int status)
{
	int ret = 0;

	if (WIFEXITED(status)) {
		ret = WEXITSTATUS(status);
		if (ret)
			INFO("child <%d> ended on error (%d)", pid, ret);
	}

	if (WIFSIGNALED(status)) {
		int signal = WTERMSIG(status);

		INFO("child <%d> ended on signal (%d)", pid, signal);
	}

	return ret;
}
