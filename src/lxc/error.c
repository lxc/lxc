/* SPDX-License-Identifier: LGPL-2.1+ */

#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>

#include "error.h"
#include "log.h"

lxc_log_define(error, lxc);

/*---------------------------------------------------------------------------*/
/* lxc_error_set_and_log
 * function is here to convert
 * the reported status to an exit code as detailed here:
 *
 *   0-126       exit code of the application
 *   128+n       signal n received by the application
 *   255         lxc error
 */
int lxc_error_set_and_log(int pid, int status)
{
	int ret = 0;

	if (WIFEXITED(status)) {
		ret = WEXITSTATUS(status);
		if (ret)
			INFO("Child <%d> ended on error (%d)", pid, ret);
	}

	if (WIFSIGNALED(status)) {
		int signal = WTERMSIG(status);
		INFO("Child <%d> ended on signal (%d)", pid, signal);
		ret = 128 + signal;
	}

	return ret;
}
