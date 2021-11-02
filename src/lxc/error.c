/* SPDX-License-Identifier: LGPL-2.1+ */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>

#include "error.h"
#include "log.h"
#include "process_utils.h"

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
	} else if (WIFSIGNALED(status)) {
		int signal_nr = WTERMSIG(status);
		INFO("Child <%d> ended on signal %s(%d)", pid, signal_name(signal_nr), signal_nr);
		ret = 128 + signal_nr;
	} else {
		ERROR("Invalid exit status (%d)", status);
	}

	return ret;
}
