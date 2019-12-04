/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_ERROR_H
#define __LXC_ERROR_H

#define LXC_CLONE_ERROR "Failed to clone a new set of namespaces"
#define LXC_UNPRIV_EOPNOTSUPP "the requested function %s is not currently supported with unprivileged containers"

extern int  lxc_error_set_and_log(int pid, int status);

#endif
