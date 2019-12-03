/* SPDX-License-Identifier: LGPL-2.1+ */

#ifndef __LXC_LXCSECCOMP_H
#define __LXC_LXCSECCOMP_H

#include "conf.h"

#ifdef HAVE_SECCOMP
extern int lxc_seccomp_load(struct lxc_conf *conf);
extern int lxc_read_seccomp_config(struct lxc_conf *conf);
extern void lxc_seccomp_free(struct lxc_conf *conf);
#else
static inline int lxc_seccomp_load(struct lxc_conf *conf)
{
	return 0;
}

static inline int lxc_read_seccomp_config(struct lxc_conf *conf)
{
	return 0;
}

static inline void lxc_seccomp_free(struct lxc_conf *conf)
{
	free(conf->seccomp);
	conf->seccomp = NULL;
}
#endif

#endif
