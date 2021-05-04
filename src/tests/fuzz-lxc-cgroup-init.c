/* SPDX-License-Identifier: LGPL-2.1+ */

#include <stddef.h>
#include <stdint.h>

#include "cgroups/cgroup.h"
#include "conf.h"
#include "confile.h"
#include "lxctest.h"
#include "utils.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	int fd = -1;
	char tmpf[] = "/tmp/fuzz-lxc-cgroup-init-XXXXXX";
	struct lxc_conf *conf = NULL;
	int ret;
	struct cgroup_ops *ops;

	/*
	 * 100Kb should probably be enough to trigger all the issues
	 * we're interested in without any timeouts
	 */
	if (size > 102400)
		return 0;

	fd = lxc_make_tmpfile(tmpf, false);
	lxc_test_assert_abort(fd >= 0);
	lxc_write_nointr(fd, data, size);
	close(fd);

	conf = lxc_conf_init();
	lxc_test_assert_abort(conf);

	/* Test cgroup_init() with valid config. */
	ops = cgroup_init(conf);
	cgroup_exit(ops);

	ret = lxc_config_read(tmpf, conf, false);
	if (ret == 0) {
		/* Test cgroup_init() with likely garbage config. */
		ops = cgroup_init(conf);
		cgroup_exit(ops);
	}
	lxc_conf_free(conf);

	(void) unlink(tmpf);

	return 0;
}

