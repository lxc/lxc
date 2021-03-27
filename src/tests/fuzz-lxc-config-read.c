/* SPDX-License-Identifier: LGPL-2.1+ */

#include <stddef.h>
#include <stdint.h>

#include "conf.h"
#include "confile.h"
#include "lxctest.h"
#include "utils.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	int fd = -1;
	char tmpf[] = "/tmp/fuzz-lxc-config-read-XXXXXX";
	struct lxc_conf *conf = NULL;

	fd = lxc_make_tmpfile(tmpf, false);
	lxc_test_assert_abort(fd >= 0);
	lxc_write_nointr(fd, data, size);
	close(fd);

	conf = lxc_conf_init();
	lxc_test_assert_abort(conf);
	lxc_config_read(tmpf, conf, false);

	(void) unlink(tmpf);
	return 0;
}
