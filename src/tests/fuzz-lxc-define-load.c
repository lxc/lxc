/* SPDX-License-Identifier: LGPL-2.1+ */

#include <stddef.h>
#include <stdint.h>

#include "conf.h"
#include "confile.h"
#include "lxctest.h"
#include "utils.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	__do_free char *new_str = NULL;
	struct lxc_container *c = NULL;
	struct lxc_list defines;
	struct lxc_list *it;
	__do_close int devnull_fd = -EBADF;

	if (size > 102400)
		return 0;

	c = lxc_container_new("FUZZ", NULL);
	lxc_test_assert_abort(c);

	new_str = (char *)malloc(size+1);
	lxc_test_assert_abort(new_str);
	memcpy(new_str, data, size);
	new_str[size] = '\0';

	lxc_list_init(&defines);

	if (lxc_config_define_add(&defines, new_str) < 0)
		goto out;

	if (!lxc_config_define_load(&defines, c))
		goto out;

	devnull_fd = open_devnull();
	lxc_test_assert_abort(devnull_fd >= 0);

	lxc_list_for_each(it, &defines) {
		__do_free char *val = NULL;
		struct new_config_item *config_item = it->elem;
		int len;

		len = c->get_config_item(c, config_item->key, NULL, 0);
		if (len < 0)
			continue;

		val = (char *)malloc(len + 1);
		lxc_test_assert_abort(val);

		if (c->get_config_item(c, config_item->key, val, len + 1) != len)
			continue;

		if (len > 0)
			dprintf(devnull_fd, "[%s/%s]\n", config_item->key, val);
	}

out:
	lxc_container_put(c);
	lxc_config_define_free(&defines);

	return 0;
}
