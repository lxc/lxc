/* lxc: linux Container library
 *
 * SPDX-License-Identifier: LGPL-2.1+
 *
 */

#ifndef __LXC_TEST_H_
#define __LXC_TEST_H_

#include "config.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#define lxc_debug_stream(stream, format, ...)                         \
	do {                                                          \
		fprintf(stream, "%s: %d: %s: " format "\n", __FILE__, \
			__LINE__, __func__, ##__VA_ARGS__);           \
	} while (false)

#define lxc_error(format, ...) lxc_debug_stream(stderr, format, ##__VA_ARGS__)
#define lxc_debug(format, ...) lxc_debug_stream(stdout, format, ##__VA_ARGS__)

#define lxc_test_assert_stringify(expression, stringify_expression)            \
	do {                                                                   \
		if (!(expression)) {                                           \
			fprintf(stderr, "%s: %s: %d: %s\n", __FILE__,          \
				__func__, __LINE__, stringify_expression);     \
			abort();                                               \
		}                                                              \
	} while (false)

#define lxc_test_assert_abort(expression) lxc_test_assert_stringify(expression, #expression)

#define test_error_ret(__ret__, format, ...)                  \
	({                                                    \
		typeof(__ret__) __internal_ret__ = (__ret__); \
		fprintf(stderr, format, ##__VA_ARGS__);       \
		__internal_ret__;                             \
	})

#endif /* __LXC_TEST_H */
