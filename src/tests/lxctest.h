/*
 * lxc: linux Container library
 *
 * Copyright © 2016 Canonical Ltd.
 *
 * Authors:
 * Christian Brauner <christian.brauner@mailbox.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef __LXC_TEST_H_
#define __LXC_TEST_H_

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#define lxc_debug_stream(stream, format, ...)                                  \
	do {                                                                   \
		fprintf(stream, "%s: %d: %s: " format "\n", __FILE__, __LINE__,     \
			__func__, __VA_ARGS__);                                \
	} while (false)

#define lxc_error(format, ...) lxc_debug_stream(stderr, format, __VA_ARGS__)
#define lxc_debug(format, ...) lxc_debug_stream(stdout, format, __VA_ARGS__)

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
