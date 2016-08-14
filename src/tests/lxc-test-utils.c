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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lxctest.h"
#include "utils.h"

void test_lxc_string_replace(void)
{
	char *s;

	s = lxc_string_replace("A", "A", "A");
	lxc_test_assert_abort(strcmp(s, "A") == 0);
	free(s);

	s = lxc_string_replace("A", "AA", "A");
	lxc_test_assert_abort(strcmp(s, "AA") == 0);
	free(s);

	s = lxc_string_replace("A", "AA", "BA");
	lxc_test_assert_abort(strcmp(s, "BAA") == 0);
	free(s);

	s = lxc_string_replace("A", "AA", "BAB");
	lxc_test_assert_abort(strcmp(s, "BAAB") == 0);
	free(s);

	s = lxc_string_replace("AA", "A", "AA");
	lxc_test_assert_abort(strcmp(s, "A") == 0);
	free(s);

	s = lxc_string_replace("AA", "A", "BAA");
	lxc_test_assert_abort(strcmp(s, "BA") == 0);
	free(s);

	s = lxc_string_replace("AA", "A", "BAAB");
	lxc_test_assert_abort(strcmp(s, "BAB") == 0);
	free(s);

	s = lxc_string_replace("\"A\"A", "\"A\"", "B\"A\"AB");
	lxc_test_assert_abort(strcmp(s, "B\"A\"B") == 0);
	free(s);
}

void test_lxc_string_in_array(void)
{
	lxc_test_assert_abort(lxc_string_in_array("", (const char *[]){"", NULL}));
	lxc_test_assert_abort(!lxc_string_in_array("A", (const char *[]){"", NULL}));
	lxc_test_assert_abort(!lxc_string_in_array("AAA", (const char *[]){"", "3472", "jshH", NULL}));

	lxc_test_assert_abort(lxc_string_in_array("A", (const char *[]){"A", NULL}));
	lxc_test_assert_abort(lxc_string_in_array("A", (const char *[]){"A", "B", "C", NULL}));
	lxc_test_assert_abort(lxc_string_in_array("A", (const char *[]){"B", "A", "C", NULL}));

	lxc_test_assert_abort(lxc_string_in_array("ABC", (const char *[]){"ASD", "ATR", "ABC", NULL}));
	lxc_test_assert_abort(lxc_string_in_array("GHJ", (const char *[]){"AZIU", "WRT567B", "879C", "GHJ", "IUZ89", NULL}));
	lxc_test_assert_abort(lxc_string_in_array("XYZ", (const char *[]){"BERTA", "ARQWE(9", "C8Zhkd", "7U", "XYZ", "UOIZ9", "=)()", NULL}));
}

int main(int argc, char *argv[])
{
	test_lxc_string_replace();
	test_lxc_string_in_array();

	exit(EXIT_SUCCESS);
}
