/* liblxcapi
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "config.h"

#include <string.h>
#include <limits.h>

#include "lxc/lxccontainer.h"
#include "lxctest.h"

int main(int argc, char *argv[])
{
	struct lxc_container *c;
	struct migrate_opts m_opts;
	int ret = EXIT_FAILURE;

	/* Test the feature check interface,
	 * we actually do not need a container. */
	c = lxc_container_new("check_feature", NULL);
	if (!c) {
		lxc_error("%s", "Failed to create container \"check_feature\"");
		exit(ret);
	}

	if (c->is_defined(c)) {
		lxc_error("%s\n", "Container \"check_feature\" is defined");
		goto on_error_put;
	}

	/* check the migrate API call with wrong 'cmd' */
	if (!c->migrate(c, UINT_MAX, &m_opts, sizeof(struct migrate_opts))) {
		/* This should failed */
		lxc_error("%s\n", "Migrate API calls with command UINT_MAX did not fail");
		goto on_error_put;
	}

	/* do the actual feature check for memory tracking */
	m_opts.features_to_check = FEATURE_MEM_TRACK;
	if (c->migrate(c, MIGRATE_FEATURE_CHECK, &m_opts, sizeof(struct migrate_opts))) {
		lxc_debug("%s\n", "System does not support \"FEATURE_MEM_TRACK\".");
	}

	/* check for lazy pages */
	m_opts.features_to_check = FEATURE_LAZY_PAGES;
	if (c->migrate(c, MIGRATE_FEATURE_CHECK, &m_opts, sizeof(struct migrate_opts))) {
		lxc_debug("%s\n", "System does not support \"FEATURE_LAZY_PAGES\".");
	}

	/* check for lazy pages and memory tracking */
	m_opts.features_to_check = FEATURE_LAZY_PAGES | FEATURE_MEM_TRACK;
	if (c->migrate(c, MIGRATE_FEATURE_CHECK, &m_opts, sizeof(struct migrate_opts))) {
		if (m_opts.features_to_check == FEATURE_LAZY_PAGES)
			lxc_debug("%s\n", "System does not support \"FEATURE_MEM_TRACK\"");
		else if (m_opts.features_to_check == FEATURE_MEM_TRACK)
			lxc_debug("%s\n", "System does not support \"FEATURE_LAZY_PAGES\"");
		else
			lxc_debug("%s\n", "System does not support \"FEATURE_MEM_TRACK\" "
					"and \"FEATURE_LAZY_PAGES\"");
	}

	/* test for unknown feature; once there are 64 features to test
	 * this will be valid... */
	m_opts.features_to_check = -1ULL;
	if (!c->migrate(c, MIGRATE_FEATURE_CHECK, &m_opts, sizeof(struct migrate_opts))) {
		lxc_error("%s\n", "Unsupported feature supported, which is strange.");
		goto on_error_put;
	}

	ret = EXIT_SUCCESS;

on_error_put:
	lxc_container_put(c);
	if (ret == EXIT_SUCCESS)
		lxc_debug("%s\n", "All criu feature check tests passed");

	exit(ret);
}
