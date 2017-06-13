/* liblxcapi
 *
 * Copyright © 2017 Christian Brauner <christian.brauner@ubuntu.com>.
 * Copyright © 2017 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdio.h>
#include <string.h>

#include "conf.h"
#include "log.h"
#include "utils.h"

int parse_idmaps(const char *idmap, char *type, unsigned long *nsid,
		 unsigned long *hostid, unsigned long *range)
{
	int ret = -1;
	unsigned long tmp_hostid, tmp_nsid, tmp_range;
	char tmp_type;
	char *window, *slide;
	char *dup = NULL;

	/* Duplicate string. */
	dup = strdup(idmap);
	if (!dup)
		goto on_error;

	/* A prototypical idmap entry would be: "u 1000 1000000 65536" */

	/* align */
	slide = window = dup;
	/* skip whitespace */
	slide += strspn(slide, " \t\r");
	if (slide != window && *slide == '\0')
		goto on_error;

	/* Validate type. */
	if (*slide != 'u' && *slide != 'g')
		goto on_error;
	/* Assign type. */
	tmp_type = *slide;

	/* move beyond type */
	slide++;
	/* align */
	window = slide;
	/* Validate that only whitespace follows. */
	slide += strspn(slide, " \t\r");
	/* There must be whitespace. */
	if (slide == window)
		goto on_error;

	/* Mark beginning of nsuid. */
	window = slide;
	/* Validate that non-whitespace follows. */
	slide += strcspn(slide, " \t\r");
	/* There must be non-whitespace. */
	if (slide == window || *slide == '\0')
		goto on_error;
	/* Mark end of nsuid. */
	*slide = '\0';

	/* Parse nsuid. */
	if (lxc_safe_ulong(window, &tmp_nsid) < 0)
		goto on_error;

	/* Move beyond \0. */
	slide++;
	/* align */
	window = slide;
	/* Validate that only whitespace follows. */
	slide += strspn(slide, " \t\r");
	/* If there was only one whitespace then we whiped it with our \0 above.
	 * So only ensure that we're not at the end of the string.
	 */
	if (*slide == '\0')
		goto on_error;

	/* Mark beginning of hostid. */
	window = slide;
	/* Validate that non-whitespace follows. */
	slide += strcspn(slide, " \t\r");
	/* There must be non-whitespace. */
	if (slide == window || *slide == '\0')
		goto on_error;
	/* Mark end of nsuid. */
	*slide = '\0';

	/* Parse hostid. */
	if (lxc_safe_ulong(window, &tmp_hostid) < 0)
		goto on_error;

	/* Move beyond \0. */
	slide++;
	/* align */
	window = slide;
	/* Validate that only whitespace follows. */
	slide += strspn(slide, " \t\r");
	/* If there was only one whitespace then we whiped it with our \0 above.
	 * So only ensure that we're not at the end of the string.
	 */
	if (*slide == '\0')
		goto on_error;

	/* Mark beginning of range. */
	window = slide;
	/* Validate that non-whitespace follows. */
	slide += strcspn(slide, " \t\r");
	/* There must be non-whitespace. */
	if (slide == window)
		goto on_error;

	/* The range is the last valid entry we expect. So make sure that there
	 * is not trailing garbage and if there is, error out.
	 */
	if (*(slide + strspn(slide, " \t\r\n")) != '\0')
		goto on_error;
	/* Mark end of range. */
	*slide = '\0';

	/* Parse range. */
	if (lxc_safe_ulong(window, &tmp_range) < 0)
		goto on_error;

	*type = tmp_type;
	*nsid = tmp_nsid;
	*hostid = tmp_hostid;
	*range = tmp_range;

	/* Yay, we survived. */
	ret = 0;

on_error:
	free(dup);

	return ret;
}

bool lxc_config_value_empty(const char *value)
{
	if (value && strlen(value) > 0)
		return false;

	return true;
}
