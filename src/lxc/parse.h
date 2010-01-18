/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Daniel Lezcano <dlezcano at fr.ibm.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
#ifndef __parse_h
#define __parse_h

typedef int (*lxc_dir_cb)(const char *name, const char *directory,
			  const char *file, void *data);

typedef int (*lxc_file_cb)(char *buffer, void *data);

extern int lxc_dir_for_each(const char *name, const char *directory,
			    lxc_dir_cb callback, void *data);

extern int lxc_file_for_each_line(const char *file, lxc_file_cb callback,
				  void* data);

extern int lxc_char_left_gc(char *buffer, size_t len);

extern int lxc_char_right_gc(char *buffer, size_t len);

extern int lxc_is_line_empty(char *line);

#endif
