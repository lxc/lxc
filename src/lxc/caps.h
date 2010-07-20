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
#ifndef _caps_h
#define _caps_h

extern int lxc_caps_reset(void);
extern int lxc_caps_down(void);
extern int lxc_caps_up(void);
extern int lxc_caps_init(void);

#define lxc_priv(__lxc_function)			\
	({						\
		int __ret, __ret2, __errno = 0;		\
		__ret = lxc_caps_up();			\
		if (__ret)				\
			goto __out;			\
		__ret = __lxc_function;			\
		if (__ret)				\
			__errno = errno;		\
		__ret2 = lxc_caps_down();		\
	__out:	__ret ? errno = __errno,__ret : __ret2;	\
	})

#define lxc_unpriv(__lxc_function)		\
	({						\
		int __ret, __ret2, __errno = 0;		\
		__ret = lxc_caps_down();		\
		if (__ret)				\
			goto __out;			\
		__ret = __lxc_function;			\
		if (__ret)				\
			__errno = errno;		\
		__ret2 = lxc_caps_up();			\
	__out:	__ret ? errno = __errno,__ret : __ret2;	\
	})
#endif
