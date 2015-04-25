/*
 * lxc: linux Container library
 *
 * (C) Copyright IBM Corp. 2007, 2008
 *
 * Authors:
 * Daniel Lezcano <daniel.lezcano at free.fr>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef __LXC_LIST_H
#define __LXC_LIST_H

struct lxc_list {
	void *elem;
	struct lxc_list *next;
	struct lxc_list *prev;
};

#define lxc_init_list(l) { .next = l, .prev = l }

#define lxc_list_for_each(__iterator, __list)				\
	for (__iterator = (__list)->next;				\
	     __iterator != __list;					\
	     __iterator = __iterator->next)

#define lxc_list_for_each_safe(__iterator, __list, __next)		\
	for (__iterator = (__list)->next, __next = __iterator->next;	\
	     __iterator != __list;					\
	     __iterator = __next, __next = __next->next)

static inline void lxc_list_init(struct lxc_list *list)
{
	list->elem = NULL;
	list->next = list->prev = list;
}

static inline void lxc_list_add_elem(struct lxc_list *list, void *elem)
{
	list->elem = elem;
}

static inline void *lxc_list_first_elem(struct lxc_list *list)
{
	return list->next->elem;
}

static inline void *lxc_list_last_elem(struct lxc_list *list)
{
	return list->prev->elem;
}

static inline int lxc_list_empty(struct lxc_list *list)
{
	return list == list->next;
}

static inline void __lxc_list_add(struct lxc_list *new,
				  struct lxc_list *prev,
				  struct lxc_list *next)
{
        next->prev = new;
        new->next = next;
        new->prev = prev;
        prev->next = new;
}

static inline void lxc_list_add(struct lxc_list *head, struct lxc_list *list)
{
	__lxc_list_add(list, head, head->next);
}

static inline void lxc_list_add_tail(struct lxc_list *head,
				     struct lxc_list *list)
{
	__lxc_list_add(list, head->prev, head);
}

static inline void lxc_list_del(struct lxc_list *list)
{
	struct lxc_list *next, *prev;

	next = list->next;
	prev = list->prev;
	next->prev = prev;
	prev->next = next;
}

static inline int lxc_list_len(struct lxc_list *list)
{
	 int i = 0;
	 struct lxc_list *iter;
	 lxc_list_for_each(iter, list) {
		i++;
	 }

	 return i;
}

#endif
