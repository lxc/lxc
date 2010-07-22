#ifndef _list_h
#define _list_h

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

#endif
