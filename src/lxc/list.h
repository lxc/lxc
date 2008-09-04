#ifndef _list_h
#define _list_h

struct list {
	void *elem;
	struct list *next;
	struct list *prev;
};

#define init_list(l) { .next = l, .prev = l, }

#define list_for_each(__iterator, __list)				\
	for (__iterator = (__list)->next;				\
	     __iterator != __list;					\
	     __iterator = __iterator->next)

static inline void list_init(struct list *list)
{
	list->elem = NULL;
	list->next = list->prev = list;
}

static inline void list_add_elem(struct list *list, void *elem)
{
	list->elem = elem;
}

static inline void *list_first_elem(struct list *list)
{
	return list->next->elem;
}

static inline int list_empty(struct list *list)
{
	return list == list->next;
}

static inline void list_add(struct list *list, struct list *new)
{
	struct list *next = list->next;
	next->prev = new;
	new->next = next;
	new->prev = list;
	list->next = new;
}

static inline void list_del(struct list *list)
{
	struct list *next, *prev;

	next = list->next;
	prev = list->prev;
	next->prev = prev;
	prev->next = next;
}

#endif
