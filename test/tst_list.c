#include <stdio.h>
#include <string.h>
#include <list.h>

int main(int argc, char *argv[])
{
	struct list *iterator;
	struct list head = init_list(&head);
	struct list l1 = init_list(&l1);
	struct list l2 = init_list(&l2);
	struct list l3 = init_list(&l3);
	struct list l4 = init_list(&l4);

	struct dummy {
		int a;
	};
	
	struct dummy *elem;
	struct dummy d1 = { .a = 1 };
	struct dummy d2 = { .a = 2 };
	struct dummy d3 = { .a = 3 };
	struct dummy d4 = { .a = 4 };

	if (!list_empty(&head)) {
		fprintf(stderr, "expected empty list\n");
		return -1;
	}

	l1.elem = &d1;
	l2.elem = &d2;
	l3.elem = &d3;
	l4.elem = &d4;

	list_add(&head, &l1);
	list_add(&head, &l2);
	list_add(&head, &l3);
	list_add(&head, &l4);

	list_for_each(iterator, &head) {
		elem = iterator->elem;
		printf("elem has %d\n", elem->a);
	}

	list_del(&l3);

	list_for_each(iterator, &head) {
		elem = iterator->elem;
		printf("elem has %d\n", elem->a);
	}
	
	list_del(&l1);
	list_del(&l2);
	list_del(&l4);

	if (!list_empty(&head)) {
		fprintf(stderr, "expected empty list\n");
		return -1;
	}

	list_for_each(iterator, &head) {
		fprintf(stderr, "should not loop\n");
		return -1;
	}

	return 0;
}
