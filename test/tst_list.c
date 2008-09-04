#include <stdio.h>
#include <string.h>
#include <lxc/lxc_list.h>

int main(int argc, char *argv[])
{
	struct lxc_list *iterator;
	struct lxc_list head = lxc_init_list(&head);
	struct lxc_list l1 = lxc_init_list(&l1);
	struct lxc_list l2 = lxc_init_list(&l2);
	struct lxc_list l3 = lxc_init_list(&l3);
	struct lxc_list l4 = lxc_init_list(&l4);

	struct dummy {
		int a;
	};
	
	struct dummy *elem;
	struct dummy d1 = { .a = 1 };
	struct dummy d2 = { .a = 2 };
	struct dummy d3 = { .a = 3 };
	struct dummy d4 = { .a = 4 };

	if (!lxc_list_empty(&head)) {
		fprintf(stderr, "expected empty list\n");
		return -1;
	}

	l1.elem = &d1;
	l2.elem = &d2;
	l3.elem = &d3;
	l4.elem = &d4;

	lxc_list_add(&head, &l1);
	lxc_list_add(&head, &l2);
	lxc_list_add(&head, &l3);
	lxc_list_add(&head, &l4);

	lxc_list_for_each(iterator, &head) {
		elem = iterator->elem;
		printf("elem has %d\n", elem->a);
	}

	lxc_list_del(&l3);

	lxc_list_for_each(iterator, &head) {
		elem = iterator->elem;
		printf("elem has %d\n", elem->a);
	}
	
	lxc_list_del(&l1);
	lxc_list_del(&l2);
	lxc_list_del(&l4);

	if (!lxc_list_empty(&head)) {
		fprintf(stderr, "expected empty list\n");
		return -1;
	}

	lxc_list_for_each(iterator, &head) {
		fprintf(stderr, "should not loop\n");
		return -1;
	}

	return 0;
}
