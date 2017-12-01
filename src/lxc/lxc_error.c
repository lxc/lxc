#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

//#include "config.h"

#include <errno.h>
#include <fcntl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

//#include <lxc/lxccontainer.h>

/*#include "attach.h"
#include "arguments.h"
#include "caps.h"
#include "conf.h"
#include "confile.h"
#include "console.h"
#include "log.h"
#include "list.h"
#include "mainloop.h"
#include "utils.h"

#include "lxc_error.h"*/

/* from lxccontainer.h */
struct lxc_container {
  char *name;
  char *error_string;
  int error_num;
  //<other fun stuff>
};

#define LXC_FORK_ERR "01"

#define DEBUG 1

/* concatenate error numbers for later dumping */
char *lxc_error_concat(char *error_string, char *lxc_error_code) {
  char *new_error_string = NULL;

  /* error code is always same length, +1 for last null */
  size_t ERROR_LEN = 2 + 1;

  if (!error_string) {
    new_error_string = malloc(sizeof(lxc_error_code));
    asprintf(&new_error_string, "%s", lxc_error_code);
  } else {
    /* error_string_len not null, can dereference and get length*/
    size_t error_string_len = strlen(error_string) + 1;
    if (DEBUG)
      printf("error_string_len: %lu\n", error_string_len);
    new_error_string = malloc(sizeof(error_string_len + ERROR_LEN ));
    asprintf(&new_error_string, "%s:%s", error_string, lxc_error_code);
  }
  if (DEBUG)
    printf("new_error_string: %s\n", new_error_string);

  return new_error_string;
}


/* Make error printing human readable */
/* massive case statement for up to 100 unique errors (2 digits per error) */
/*void lxc_error_dump(struct lxc_container *c) {
  
  switch(lxc_error) {

    case LXC_OOM_ERR :

  }
}*/

/* main method for testing error handling functions */
int main(void) {
  /* argument parsing, fills up my_args in other functions */
  //struct lxc_container *c = lxc_container_new(my_args.name, my_args.lxcpath[0]);
  struct lxc_container *c = NULL;
  c = malloc(sizeof(struct lxc_container));
  c->name = "test";
  c->error_string = NULL;
  c->error_num = -1;
  if (DEBUG)
    printf("LXC_FORK_ERR: %s\n", LXC_FORK_ERR);

  /* container does things, sometime hits error */
  //pid_t p = fork();
  pid_t p = -1;
  if (p < 0) {
    if (DEBUG)
      fprintf(stderr, "failed to fork task\n");

    // lxc_error_dump(c);
    c->error_string = lxc_error_concat("01:00:00:11:21", LXC_FORK_ERR);
     
    free(c);
    exit(EXIT_FAILURE);
  }
  free(c);
  exit(EXIT_SUCCESS);
}
