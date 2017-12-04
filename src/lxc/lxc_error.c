#ifndef _GNU_SOURCE
#define _GNU_SOURCE
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
*/
#include "lxc_error.h"

/* from lxccontainer.h */
/* struct lxc_container {
  char *name;
  char *error_string;
  int error_num;
  //<other fun stuff>
}; */

#define DEBUG 0
#define LXC_MALLOC_ERR "Malloc failed"

/* need to work on memory leaks */

/* concatenate error numbers for later dumping, could just as easily use a queue
 * to store them, but struct element is char * and I haven't asked them about it */
void *lxc_error_concat(struct lxc_container *c, char *lxc_error, int LXC_ERROR_CODE)
{
  char *error_string = c->error_string;
  int error_num = c->error_num;
  size_t error_string_len = 0;
  size_t error_len = 0;
  char *new_error_string;
  int new_error_num;

  /* nothing changes */
  if ((!error_string && !lxc_error) || (error_string && !lxc_error)) {
    new_error_string = error_string;
    new_error_num = error_num;
  } else if (!error_string && lxc_error) {
    /* lxc_error not null, can dereference and get length + 1 for NULL */
    error_len = strlen(lxc_error) + 1;
    new_error_string = malloc(error_len);

    if (!new_error_string) {
      fprintf(stderr, "%s\n", LXC_MALLOC_ERR);
      exit(EXIT_FAILURE);
    }

    asprintf(&new_error_string, "%s", lxc_error);
    new_error_num = LXC_ERROR_CODE;
  } else {
    /* error_string not null, can dereference and get length + 1 for NULL */
    error_string_len = strlen(error_string) + 1;
    error_len = strlen(lxc_error) + 1;

    /* extra byte for duplicate delimiter could avoid confusion */
    int new_error_len = error_string_len + error_len;
    new_error_string = malloc(new_error_len);

    if (!new_error_string) {
      fprintf(stderr, "%s\n", LXC_MALLOC_ERR);
      exit(EXIT_FAILURE);
    }

    asprintf(&new_error_string, "%s~%s", error_string, lxc_error);
    new_error_num = LXC_ERROR_CODE;
    free(error_string);
  }
  c->error_string = new_error_string;
  c->error_num = new_error_num;
}

/* Make error printing human readable, and reset error_string to new error */
void lxc_error_dump(struct lxc_container *c, char *lxc_error, int LXC_ERROR_CODE)
{
  /* intelligence for error dump */
  int dump;
  switch (LXC_ERROR_CODE) {
    case LXC_FORK_ERR :
      dump = 1;
      break;
    case LXC_FD_ERR :
      dump = 0;
      break;
    /* etc...
     *
     *
     */
    default :
      dump = 0;
  } 

  /* dump and concat, dump just changes initial condition */
  if (dump) {
    char *local_str = malloc(strlen(c->error_string) + 1);
    if (!local_str) {
      fprintf(stderr, "%s\n", LXC_MALLOC_ERR);
      exit(EXIT_FAILURE);
    }
    strcpy(local_str, c->error_string);

    char *head = local_str;
    char *strerror = strtok_r(head, "~", &head);

    printf("lxc_error_dump:\n");
    while (strerror != NULL) {
      printf("\t%s\n", strerror);
      strerror = strtok_r(head, "~", &head);
    }

    free(local_str);
    free(c->error_string);
    c->error_string = NULL;
    c->error_num = -1;
  }
  lxc_error_concat(c, lxc_error, LXC_ERROR_CODE);
}

/* to be filled in later by various error handling codes */
int lxc_error_handle(struct lxc_container *c)
{
  int error_num = c->error_num;
  int success = 0;

  switch (error_num) {
    case LXC_FORK_ERR :
      //success = handle_fork_err(); 
      break;
    case LXC_FD_ERR :
      //success = handle_fd_err(); 
      break;
    /* etc...
     *
     *
     */
    default :
      printf("Unknown error code\n");
  } 
  return success;
}

//lxc_error_dump(c, lxc_error, LXC_FORK_ERR);
void test_dump(struct lxc_container *c)
{
  /* test zero, start null */
  printf("Before test zero, expect '(null)' and '-1'\n \
      c->error_string: %s, c->error_num: %d\n", c->error_string, c->error_num);

  lxc_error_dump(c, "this should concatenate", 20);
  printf("After test zero, expect 'this should concatenate' and '20'\n \
      c->error_string: %s, c->error_num: %d\n", c->error_string, c->error_num);

  /* test one */
  lxc_error_dump(c, "one more err", 21);
  printf("After test one, expect 'this should concatenate~one more err' and '21'\n \
      c->error_string: %s, c->error_num: %d\n", c->error_string, c->error_num);

  /* test two */
  lxc_error_dump(c, NULL, 30);
  printf("After test two, expect 'this should concatenate~one more err' and '21'\n \
      c->error_string: %s, c->error_num: %d\n", c->error_string, c->error_num);

  /* test three */
  lxc_error_dump(c, "failed to fork", LXC_FORK_ERR);
  printf("After test three, expect dump of errors and now 'failed to fork' and '7'\n \
      c->error_string: %s, c->error_num: %d\n", c->error_string, c->error_num);
  
  free(c->error_string);
}

/* main method for testing error handling functions */
/* argument parsing, fills up my_args in other functions */
int main(void)
{
  //struct lxc_container *c = lxc_container_new(my_args.name, my_args.lxcpath[0]);
  struct lxc_container *c = NULL;
  char *lxc_error = NULL;
  c = malloc(sizeof(struct lxc_container));

  if (!c) {
    printf("%s\n", LXC_MALLOC_ERR);
    exit(EXIT_FAILURE);
  }

  c->name = "test";
  c->error_string = NULL;
  c->error_num = -1;

  /* container does things, sometime hits error */
  //pid_t p = fork();
  pid_t p = -1;
  if (p < 0) {
    /* how it looks now */
    //fprintf(stderr, "failed to fork task\n"); OR SYSERROR("failed to fork task");

    /* these next 3 lines are the goal, to get added everywhere */
    //lxc_error = "failed to fork task";
    //SYSERROR(%s, lxc_error);
    //lxc_error_dump(c, lxc_error, LXC_FORK_ERR);

    test_dump(c);

    free(c);
    exit(EXIT_FAILURE);
  }
  free(c);
  exit(EXIT_SUCCESS);
}

/* Notes
 *
 * 1. Thought we might be able to store a couple of string digits that would
 *    map to an error, which would then get translated into the full string
 *    error codes they represent upon "dumping" the errors.
 *    Issue: Mix of generic and specific print statements, %s, %d, OOM, etc
 *    Resolution: Only use codes for error_num, lxc_error passed instead
 *
 * 2. Tried to mirror format of existing *.h files with #ifdef/etc
 * 
 * 3. Could come up with a better ordering for macros (by file?)
 *
 * 4. Way to pinpoint file + error together (my_args.progname)
 *
 */
