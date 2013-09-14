/* concurrent.c
 *
 * Copyright © 2013 S.Çağlar Onur <caglar@10ur.org>
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
#include <pthread.h>

#include "../lxc/lxccontainer.h"

#define NTHREADS 5

char *template = "busybox";

struct thread_args {
    int thread_id;
    int return_code;
    char *mode;
};

void * concurrent(void *arguments) {
    char name[4];
    struct thread_args *args = arguments;
    struct lxc_container *c;

    sprintf(name, "%d", args->thread_id);

    c = lxc_container_new(name, NULL);

    args->return_code = 1;
    if (strcmp(args->mode, "create") == 0) {
        if (!c->is_defined(c)) {
            if (!c->create(c, template, NULL, NULL, 1, NULL)) {
                fprintf(stderr, "Creating the container (%s) failed...\n", name);
                goto out;
            }
        }
    } else if(strcmp(args->mode, "start") == 0) {
        if (c->is_defined(c) && !c->is_running(c)) {
            c->want_daemonize(c);
            if (!c->start(c, false, NULL)) {
                fprintf(stderr, "Starting the container (%s) failed...\n", name);
                goto out;
            }
            if (!c->wait(c, "RUNNING", -1)) {
                fprintf(stderr, "Waiting the container (%s) to start failed...\n", name);
                goto out;
            }
        }
    } else if(strcmp(args->mode, "stop") == 0) {
        if (c->is_defined(c) && c->is_running(c)) {
            if (!c->stop(c)) {
                fprintf(stderr, "Stopping the container (%s) failed...\n", name);
                goto out;
            }
            if (!c->wait(c, "STOPPED", -1)) {
                fprintf(stderr, "Waiting the container (%s) to stop failed...\n", name);
                goto out;
            }
        }
    } else if(strcmp(args->mode, "destroy") == 0) {
        if (c->is_defined(c) && !c->is_running(c)) {
            if (!c->destroy(c)) {
                fprintf(stderr, "Destroying the container (%s) failed...\n", name);
                goto out;
            }
        }
    }
    args->return_code = 0;
out:
    lxc_container_put(c);
    pthread_exit(NULL);
}


int main(int argc, char *argv[]) {
    int i, j;
    pthread_attr_t attr;
    pthread_t threads[NTHREADS];
    struct thread_args args[NTHREADS];

    char *modes[] = {"create", "start", "stop", "destroy", NULL};

    if (argc > 1)
	    template = argv[1];

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    for (i = 0; modes[i];i++) {
        printf("Executing (%s) for %d containers...\n", modes[i], NTHREADS);
        for (j = 0; j < NTHREADS; j++) {
            args[j].thread_id = j;
            args[j].mode = modes[i];

            if (pthread_create(&threads[j], &attr, concurrent, (void *) &args[j]) != 0) {
                perror("pthread_create() error");
                exit(EXIT_FAILURE);
            }
        }

        for (j = 0; j < NTHREADS; j++) {
            if ( pthread_join(threads[j], NULL) != 0) {
                perror("pthread_join() error");
                exit(EXIT_FAILURE);
            }
            if (args[j].return_code) {
                perror("thread returned an error");
                exit(EXIT_FAILURE);
            }
        }
        printf("\n");
    }

    pthread_attr_destroy(&attr);
    exit(EXIT_SUCCESS);
}
