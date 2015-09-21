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

#include <limits.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#define _GNU_SOURCE
#include <getopt.h>

#include <lxc/lxccontainer.h>

static int nthreads = 5;
static int iterations = 1;
static int debug = 0;
static int quiet = 0;
static int delay = 0;
static const char *template = "busybox";

static const struct option options[] = {
    { "threads",     required_argument, NULL, 'j' },
    { "iterations",  required_argument, NULL, 'i' },
    { "template",    required_argument, NULL, 't' },
    { "delay",       required_argument, NULL, 'd' },
    { "modes",       required_argument, NULL, 'm' },
    { "quiet",       no_argument,       NULL, 'q' },
    { "debug",       no_argument,       NULL, 'D' },
    { "help",        no_argument,       NULL, '?' },
    { 0, 0, 0, 0 },
};

static void usage(void) {
    fprintf(stderr, "Usage: lxc-test-concurrent [OPTION]...\n\n"
        "Common options :\n"
        "  -j, --threads=N              Threads to run concurrently\n"
        "                               (default: 5, use 1 for no threading)\n"
        "  -i, --iterations=N           Number times to run the test (default: 1)\n"
        "  -t, --template=t             Template to use (default: busybox)\n"
        "  -d, --delay=N                Delay in seconds between start and stop\n"
        "  -m, --modes=<mode,mode,...>  Modes to run (create, start, stop, destroy)\n"
        "  -q, --quiet                  Don't produce any output\n"
        "  -D, --debug                  Create a debug log\n"
        "  -?, --help                   Give this help list\n"
        "\n"
        "Mandatory or optional arguments to long options are also mandatory or optional\n"
        "for any corresponding short options.\n\n");
}

struct thread_args {
    int thread_id;
    int return_code;
    const char *mode;
};

static void do_function(void *arguments)
{
    char name[NAME_MAX+1];
    struct thread_args *args = arguments;
    struct lxc_container *c;

    sprintf(name, "lxc-test-concurrent-%d", args->thread_id);

    args->return_code = 1;
    c = lxc_container_new(name, NULL);
    if (!c) {
        fprintf(stderr, "Unable to instantiate container (%s)\n", name);
        return;
    }

    if (debug) {
        c->set_config_item(c, "lxc.loglevel", "DEBUG");
        c->set_config_item(c, "lxc.logfile", name);
    }

    if (strcmp(args->mode, "create") == 0) {
        if (!c->is_defined(c)) {
            if (!c->create(c, template, NULL, NULL, 1, NULL)) {
                fprintf(stderr, "Creating the container (%s) failed...\n", name);
                goto out;
            }
        }
    } else if(strcmp(args->mode, "start") == 0) {
        if (c->is_defined(c) && !c->is_running(c)) {
            c->want_daemonize(c, true);
            if (!c->start(c, false, NULL)) {
                fprintf(stderr, "Starting the container (%s) failed...\n", name);
                goto out;
            }
            if (!c->wait(c, "RUNNING", 15)) {
                fprintf(stderr, "Waiting the container (%s) to start failed...\n", name);
                goto out;
            }
            sleep(delay);
        }
    } else if(strcmp(args->mode, "stop") == 0) {
        if (c->is_defined(c) && c->is_running(c)) {
            if (!c->stop(c)) {
                fprintf(stderr, "Stopping the container (%s) failed...\n", name);
                goto out;
            }
            if (!c->wait(c, "STOPPED", 15)) {
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
    if (debug)
        lxc_log_close();
}

static void *concurrent(void *arguments)
{
    do_function(arguments);
    pthread_exit(NULL);

    return NULL;
}

int main(int argc, char *argv[]) {
    int i, j, iter, opt;
    pthread_attr_t attr;
    pthread_t *threads;
    struct thread_args *args;

    char *modes_default[] = {"create", "start", "stop", "destroy", NULL};
    char **modes = modes_default;

    pthread_attr_init(&attr);

    while ((opt = getopt_long(argc, argv, "j:i:t:d:m:qD", options, NULL)) != -1) {
        switch(opt) {
        case 'j':
            nthreads = atoi(optarg);
            break;
        case 'i':
            iterations = atoi(optarg);
            break;
        case 't':
            template = optarg;
            break;
        case 'd':
            delay = atoi(optarg);
            break;
        case 'q':
            quiet = 1;
            break;
        case 'D':
            debug = 1;
            break;
        case 'm': {
            char *mode_tok, *tok, *saveptr = NULL;

            modes = NULL;
            for (i = 0, mode_tok = optarg;
                 (tok = strtok_r(mode_tok, ",", &saveptr));
                i++, mode_tok = NULL) {
                modes = realloc(modes, sizeof(*modes) * (i+2));
                if (!modes) {
                    perror("realloc");
                    exit(EXIT_FAILURE);
                }
                modes[i] = tok;
            }
            modes[i] = NULL;
            break;
        }
        default: /* '?' */
            usage();
            exit(EXIT_FAILURE);
        }
    }

    threads = malloc(sizeof(*threads) * nthreads);
    args = malloc(sizeof(*args) * nthreads);
    if (threads == NULL || args == NULL) {
        fprintf(stderr, "Unable malloc enough memory for %d threads\n", nthreads);
        exit(EXIT_FAILURE);
    }

    for (iter = 1; iter <= iterations; iter++) {
        int fd;
        fd = open("/", O_RDONLY);
        if (fd < 0) {
            fprintf(stderr, "Failed to open /\n");
            continue;
        }

        if (!quiet)
            printf("\nIteration %d/%d maxfd:%d\n", iter, iterations, fd);
        close(fd);

        for (i = 0; modes[i];i++) {
            if (!quiet)
                printf("Executing (%s) for %d containers...\n", modes[i], nthreads);
            for (j = 0; j < nthreads; j++) {
                args[j].thread_id = j;
                args[j].mode = modes[i];

                if (nthreads > 1) {
                    if (pthread_create(&threads[j], &attr, concurrent, (void *) &args[j]) != 0) {
                        perror("pthread_create() error");
                        exit(EXIT_FAILURE);
                    }
                } else {
                    do_function(&args[j]);
                }
            }

            for (j = 0; j < nthreads; j++) {
                if (nthreads > 1) {
                    if (pthread_join(threads[j], NULL) != 0) {
                        perror("pthread_join() error");
                        exit(EXIT_FAILURE);
                    }
                }
                if (args[j].return_code) {
                    fprintf(stderr, "thread returned error %d\n", args[j].return_code);
                    exit(EXIT_FAILURE);
                }
            }
        }
    }

    free(args);
    free(threads);
    pthread_attr_destroy(&attr);
    exit(EXIT_SUCCESS);
}
