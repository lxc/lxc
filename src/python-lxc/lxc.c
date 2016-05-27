/*
 * python-lxc: Python bindings for LXC
 *
 * (C) Copyright Canonical Ltd. 2012-2013
 *
 * Authors:
 * Stéphane Graber <stgraber@ubuntu.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
 * USA
 */

#include <Python.h>
#include "structmember.h"
#include <lxc/lxccontainer.h>
#include <stdio.h>
#include <sys/wait.h>
#include <sched.h>

/*
 * CLONE_* definitions copied from lxc/namespace.h
 */
#ifndef CLONE_FS
#  define CLONE_FS                0x00000200
#endif
#ifndef CLONE_NEWNS
#  define CLONE_NEWNS             0x00020000
#endif
#ifndef CLONE_NEWCGROUP
#  define CLONE_NEWCGROUP         0x02000000
#endif
#ifndef CLONE_NEWUTS
#  define CLONE_NEWUTS            0x04000000
#endif
#ifndef CLONE_NEWIPC
#  define CLONE_NEWIPC            0x08000000
#endif
#ifndef CLONE_NEWUSER
#  define CLONE_NEWUSER           0x10000000
#endif
#ifndef CLONE_NEWPID
#  define CLONE_NEWPID            0x20000000
#endif
#ifndef CLONE_NEWNET
#  define CLONE_NEWNET            0x40000000
#endif

/* From sys/personality.h */
#define PER_LINUX 0x0000
#define PER_LINUX32 0x0008

/* Helper functions */

/* Copied from lxc/utils.c */
static int lxc_wait_for_pid_status(pid_t pid)
{
    int status, ret;

again:
    ret = waitpid(pid, &status, 0);
    if (ret == -1) {
        if (errno == EINTR)
            goto again;
        return -1;
    }
    if (ret != pid)
        goto again;
    return status;
}

/* Copied from lxc/confile.c, with HAVE_SYS_PERSONALITY_H check removed */
signed long lxc_config_parse_arch(const char *arch)
{
    struct per_name {
        char *name;
        unsigned long per;
    } pername[] = {
        { "x86", PER_LINUX32 },
        { "linux32", PER_LINUX32 },
        { "i386", PER_LINUX32 },
        { "i486", PER_LINUX32 },
        { "i586", PER_LINUX32 },
        { "i686", PER_LINUX32 },
        { "athlon", PER_LINUX32 },
        { "linux64", PER_LINUX },
        { "x86_64", PER_LINUX },
        { "amd64", PER_LINUX },
    };
    size_t len = sizeof(pername) / sizeof(pername[0]);

    size_t i;

    for (i = 0; i < len; i++) {
        if (!strcmp(pername[i].name, arch))
            return pername[i].per;
    }

    return -1;
}

char**
convert_tuple_to_char_pointer_array(PyObject *argv) {
    int argc;
    int i, j;
    char **result;

    /* not a list or tuple */
    if (!PyList_Check(argv) && !PyTuple_Check(argv)) {
        PyErr_SetString(PyExc_TypeError, "Expected list or tuple.");
        return NULL;
    }

    argc = PySequence_Fast_GET_SIZE(argv);

    result = (char**) calloc(argc + 1, sizeof(char*));

    if (result == NULL) {
        PyErr_SetNone(PyExc_MemoryError);
        return NULL;
    }

    for (i = 0; i < argc; i++) {
        char *str = NULL;
        PyObject *pystr = NULL;
        PyObject *pyobj = PySequence_Fast_GET_ITEM(argv, i);
        assert(pyobj != NULL);

        if (!PyUnicode_Check(pyobj)) {
            PyErr_SetString(PyExc_ValueError, "Expected a string");
            goto error;
        }

        pystr = PyUnicode_AsUTF8String(pyobj);
        if (!pystr) {
            /* Maybe it wasn't UTF-8 encoded.  An exception is already set. */
            goto error;
        }

        str = PyBytes_AsString(pystr);
        if (!str) {
            /* Maybe pystr wasn't a valid object. An exception is already set.
             */
            Py_DECREF(pystr);
            goto error;
        }

        /* We must make a copy of str, because it points into internal memory
         * which we do not own.  Assume it's NULL terminated, otherwise we'd
         * have to use PyUnicode_AsUTF8AndSize() and be explicit about copying
         * the memory.
         */
        result[i] = strdup(str);

        /* Do not decref pyobj since we stole a reference by using
         * PyTuple_GET_ITEM().
         */
        Py_DECREF(pystr);
        if (result[i] == NULL) {
            PyErr_SetNone(PyExc_MemoryError);
            goto error;
        }
    }

    result[argc] = NULL;
    return result;

error:
    /* We can only iterate up to but not including i because malloc() does not
     * initialize its memory.  Thus if we got here, i points to the index
     * after the last strdup'd entry in result.
     */
    for (j = 0; j < i; j++)
        free(result[j]);
    free(result);
    return NULL;
}

struct lxc_attach_python_payload {
    PyObject *fn;
    PyObject *arg;
};

static int lxc_attach_python_exec(void* _payload)
{
    /* This function is the first one to be called after attaching to a
     * container. As lxc_attach() calls fork() PyOS_AfterFork should be called
     * in the new process if the Python interpreter will continue to be used.
     */
    PyOS_AfterFork();

    struct lxc_attach_python_payload *payload =
        (struct lxc_attach_python_payload *)_payload;
    PyObject *result = PyObject_CallFunctionObjArgs(payload->fn,
                                                    payload->arg, NULL);

    if (!result) {
        PyErr_Print();
        return -1;
    }
    if (PyLong_Check(result))
        return (int)PyLong_AsLong(result);
    else
        return -1;
}

static void lxc_attach_free_options(lxc_attach_options_t *options);

static lxc_attach_options_t *lxc_attach_parse_options(PyObject *kwds)
{
    static char *kwlist[] = {"attach_flags", "namespaces", "personality",
                             "initial_cwd", "uid", "gid", "env_policy",
                             "extra_env_vars", "extra_keep_env", "stdin",
                             "stdout", "stderr", NULL};
    long temp_uid, temp_gid;
    int temp_env_policy;
    PyObject *extra_env_vars_obj = NULL;
    PyObject *extra_keep_env_obj = NULL;
    PyObject *stdin_obj = NULL;
    PyObject *stdout_obj = NULL;
    PyObject *stderr_obj = NULL;
    PyObject *initial_cwd_obj = NULL;
    PyObject *dummy = NULL;
    bool parse_result;

    lxc_attach_options_t default_options = LXC_ATTACH_OPTIONS_DEFAULT;
    lxc_attach_options_t *options = malloc(sizeof(*options));

    if (!options) {
        PyErr_SetNone(PyExc_MemoryError);
        return NULL;
    }
    memcpy(options, &default_options, sizeof(*options));

    /* we need some dummy variables because we can't be sure
     * the data types match completely */
    temp_uid = -1;
    temp_gid = -1;
    temp_env_policy = options->env_policy;

    /* we need a dummy tuple */
    dummy = PyTuple_New(0);

    parse_result = PyArg_ParseTupleAndKeywords(dummy, kwds, "|iilO&lliOOOOO",
                                               kwlist, &options->attach_flags,
                                               &options->namespaces,
                                               &options->personality,
                                               PyUnicode_FSConverter,
                                               &initial_cwd_obj, &temp_uid,
                                               &temp_gid, &temp_env_policy,
                                               &extra_env_vars_obj,
                                               &extra_keep_env_obj,
                                               &stdin_obj, &stdout_obj,
                                               &stderr_obj);

    /* immediately get rid of the dummy tuple */
    Py_DECREF(dummy);

    if (!parse_result) {
        lxc_attach_free_options(options);
        return NULL;
    }

    /* duplicate the string, so we don't depend on some random Python object */
    if (initial_cwd_obj != NULL) {
        options->initial_cwd = strndup(PyBytes_AsString(initial_cwd_obj),
                                       PyBytes_Size(initial_cwd_obj));
        Py_DECREF(initial_cwd_obj);
    }

    /* do the type conversion from the types that match the parse string */
    if (temp_uid != -1) options->uid = (uid_t)temp_uid;
    if (temp_gid != -1) options->gid = (gid_t)temp_gid;
    options->env_policy = (lxc_attach_env_policy_t)temp_env_policy;

    if (extra_env_vars_obj)
        options->extra_env_vars =
            convert_tuple_to_char_pointer_array(extra_env_vars_obj);
    if (extra_keep_env_obj)
        options->extra_keep_env =
            convert_tuple_to_char_pointer_array(extra_keep_env_obj);
    if (stdin_obj) {
        options->stdin_fd = PyObject_AsFileDescriptor(stdin_obj);
        if (options->stdin_fd < 0) {
            lxc_attach_free_options(options);
            return NULL;
        }
    }
    if (stdout_obj) {
        options->stdout_fd = PyObject_AsFileDescriptor(stdout_obj);
        if (options->stdout_fd < 0) {
            lxc_attach_free_options(options);
            return NULL;
        }
    }
    if (stderr_obj) {
        options->stderr_fd = PyObject_AsFileDescriptor(stderr_obj);
        if (options->stderr_fd < 0) {
            lxc_attach_free_options(options);
            return NULL;
        }
    }

    return options;
}

void lxc_attach_free_options(lxc_attach_options_t *options)
{
    int i;
    if (!options)
        return;
    free(options->initial_cwd);
    if (options->extra_env_vars) {
        for (i = 0; options->extra_env_vars[i]; i++)
            free(options->extra_env_vars[i]);
        free(options->extra_env_vars);
    }
    if (options->extra_keep_env) {
        for (i = 0; options->extra_keep_env[i]; i++)
            free(options->extra_keep_env[i]);
        free(options->extra_keep_env);
    }
    free(options);
}

/* Module functions */
static PyObject *
LXC_arch_to_personality(PyObject *self, PyObject *arg)
{
    long rv = -1;
    PyObject *pystr = NULL;
    char *str;

    if (!PyUnicode_Check(arg)) {
        PyErr_SetString(PyExc_ValueError, "Expected a string");
        return NULL;
    }

    pystr = PyUnicode_AsUTF8String(arg);
    if (!pystr)
        return NULL;

    str = PyBytes_AsString(pystr);
    if (!str)
        goto out;

    rv = lxc_config_parse_arch(str);
    if (rv == -1)
        PyErr_SetString(PyExc_KeyError, "Failed to lookup architecture.");

out:
    Py_DECREF(pystr);
    return rv == -1 ? NULL : PyLong_FromLong(rv);
}

static PyObject *
LXC_attach_run_command(PyObject *self, PyObject *arg)
{
    PyObject *args_obj = NULL;
    int i, rv;
    lxc_attach_command_t cmd = {
        NULL,         /* program */
        NULL          /* argv[] */
    };

    if (!PyArg_ParseTuple(arg, "sO", (const char**)&cmd.program, &args_obj))
        return NULL;
    if (args_obj && PyList_Check(args_obj)) {
        cmd.argv = convert_tuple_to_char_pointer_array(args_obj);
    } else {
        PyErr_Format(PyExc_TypeError, "Second part of tuple passed to "
                                      "attach_run_command must be a list.");
        return NULL;
    }

    if (!cmd.argv)
        return NULL;

    rv = lxc_attach_run_command(&cmd);

    for (i = 0; cmd.argv[i]; i++)
        free(cmd.argv[i]);
    free(cmd.argv);

    return PyLong_FromLong(rv);
}

static PyObject *
LXC_attach_run_shell(PyObject *self, PyObject *arg)
{
    int rv;

    rv = lxc_attach_run_shell(NULL);

    return PyLong_FromLong(rv);
}

static PyObject *
LXC_get_global_config_item(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"key", NULL};
    char* key = NULL;
    const char* value = NULL;

    if (! PyArg_ParseTupleAndKeywords(args, kwds, "s|", kwlist,
                                      &key))
        return NULL;

    value = lxc_get_global_config_item(key);

    if (!value) {
        PyErr_SetString(PyExc_KeyError, "Invalid configuration key");
        return NULL;
    }

    return PyUnicode_FromString(value);
}

static PyObject *
LXC_get_version(PyObject *self, PyObject *args)
{
    return PyUnicode_FromString(lxc_get_version());
}

static PyObject *
LXC_list_containers(PyObject *self, PyObject *args, PyObject *kwds)
{
    char **names = NULL;
    PyObject *list = NULL;
    int list_count = 0;

    int list_active = 1;
    int list_defined = 1;

    PyObject *py_list_active = NULL;
    PyObject *py_list_defined = NULL;

    char* config_path = NULL;

    int i = 0;
    PyObject *vargs = NULL;
    static char *kwlist[] = {"active", "defined", "config_path", NULL};

    if (! PyArg_ParseTupleAndKeywords(args, kwds, "|OOs", kwlist,
                                      &py_list_active,
                                      &py_list_defined,
                                      &config_path, &vargs))
        return NULL;

    /* We default to listing everything */
    if (py_list_active && py_list_active != Py_True) {
        list_active = 0;
    }

    if (py_list_defined && py_list_defined != Py_True) {
        list_defined = 0;
    }

    /* Call the right API function based on filters */
    if (list_active == 1 && list_defined == 1)
        list_count = list_all_containers(config_path, &names, NULL);
    else if (list_active == 1)
        list_count = list_active_containers(config_path, &names, NULL);
    else if (list_defined == 1)
        list_count = list_defined_containers(config_path, &names, NULL);

    /* Handle failure */
    if (list_count < 0) {
        PyErr_SetString(PyExc_ValueError, "failure to list containers");
        return NULL;
    }

    /* Generate the tuple */
    list = PyTuple_New(list_count);
    for (i = 0; i < list_count; i++) {
        PyTuple_SET_ITEM(list, i, PyUnicode_FromString(names[i]));
        free(names[i]);
    }
    free(names);

    return list;
}

/* Base type and functions for Container */
typedef struct {
    PyObject_HEAD
    struct lxc_container *container;
} Container;

static void
Container_dealloc(Container* self)
{
    lxc_container_put(self->container);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static int
Container_init(Container *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"name", "config_path", NULL};
    char *name = NULL;
    PyObject *fs_config_path = NULL;
    char *config_path = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|O&", kwlist,
                                      &name,
                                      PyUnicode_FSConverter, &fs_config_path))
        return -1;

    if (fs_config_path != NULL) {
        config_path = PyBytes_AS_STRING(fs_config_path);
        assert(config_path != NULL);
    }

    self->container = lxc_container_new(name, config_path);
    if (!self->container) {
        Py_XDECREF(fs_config_path);

        PyErr_Format(PyExc_RuntimeError, "%s:%s:%d: error during init for container '%s'.",
			__FUNCTION__, __FILE__, __LINE__, name);
        return -1;
    }

    Py_XDECREF(fs_config_path);
    return 0;
}

static PyObject *
Container_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    Container *self;

    self = (Container *)type->tp_alloc(type, 0);

    return (PyObject *)self;
}

/* Container properties */
static PyObject *
Container_config_file_name(Container *self, void *closure)
{
    return PyUnicode_FromString(
                self->container->config_file_name(self->container));
}

static PyObject *
Container_controllable(Container *self, void *closure)
{
    if (self->container->may_control(self->container)) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static PyObject *
Container_defined(Container *self, void *closure)
{
    if (self->container->is_defined(self->container)) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static PyObject *
Container_init_pid(Container *self, void *closure)
{
    return PyLong_FromLong(self->container->init_pid(self->container));
}

static PyObject *
Container_name(Container *self, void *closure)
{
    return PyUnicode_FromString(self->container->name);
}

static PyObject *
Container_running(Container *self, void *closure)
{
    if (self->container->is_running(self->container)) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static PyObject *
Container_state(Container *self, void *closure)
{
    return PyUnicode_FromString(self->container->state(self->container));
}

/* Container Functions */
static PyObject *
Container_attach_interface(Container *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"src_ifname", "dst_ifname", NULL};
    char *src_name = NULL;
    char *dst_name = NULL;
    PyObject *py_src_name = NULL;
    PyObject *py_dst_name = NULL;

    if (! PyArg_ParseTupleAndKeywords(args, kwds, "O&|O&", kwlist,
                                      PyUnicode_FSConverter, &py_src_name,
                                      PyUnicode_FSConverter, &py_dst_name))
        return NULL;

    if (py_src_name != NULL) {
        src_name = PyBytes_AS_STRING(py_src_name);
        assert(src_name != NULL);
    }

    if (py_dst_name != NULL) {
        dst_name = PyBytes_AS_STRING(py_dst_name);
        assert(dst_name != NULL);
    }

    if (self->container->attach_interface(self->container, src_name, dst_name)) {
        Py_XDECREF(py_src_name);
        Py_XDECREF(py_dst_name);
        Py_RETURN_TRUE;
    }

    Py_XDECREF(py_src_name);
    Py_XDECREF(py_dst_name);
    Py_RETURN_FALSE;
}

static PyObject *
Container_detach_interface(Container *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"ifname", NULL};
    char *ifname = NULL;
    PyObject *py_ifname = NULL;

    if (! PyArg_ParseTupleAndKeywords(args, kwds, "O&", kwlist,
                                      PyUnicode_FSConverter, &py_ifname))
        return NULL;

    if (py_ifname != NULL) {
        ifname = PyBytes_AS_STRING(py_ifname);
        assert(ifname != NULL);
    }

    if (self->container->detach_interface(self->container, ifname, NULL)) {
        Py_XDECREF(py_ifname);
        Py_RETURN_TRUE;
    }

    Py_XDECREF(py_ifname);
    Py_RETURN_FALSE;
}

static PyObject *
Container_add_device_node(Container *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"src_path", "dest_path", NULL};
    char *src_path = NULL;
    char *dst_path = NULL;
    PyObject *py_src_path = NULL;
    PyObject *py_dst_path = NULL;

    if (! PyArg_ParseTupleAndKeywords(args, kwds, "O&|O&", kwlist,
                                      PyUnicode_FSConverter, &py_src_path,
                                      PyUnicode_FSConverter, &py_dst_path))
        return NULL;

    if (py_src_path != NULL) {
        src_path = PyBytes_AS_STRING(py_src_path);
        assert(src_path != NULL);
    }

    if (py_dst_path != NULL) {
        dst_path = PyBytes_AS_STRING(py_dst_path);
        assert(dst_path != NULL);
    }

    if (self->container->add_device_node(self->container, src_path,
                                         dst_path)) {
        Py_XDECREF(py_src_path);
        Py_XDECREF(py_dst_path);
        Py_RETURN_TRUE;
    }

    Py_XDECREF(py_src_path);
    Py_XDECREF(py_dst_path);
    Py_RETURN_FALSE;
}

static PyObject *
Container_attach_and_possibly_wait(Container *self, PyObject *args,
                                   PyObject *kwds, int wait)
{
    struct lxc_attach_python_payload payload = { NULL, NULL };
    lxc_attach_options_t *options = NULL;
    long ret;
    pid_t pid;

    if (!PyArg_ParseTuple(args, "O|O", &payload.fn, &payload.arg))
        return NULL;
    if (!PyCallable_Check(payload.fn)) {
        PyErr_Format(PyExc_TypeError, "attach: object not callable");
        return NULL;
    }

    options = lxc_attach_parse_options(kwds);
    if (!options)
        return NULL;

    ret = self->container->attach(self->container, lxc_attach_python_exec,
                                  &payload, options, &pid);
    if (ret < 0)
        goto out;

    if (wait) {
        Py_BEGIN_ALLOW_THREADS
        ret = lxc_wait_for_pid_status(pid);
        Py_END_ALLOW_THREADS
        /* handle case where attach fails */
        if (WIFEXITED(ret) && WEXITSTATUS(ret) == 255)
            ret = -1;
    } else {
        ret = (long)pid;
    }

out:
    lxc_attach_free_options(options);
    return PyLong_FromLong(ret);
}

static PyObject *
Container_attach(Container *self, PyObject *args, PyObject *kwds)
{
    return Container_attach_and_possibly_wait(self, args, kwds, 0);
}

static PyObject *
Container_attach_wait(Container *self, PyObject *args, PyObject *kwds)
{
    return Container_attach_and_possibly_wait(self, args, kwds, 1);
}

static PyObject *
Container_clear_config(Container *self, PyObject *args, PyObject *kwds)
{
    self->container->clear_config(self->container);

    Py_RETURN_NONE;
}

static PyObject *
Container_clear_config_item(Container *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"key", NULL};
    char *key = NULL;

    if (! PyArg_ParseTupleAndKeywords(args, kwds, "s", kwlist,
                                      &key))
        return NULL;

    if (self->container->clear_config_item(self->container, key)) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static PyObject *
Container_clone(Container *self, PyObject *args, PyObject *kwds)
{
    char *newname = NULL;
    char *config_path = NULL;
    int flags = 0;
    char *bdevtype = NULL;
    char *bdevdata = NULL;
    unsigned long newsize = 0;
    char **hookargs = NULL;

    PyObject *py_hookargs = NULL;
    PyObject *py_config_path = NULL;
    struct lxc_container *new_container = NULL;
    int i = 0;

    static char *kwlist[] = {"newname", "config_path", "flags", "bdevtype",
                             "bdevdata", "newsize", "hookargs", NULL};
    if (! PyArg_ParseTupleAndKeywords(args, kwds, "s|O&isskO", kwlist,
                                      &newname,
                                      PyUnicode_FSConverter, &py_config_path,
                                      &flags, &bdevtype, &bdevdata, &newsize,
                                      &py_hookargs))
        return NULL;

    if (py_hookargs) {
        if (PyTuple_Check(py_hookargs)) {
            hookargs = convert_tuple_to_char_pointer_array(py_hookargs);
            if (!hookargs) {
                return NULL;
            }
        }
        else {
            PyErr_SetString(PyExc_ValueError, "hookargs needs to be a tuple");
            return NULL;
        }
    }

    if (py_config_path != NULL) {
        config_path = PyBytes_AS_STRING(py_config_path);
        assert(config_path != NULL);
    }

    new_container = self->container->clone(self->container, newname,
                                           config_path, flags, bdevtype,
                                           bdevdata, newsize, hookargs);

    Py_XDECREF(py_config_path);

    if (hookargs) {
        for (i = 0; i < PyTuple_GET_SIZE(py_hookargs); i++)
            free(hookargs[i]);
        free(hookargs);
    }

    if (new_container == NULL) {
        Py_RETURN_FALSE;
    }

    lxc_container_put(new_container);

    Py_RETURN_TRUE;
}

static PyObject *
Container_console(Container *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"ttynum", "stdinfd", "stdoutfd", "stderrfd",
                             "escape", NULL};
    int ttynum = -1, stdinfd = 0, stdoutfd = 1, stderrfd = 2, escape = 1;

    if (! PyArg_ParseTupleAndKeywords(args, kwds, "|iiiii", kwlist,
                                      &ttynum, &stdinfd, &stdoutfd, &stderrfd,
                                      &escape))
        return NULL;

    if (self->container->console(self->container, ttynum,
            stdinfd, stdoutfd, stderrfd, escape) == 0) {
        Py_RETURN_TRUE;
    }
    Py_RETURN_FALSE;
}

static PyObject *
Container_console_getfd(Container *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"ttynum", NULL};
    int ttynum = -1, masterfd;

    if (! PyArg_ParseTupleAndKeywords(args, kwds, "|i", kwlist, &ttynum))
        return NULL;

    if (self->container->console_getfd(self->container, &ttynum,
                                       &masterfd) < 0) {
        PyErr_SetString(PyExc_ValueError, "Unable to allocate tty");
        return NULL;
    }
    return PyLong_FromLong(masterfd);
}

static PyObject *
Container_create(Container *self, PyObject *args, PyObject *kwds)
{
    char* template_name = NULL;
    int flags = 0;
    char** create_args = {NULL};
    PyObject *retval = NULL;
    PyObject *vargs = NULL;
    char *bdevtype = NULL;
    int i = 0;
    static char *kwlist[] = {"template", "flags", "bdevtype", "args", NULL};
    if (! PyArg_ParseTupleAndKeywords(args, kwds, "|sisO", kwlist,
                                      &template_name, &flags, &bdevtype, &vargs))
        return NULL;

    if (vargs) {
        if (PyTuple_Check(vargs)) {
            create_args = convert_tuple_to_char_pointer_array(vargs);
            if (!create_args) {
                return NULL;
            }
        }
        else {
            PyErr_SetString(PyExc_ValueError, "args needs to be a tuple");
            return NULL;
        }
    }

    if (self->container->create(self->container, template_name, bdevtype, NULL,
                                flags, create_args))
        retval = Py_True;
    else
        retval = Py_False;

    if (vargs) {
        /* We cannot have gotten here unless vargs was given and create_args
         * was successfully allocated.
         */
        for (i = 0; i < PyTuple_GET_SIZE(vargs); i++)
            free(create_args[i]);
        free(create_args);
    }

    Py_INCREF(retval);
    return retval;
}

static PyObject *
Container_destroy(Container *self, PyObject *args, PyObject *kwds)
{
    if (self->container->destroy(self->container)) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static PyObject *
Container_freeze(Container *self, PyObject *args, PyObject *kwds)
{
    if (self->container->freeze(self->container)) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static PyObject *
Container_get_cgroup_item(Container *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"key", NULL};
    char* key = NULL;
    int len = 0;
    char* value;
    PyObject *ret = NULL;

    if (! PyArg_ParseTupleAndKeywords(args, kwds, "s", kwlist,
                                      &key))
        return NULL;

    len = self->container->get_cgroup_item(self->container, key, NULL, 0);

    if (len < 0) {
        PyErr_SetString(PyExc_KeyError, "Invalid cgroup entry");
        return NULL;
    }

    value = (char*) malloc(sizeof(char)*len + 1);
    if (value == NULL)
        return PyErr_NoMemory();

    if (self->container->get_cgroup_item(self->container,
                                            key, value, len + 1) != len) {
        PyErr_SetString(PyExc_ValueError, "Unable to read config value");
        free(value);
        return NULL;
    }

    ret = PyUnicode_FromString(value);
    free(value);
    return ret;
}

static PyObject *
Container_get_config_item(Container *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"key", NULL};
    char* key = NULL;
    int len = 0;
    char* value;
    PyObject *ret = NULL;

    if (! PyArg_ParseTupleAndKeywords(args, kwds, "s|", kwlist,
                                      &key))
        return NULL;

    len = self->container->get_config_item(self->container, key, NULL, 0);

    if (len < 0) {
        PyErr_SetString(PyExc_KeyError, "Invalid configuration key");
        return NULL;
    }

    if (len == 0) {
        return PyUnicode_FromString("");
    }

    value = (char*) malloc(sizeof(char)*len + 1);
    if (value == NULL)
        return PyErr_NoMemory();

    if (self->container->get_config_item(self->container,
                                            key, value, len + 1) != len) {
        PyErr_SetString(PyExc_ValueError, "Unable to read config value");
        free(value);
        return NULL;
    }

    ret = PyUnicode_FromString(value);
    free(value);
    return ret;
}

static PyObject *
Container_get_config_path(Container *self, PyObject *args, PyObject *kwds)
{
    return PyUnicode_FromString(
                self->container->get_config_path(self->container));
}

static PyObject *
Container_get_keys(Container *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"key", NULL};
    char* key = NULL;
    int len = 0;
    char* value;
    PyObject *ret = NULL;

    if (! PyArg_ParseTupleAndKeywords(args, kwds, "|s", kwlist,
                                      &key))
        return NULL;

    len = self->container->get_keys(self->container, key, NULL, 0);

    if (len < 0) {
        PyErr_SetString(PyExc_KeyError, "Invalid configuration key");
        return NULL;
    }

    value = (char*) malloc(sizeof(char)*len + 1);
    if (value == NULL)
        return PyErr_NoMemory();

    if (self->container->get_keys(self->container,
                                    key, value, len + 1) != len) {
        PyErr_SetString(PyExc_ValueError, "Unable to read config keys");
        free(value);
        return NULL;
    }

    ret = PyUnicode_FromString(value);
    free(value);
    return ret;
}

static PyObject *
Container_get_interfaces(Container *self)
{
    int i = 0;
    char** interfaces = NULL;

    PyObject* ret;

    /* Get the interfaces */
    interfaces = self->container->get_interfaces(self->container);
    if (!interfaces)
        return PyTuple_New(0);

    /* Count the entries */
    while (interfaces[i])
        i++;

    /* Create the new tuple */
    ret = PyTuple_New(i);
    if (!ret)
        return NULL;

    /* Add the entries to the tuple and free the memory */
    i = 0;
    while (interfaces[i]) {
        PyObject *unicode = PyUnicode_FromString(interfaces[i]);
        if (!unicode) {
            Py_DECREF(ret);
            ret = NULL;
            break;
        }
        PyTuple_SET_ITEM(ret, i, unicode);
        i++;
    }

    /* Free the list of IPs */
    i = 0;
    while (interfaces[i]) {
        free(interfaces[i]);
        i++;
    }
    free(interfaces);

    return ret;
}

static PyObject *
Container_get_ips(Container *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"interface", "family", "scope", NULL};
    char* interface = NULL;
    char* family = NULL;
    int scope = 0;

    int i = 0;
    char** ips = NULL;

    PyObject* ret;

    if (! PyArg_ParseTupleAndKeywords(args, kwds, "|ssi", kwlist,
                                      &interface, &family, &scope))
        return NULL;

    /* Get the IPs */
    ips = self->container->get_ips(self->container, interface, family, scope);
    if (!ips)
        return PyTuple_New(0);

    /* Count the entries */
    while (ips[i])
        i++;

    /* Create the new tuple */
    ret = PyTuple_New(i);
    if (!ret)
        return NULL;

    /* Add the entries to the tuple and free the memory */
    i = 0;
    while (ips[i]) {
        PyObject *unicode = PyUnicode_FromString(ips[i]);
        if (!unicode) {
            Py_DECREF(ret);
            ret = NULL;
            break;
        }
        PyTuple_SET_ITEM(ret, i, unicode);
        i++;
    }

    /* Free the list of IPs */
    i = 0;
    while (ips[i]) {
        free(ips[i]);
        i++;
    }
    free(ips);

    return ret;
}

static PyObject *
Container_get_running_config_item(Container *self, PyObject *args,
                                  PyObject *kwds)
{
    static char *kwlist[] = {"key", NULL};
    char* key = NULL;
    char* value = NULL;
    PyObject *ret = NULL;

    if (! PyArg_ParseTupleAndKeywords(args, kwds, "s|", kwlist,
                                      &key))
        return NULL;

    value = self->container->get_running_config_item(self->container, key);

    if (!value)
        Py_RETURN_NONE;

    ret = PyUnicode_FromString(value);
    free(value);
    return ret;
}


static PyObject *
Container_load_config(Container *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"path", NULL};
    PyObject *fs_path = NULL;
    char* path = NULL;

    if (! PyArg_ParseTupleAndKeywords(args, kwds, "|O&", kwlist,
                                      PyUnicode_FSConverter, &fs_path))
        return NULL;

    if (fs_path != NULL) {
        path = PyBytes_AS_STRING(fs_path);
        assert(path != NULL);
    }

    if (self->container->load_config(self->container, path)) {
        Py_XDECREF(fs_path);
        Py_RETURN_TRUE;
    }

    Py_XDECREF(fs_path);
    Py_RETURN_FALSE;
}

static PyObject *
Container_reboot(Container *self, PyObject *args, PyObject *kwds)
{
    if (self->container->reboot(self->container)) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static PyObject *
Container_rename(Container *self, PyObject *args, PyObject *kwds)
{
    char *new_name = NULL;
    static char *kwlist[] = {"new_name", NULL};

    if (! PyArg_ParseTupleAndKeywords(args, kwds, "s|", kwlist,
                                      &new_name))
        return NULL;

    if (self->container->rename(self->container, new_name)) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static PyObject *
Container_remove_device_node(Container *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"src_path", "dest_path", NULL};
    char *src_path = NULL;
    char *dst_path = NULL;
    PyObject *py_src_path = NULL;
    PyObject *py_dst_path = NULL;

    if (! PyArg_ParseTupleAndKeywords(args, kwds, "O&|O&", kwlist,
                                      PyUnicode_FSConverter, &py_src_path,
                                      PyUnicode_FSConverter, &py_dst_path))
        return NULL;

    if (py_src_path != NULL) {
        src_path = PyBytes_AS_STRING(py_src_path);
        assert(src_path != NULL);
    }

    if (py_dst_path != NULL) {
        dst_path = PyBytes_AS_STRING(py_dst_path);
        assert(dst_path != NULL);
    }

    if (self->container->remove_device_node(self->container, src_path,
                                            dst_path)) {
        Py_XDECREF(py_src_path);
        Py_XDECREF(py_dst_path);
        Py_RETURN_TRUE;
    }

    Py_XDECREF(py_src_path);
    Py_XDECREF(py_dst_path);
    Py_RETURN_FALSE;
}

static PyObject *
Container_save_config(Container *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"path", NULL};
    PyObject *fs_path = NULL;
    char* path = NULL;

    if (! PyArg_ParseTupleAndKeywords(args, kwds, "|O&", kwlist,
                                      PyUnicode_FSConverter, &fs_path))
        return NULL;

    if (fs_path != NULL) {
        path = PyBytes_AS_STRING(fs_path);
        assert(path != NULL);
    }

    if (self->container->save_config(self->container, path)) {
        Py_XDECREF(fs_path);
        Py_RETURN_TRUE;
    }

    Py_XDECREF(fs_path);
    Py_RETURN_FALSE;
}

static PyObject *
Container_set_cgroup_item(Container *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"key", "value", NULL};
    char *key = NULL;
    char *value = NULL;

    if (! PyArg_ParseTupleAndKeywords(args, kwds, "ss", kwlist,
                                      &key, &value))
        return NULL;

    if (self->container->set_cgroup_item(self->container, key, value)) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static PyObject *
Container_set_config_item(Container *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"key", "value", NULL};
    char *key = NULL;
    char *value = NULL;

    if (! PyArg_ParseTupleAndKeywords(args, kwds, "ss", kwlist,
                                      &key, &value))
        return NULL;

    if (self->container->set_config_item(self->container, key, value)) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static PyObject *
Container_set_config_path(Container *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"path", NULL};
    char *path = NULL;

    if (! PyArg_ParseTupleAndKeywords(args, kwds, "s", kwlist,
                                      &path))
        return NULL;

    if (self->container->set_config_path(self->container, path)) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static PyObject *
Container_shutdown(Container *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"timeout", NULL};
    int timeout = -1;

    if (! PyArg_ParseTupleAndKeywords(args, kwds, "|i", kwlist,
                                      &timeout))
        return NULL;

    if (self->container->shutdown(self->container, timeout)) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static PyObject *
Container_snapshot(Container *self, PyObject *args, PyObject *kwds)
{
    char *comment_path = NULL;
    static char *kwlist[] = {"comment_path", NULL};
    int retval = 0;
    int ret = 0;
    char newname[20];
    PyObject *py_comment_path = NULL;

    if (! PyArg_ParseTupleAndKeywords(args, kwds, "|O&", kwlist,
                                      PyUnicode_FSConverter, &py_comment_path))
        return NULL;

    if (py_comment_path != NULL) {
        comment_path = PyBytes_AS_STRING(py_comment_path);
        assert(comment_path != NULL);
    }

    retval = self->container->snapshot(self->container, comment_path);

    Py_XDECREF(py_comment_path);

    if (retval < 0) {
        Py_RETURN_FALSE;
    }

    ret = snprintf(newname, 20, "snap%d", retval);
    if (ret < 0 || ret >= 20)
        return NULL;


    return PyUnicode_FromString(newname);
}

static PyObject *
Container_snapshot_destroy(Container *self, PyObject *args, PyObject *kwds)
{
    char *name = NULL;
    static char *kwlist[] = {"name", NULL};

    if (! PyArg_ParseTupleAndKeywords(args, kwds, "s|", kwlist,
                                      &name))
        return NULL;

    if (self->container->snapshot_destroy(self->container, name)) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static PyObject *
Container_snapshot_list(Container *self, PyObject *args, PyObject *kwds)
{
    struct lxc_snapshot *snap;
    int snap_count = 0;
    PyObject *list = NULL;
    int i = 0;

    snap_count = self->container->snapshot_list(self->container, &snap);

    if (snap_count < 0) {
        PyErr_SetString(PyExc_KeyError, "Unable to list snapshots");
        return NULL;
    }

    list = PyTuple_New(snap_count);
    for (i = 0; i < snap_count; i++) {
        PyObject *list_entry = NULL;

        list_entry = PyTuple_New(4);
        PyTuple_SET_ITEM(list_entry, 0,
                         PyUnicode_FromString(snap[i].name));
        PyTuple_SET_ITEM(list_entry, 1,
                         PyUnicode_FromString(snap[i].comment_pathname));
        PyTuple_SET_ITEM(list_entry, 2,
                         PyUnicode_FromString(snap[i].timestamp));
        PyTuple_SET_ITEM(list_entry, 3,
                         PyUnicode_FromString(snap[i].lxcpath));

        snap[i].free(&snap[i]);

        PyTuple_SET_ITEM(list, i, list_entry);
    }

    return list;
}


static PyObject *
Container_snapshot_restore(Container *self, PyObject *args, PyObject *kwds)
{
    char *name = NULL;
    char *newname = NULL;
    static char *kwlist[] = {"name", "newname", NULL};

    if (! PyArg_ParseTupleAndKeywords(args, kwds, "s|s", kwlist,
                                      &name, &newname))
        return NULL;

    if (self->container->snapshot_restore(self->container, name, newname)) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static PyObject *
Container_start(Container *self, PyObject *args, PyObject *kwds)
{
    PyObject *useinit = NULL;
    PyObject *daemonize = NULL;
    PyObject *close_fds = NULL;

    PyObject *vargs = NULL;
    char** init_args = {NULL};

    PyObject *retval = NULL;
    int init_useinit = 0, i = 0;
    static char *kwlist[] = {"useinit", "daemonize", "close_fds",
                             "cmd", NULL};

    if (! PyArg_ParseTupleAndKeywords(args, kwds, "|OOOO", kwlist,
                                      &useinit, &daemonize, &close_fds,
                                      &vargs))
        return NULL;

    if (useinit && useinit == Py_True) {
        init_useinit = 1;
    }

    if (vargs && PyTuple_Check(vargs)) {
        init_args = convert_tuple_to_char_pointer_array(vargs);
        if (!init_args) {
            return NULL;
        }
    }

    if (close_fds && close_fds == Py_True) {
        self->container->want_close_all_fds(self->container, true);
    }
    else {
        self->container->want_close_all_fds(self->container, false);
    }

    if (!daemonize || daemonize == Py_True) {
        self->container->want_daemonize(self->container, true);
    }
    else {
        self->container->want_daemonize(self->container, false);
    }

    if (self->container->start(self->container, init_useinit, init_args))
        retval = Py_True;
    else
        retval = Py_False;

    if (vargs) {
        /* We cannot have gotten here unless vargs was given and create_args
         * was successfully allocated.
         */
        for (i = 0; i < PyTuple_GET_SIZE(vargs); i++)
            free(init_args[i]);
        free(init_args);
    }

    Py_INCREF(retval);
    return retval;
}

static PyObject *
Container_stop(Container *self, PyObject *args, PyObject *kwds)
{
    if (self->container->stop(self->container)) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static PyObject *
Container_unfreeze(Container *self, PyObject *args, PyObject *kwds)
{
    if (self->container->unfreeze(self->container)) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static PyObject *
Container_wait(Container *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"state", "timeout", NULL};
    char *state = NULL;
    int timeout = -1;

    if (! PyArg_ParseTupleAndKeywords(args, kwds, "s|i", kwlist,
                                      &state, &timeout))
        return NULL;

    if (self->container->wait(self->container, state, timeout)) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

/* Function/Properties list */
static PyGetSetDef Container_getseters[] = {
    {"config_file_name",
     (getter)Container_config_file_name, NULL,
     "Path to the container configuration",
     NULL},
    {"controllable",
     (getter)Container_controllable, NULL,
     "Boolean indicating whether the container may be controlled",
     NULL},
    {"defined",
     (getter)Container_defined, NULL,
     "Boolean indicating whether the container configuration exists",
     NULL},
    {"init_pid",
     (getter)Container_init_pid, NULL,
     "PID of the container's init process in the host's PID namespace",
     NULL},
    {"name",
     (getter)Container_name, NULL,
     "Container name",
     NULL},
    {"running",
     (getter)Container_running, NULL,
     "Boolean indicating whether the container is running or not",
     NULL},
    {"state",
     (getter)Container_state, NULL,
     "Container state",
     NULL},
    {NULL, NULL, NULL, NULL, NULL}
};

static PyMethodDef Container_methods[] = {
    {"attach_interface", (PyCFunction)Container_attach_interface,
     METH_VARARGS|METH_KEYWORDS,
     "attach_interface(src_ifname, dest_ifname) -> boolean\n"
     "\n"
     "Pass a new network device to the container."
    },
    {"detach_interface", (PyCFunction)Container_detach_interface,
     METH_VARARGS|METH_KEYWORDS,
     "detach_interface(ifname) -> boolean\n"
     "\n"
     "detach a network device from the container."
    },
    {"add_device_node", (PyCFunction)Container_add_device_node,
     METH_VARARGS|METH_KEYWORDS,
     "add_device_node(src_path, dest_path) -> boolean\n"
     "\n"
     "Pass a new device to the container."
    },
    {"attach", (PyCFunction)Container_attach,
     METH_VARARGS|METH_KEYWORDS,
     "attach(run, payload) -> int\n"
     "\n"
     "Attach to the container. Returns the pid of the attached process."
    },
    {"attach_wait", (PyCFunction)Container_attach_wait,
     METH_VARARGS|METH_KEYWORDS,
     "attach(run, payload) -> int\n"
     "\n"
     "Attach to the container. Returns the exit code of the process."
    },
    {"clear_config", (PyCFunction)Container_clear_config,
     METH_NOARGS,
     "clear_config()\n"
     "\n"
     "Clear any container configuration."
    },
    {"clear_config_item", (PyCFunction)Container_clear_config_item,
     METH_VARARGS|METH_KEYWORDS,
     "clear_config_item(key) -> boolean\n"
     "\n"
     "Clear the current value of a config key."
    },
    {"console", (PyCFunction)Container_console,
     METH_VARARGS|METH_KEYWORDS,
     "console(ttynum = -1, stdinfd = 0, stdoutfd = 1, stderrfd = 2, "
     "escape = 0) -> boolean\n"
     "\n"
     "Attach to container's console."
    },
    {"console_getfd", (PyCFunction)Container_console_getfd,
     METH_VARARGS|METH_KEYWORDS,
     "console(ttynum = -1) -> boolean\n"
     "\n"
     "Attach to container's console."
    },
    {"clone", (PyCFunction)Container_clone,
     METH_VARARGS|METH_KEYWORDS,
     "clone(newname, config_path, flags, bdevtype, bdevdata, newsize, "
     "hookargs) -> boolean\n"
     "\n"
     "Create a new container based on the current one."
    },
    {"create", (PyCFunction)Container_create,
     METH_VARARGS|METH_KEYWORDS,
     "create(template, args = (,)) -> boolean\n"
     "\n"
     "Create a new rootfs for the container, using the given template "
     "and passing some optional arguments to it."
    },
    {"destroy", (PyCFunction)Container_destroy,
     METH_NOARGS,
     "destroy() -> boolean\n"
     "\n"
     "Destroys the container."
    },
    {"freeze", (PyCFunction)Container_freeze,
     METH_NOARGS,
     "freeze() -> boolean\n"
     "\n"
     "Freezes the container and returns its return code."
    },
    {"get_cgroup_item", (PyCFunction)Container_get_cgroup_item,
     METH_VARARGS|METH_KEYWORDS,
     "get_cgroup_item(key) -> string\n"
     "\n"
     "Get the current value of a cgroup entry."
    },
    {"get_config_item", (PyCFunction)Container_get_config_item,
     METH_VARARGS|METH_KEYWORDS,
     "get_config_item(key) -> string\n"
     "\n"
     "Get the current value of a config key."
    },
    {"get_config_path", (PyCFunction)Container_get_config_path,
     METH_NOARGS,
     "get_config_path() -> string\n"
     "\n"
     "Return the LXC config path (where the containers are stored)."
    },
    {"get_keys", (PyCFunction)Container_get_keys,
     METH_VARARGS|METH_KEYWORDS,
     "get_keys(key) -> string\n"
     "\n"
     "Get a list of valid sub-keys for a key."
    },
    {"get_interfaces", (PyCFunction)Container_get_interfaces,
     METH_NOARGS,
     "get_interface() -> tuple\n"
     "\n"
     "Get a tuple of interfaces for the container."
    },
    {"get_ips", (PyCFunction)Container_get_ips,
     METH_VARARGS|METH_KEYWORDS,
     "get_ips(interface, family, scope) -> tuple\n"
     "\n"
     "Get a tuple of IPs for the container."
    },
    {"get_running_config_item", (PyCFunction)Container_get_running_config_item,
     METH_VARARGS|METH_KEYWORDS,
     "get_running_config_item(key) -> string\n"
     "\n"
     "Get the runtime value of a config key."
    },
    {"load_config", (PyCFunction)Container_load_config,
     METH_VARARGS|METH_KEYWORDS,
     "load_config(path = DEFAULT) -> boolean\n"
     "\n"
     "Read the container configuration from its default "
     "location or from an alternative location if provided."
    },
    {"reboot", (PyCFunction)Container_reboot,
     METH_NOARGS,
     "reboot() -> boolean\n"
     "\n"
     "Ask the container to reboot."
    },
    {"rename", (PyCFunction)Container_rename,
     METH_VARARGS|METH_KEYWORDS,
     "rename(new_name) -> boolean\n"
     "\n"
     "Rename the container."
    },
    {"remove_device_node", (PyCFunction)Container_remove_device_node,
     METH_VARARGS|METH_KEYWORDS,
     "remove_device_node(src_path, dest_path) -> boolean\n"
     "\n"
     "Remove a device from the container."
    },
    {"save_config", (PyCFunction)Container_save_config,
     METH_VARARGS|METH_KEYWORDS,
     "save_config(path = DEFAULT) -> boolean\n"
     "\n"
     "Save the container configuration to its default "
     "location or to an alternative location if provided."
    },
    {"set_cgroup_item", (PyCFunction)Container_set_cgroup_item,
     METH_VARARGS|METH_KEYWORDS,
     "set_cgroup_item(key, value) -> boolean\n"
     "\n"
     "Set a cgroup entry to the provided value."
    },
    {"set_config_item", (PyCFunction)Container_set_config_item,
     METH_VARARGS|METH_KEYWORDS,
     "set_config_item(key, value) -> boolean\n"
     "\n"
     "Set a config key to the provided value."
    },
    {"set_config_path", (PyCFunction)Container_set_config_path,
     METH_VARARGS|METH_KEYWORDS,
     "set_config_path(path) -> boolean\n"
     "\n"
     "Set the LXC config path (where the containers are stored)."
    },
    {"shutdown", (PyCFunction)Container_shutdown,
     METH_VARARGS|METH_KEYWORDS,
     "shutdown(timeout = -1) -> boolean\n"
     "\n"
     "Sends SIGPWR to the container and wait for it to shutdown."
     "-1 means wait forever, 0 means skip waiting."
    },
    {"snapshot", (PyCFunction)Container_snapshot,
     METH_VARARGS|METH_KEYWORDS,
     "snapshot(comment_path = None) -> string\n"
     "\n"
     "Snapshot the container and return the snapshot name "
     "(or False on error)."
    },
    {"snapshot_destroy", (PyCFunction)Container_snapshot_destroy,
     METH_VARARGS|METH_KEYWORDS,
     "snapshot_destroy(name) -> boolean\n"
     "\n"
     "Destroy a snapshot."
    },
    {"snapshot_list", (PyCFunction)Container_snapshot_list,
     METH_NOARGS,
     "snapshot_list() -> tuple of snapshot tuples\n"
     "\n"
     "List all snapshots for a container."
    },
    {"snapshot_restore", (PyCFunction)Container_snapshot_restore,
     METH_VARARGS|METH_KEYWORDS,
     "snapshot_restore(name, newname = None) -> boolean\n"
     "\n"
     "Restore a container snapshot. If newname is provided a new "
     "container will be created from the snapshot, otherwise an in-place "
     "restore will be attempted."
    },
    {"start", (PyCFunction)Container_start,
     METH_VARARGS|METH_KEYWORDS,
     "start(useinit = False, daemonize=True, close_fds=False, "
     "cmd = (,)) -> boolean\n"
     "\n"
     "Start the container, return True on success.\n"
     "When set useinit will make LXC use lxc-init to start the container.\n"
     "The container can be started in the foreground with daemonize=False.\n"
     "All fds may also be closed by passing close_fds=True."
    },
    {"stop", (PyCFunction)Container_stop,
     METH_NOARGS,
     "stop() -> boolean\n"
     "\n"
     "Stop the container and returns its return code."
    },
    {"unfreeze", (PyCFunction)Container_unfreeze,
     METH_NOARGS,
     "unfreeze() -> boolean\n"
     "\n"
     "Unfreezes the container and returns its return code."
    },
    {"wait", (PyCFunction)Container_wait,
     METH_VARARGS|METH_KEYWORDS,
     "wait(state, timeout = -1) -> boolean\n"
     "\n"
     "Wait for the container to reach a given state or timeout."
    },
    {NULL, NULL, 0, NULL}
};

static PyTypeObject _lxc_ContainerType = {
PyVarObject_HEAD_INIT(NULL, 0)
    "lxc.Container",                /* tp_name */
    sizeof(Container),              /* tp_basicsize */
    0,                              /* tp_itemsize */
    (destructor)Container_dealloc,  /* tp_dealloc */
    0,                              /* tp_print */
    0,                              /* tp_getattr */
    0,                              /* tp_setattr */
    0,                              /* tp_reserved */
    0,                              /* tp_repr */
    0,                              /* tp_as_number */
    0,                              /* tp_as_sequence */
    0,                              /* tp_as_mapping */
    0,                              /* tp_hash  */
    0,                              /* tp_call */
    0,                              /* tp_str */
    0,                              /* tp_getattro */
    0,                              /* tp_setattro */
    0,                              /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT |
        Py_TPFLAGS_BASETYPE,        /* tp_flags */
    "Container objects",            /* tp_doc */
    0,                              /* tp_traverse */
    0,                              /* tp_clear */
    0,                              /* tp_richcompare */
    0,                              /* tp_weaklistoffset */
    0,                              /* tp_iter */
    0,                              /* tp_iternext */
    Container_methods,              /* tp_methods */
    0,                              /* tp_members */
    Container_getseters,            /* tp_getset */
    0,                              /* tp_base */
    0,                              /* tp_dict */
    0,                              /* tp_descr_get */
    0,                              /* tp_descr_set */
    0,                              /* tp_dictoffset */
    (initproc)Container_init,       /* tp_init */
    0,                              /* tp_alloc */
    Container_new,                  /* tp_new */
};

static PyMethodDef LXC_methods[] = {
    {"arch_to_personality", (PyCFunction)LXC_arch_to_personality, METH_O,
     "Returns the process personality of the corresponding architecture"},
    {"attach_run_command", (PyCFunction)LXC_attach_run_command, METH_O,
     "Runs a command when attaching, to use as the run parameter for attach "
     "or attach_wait"},
    {"attach_run_shell", (PyCFunction)LXC_attach_run_shell, METH_O,
     "Starts up a shell when attaching, to use as the run parameter for "
     "attach or attach_wait"},
    {"get_global_config_item", (PyCFunction)LXC_get_global_config_item,
     METH_VARARGS|METH_KEYWORDS,
     "Returns the current LXC config path"},
    {"get_version", (PyCFunction)LXC_get_version, METH_NOARGS,
     "Returns the current LXC library version"},
    {"list_containers", (PyCFunction)LXC_list_containers,
     METH_VARARGS|METH_KEYWORDS,
     "Returns a list of container names or objects"},
    {NULL, NULL, 0, NULL}
};

static PyModuleDef _lxcmodule = {
    PyModuleDef_HEAD_INIT,
    "_lxc",
    "Binding for liblxc in python",
    -1,
    LXC_methods
};

PyMODINIT_FUNC
PyInit__lxc(void)
{
    PyObject* m;
    PyObject* d;

    if (PyType_Ready(&_lxc_ContainerType) < 0)
        return NULL;

    m = PyModule_Create(&_lxcmodule);
    if (m == NULL)
        return NULL;

    Py_INCREF(&_lxc_ContainerType);
    PyModule_AddObject(m, "Container", (PyObject *)&_lxc_ContainerType);

    /* add constants */
    d = PyModule_GetDict(m);

    #define PYLXC_EXPORT_CONST(c) \
        PyDict_SetItemString(d, #c, PyLong_FromLong(c))

    /* namespace flags (no other python lib exports this) */
    PYLXC_EXPORT_CONST(CLONE_NEWUTS);
    PYLXC_EXPORT_CONST(CLONE_NEWIPC);
    PYLXC_EXPORT_CONST(CLONE_NEWUSER);
    PYLXC_EXPORT_CONST(CLONE_NEWPID);
    PYLXC_EXPORT_CONST(CLONE_NEWNET);
    PYLXC_EXPORT_CONST(CLONE_NEWNS);

    /* attach: environment variable handling */
    PYLXC_EXPORT_CONST(LXC_ATTACH_CLEAR_ENV);
    PYLXC_EXPORT_CONST(LXC_ATTACH_KEEP_ENV);

    /* attach: attach options */
    PYLXC_EXPORT_CONST(LXC_ATTACH_DEFAULT);
    PYLXC_EXPORT_CONST(LXC_ATTACH_DROP_CAPABILITIES);
    PYLXC_EXPORT_CONST(LXC_ATTACH_LSM_EXEC);
    PYLXC_EXPORT_CONST(LXC_ATTACH_LSM_NOW);
    PYLXC_EXPORT_CONST(LXC_ATTACH_MOVE_TO_CGROUP);
    PYLXC_EXPORT_CONST(LXC_ATTACH_REMOUNT_PROC_SYS);
    PYLXC_EXPORT_CONST(LXC_ATTACH_SET_PERSONALITY);

    /* clone: clone flags */
    PYLXC_EXPORT_CONST(LXC_CLONE_KEEPBDEVTYPE);
    PYLXC_EXPORT_CONST(LXC_CLONE_KEEPMACADDR);
    PYLXC_EXPORT_CONST(LXC_CLONE_KEEPNAME);
    PYLXC_EXPORT_CONST(LXC_CLONE_MAYBE_SNAPSHOT);
    PYLXC_EXPORT_CONST(LXC_CLONE_SNAPSHOT);

    /* create: create flags */
    PYLXC_EXPORT_CONST(LXC_CREATE_QUIET);

    #undef PYLXC_EXPORT_CONST

    return m;
}

/*
 * kate: space-indent on; indent-width 4; mixedindent off; indent-mode cstyle;
 */
