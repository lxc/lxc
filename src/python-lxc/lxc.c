/*
 * python-lxc: Python bindings for LXC
 *
 * (C) Copyright Canonical Ltd. 2012
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <Python.h>
#include "structmember.h"
#include <lxc/lxccontainer.h>
#include <stdio.h>
#include <sys/wait.h>

typedef struct {
    PyObject_HEAD
    struct lxc_container *container;
} Container;

char**
convert_tuple_to_char_pointer_array(PyObject *argv) {
    int argc = PyTuple_Size(argv);
    int i;

    char **result = (char**) malloc(sizeof(char*)*argc + 1);

    for (i = 0; i < argc; i++) {
        PyObject *pyobj = PyTuple_GetItem(argv, i);

        char *str = NULL;
        PyObject *pystr;
        if (!PyUnicode_Check(pyobj)) {
            PyErr_SetString(PyExc_ValueError, "Expected a string");
            return NULL;
        }

        pystr = PyUnicode_AsUTF8String(pyobj);
        str = PyBytes_AsString(pystr);
        memcpy((char *) &result[i], (char *) &str, sizeof(str));
    }

    result[argc] = NULL;

    return result;
}

static void
Container_dealloc(Container* self)
{
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject *
Container_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    Container *self;

    self = (Container *)type->tp_alloc(type, 0);

    return (PyObject *)self;
}

static int
Container_init(Container *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"name", "config_path", NULL};
    char *name = NULL;
    char *config_path = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|s", kwlist,
                                      &name, &config_path))
        return -1;

    self->container = lxc_container_new(name, config_path);
    if (!self->container) {
        fprintf(stderr, "%d: error creating lxc_container %s\n", __LINE__, name);
        return -1;
    }

    return 0;
}

static PyObject *
LXC_get_default_config_path(PyObject *self, PyObject *args)
{
    return PyUnicode_FromString(lxc_get_default_config_path());
}

static PyObject *
LXC_get_version(PyObject *self, PyObject *args)
{
    return PyUnicode_FromString(lxc_get_version());
}

// Container properties
static PyObject *
Container_config_file_name(Container *self, PyObject *args, PyObject *kwds)
{
    return PyUnicode_FromString(self->container->config_file_name(self->container));
}

static PyObject *
Container_defined(Container *self, PyObject *args, PyObject *kwds)
{
    if (self->container->is_defined(self->container)) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static PyObject *
Container_init_pid(Container *self, PyObject *args, PyObject *kwds)
{
    return Py_BuildValue("i", self->container->init_pid(self->container));
}

static PyObject *
Container_name(Container *self, PyObject *args, PyObject *kwds)
{
    return PyUnicode_FromString(self->container->name);
}

static PyObject *
Container_running(Container *self, PyObject *args, PyObject *kwds)
{
    if (self->container->is_running(self->container)) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static PyObject *
Container_state(Container *self, PyObject *args, PyObject *kwds)
{
    return PyUnicode_FromString(self->container->state(self->container));
}

// Container Functions
static PyObject *
Container_clear_config_item(Container *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"key", NULL};
    char *key = NULL;

    if (! PyArg_ParseTupleAndKeywords(args, kwds, "s|", kwlist,
                                      &key))
        Py_RETURN_FALSE;

    if (self->container->clear_config_item(self->container, key)) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static PyObject *
Container_create(Container *self, PyObject *args, PyObject *kwds)
{
    char* template_name = NULL;
    char** create_args = {NULL};
    PyObject *vargs = NULL;
    static char *kwlist[] = {"template", "args", NULL};

    if (! PyArg_ParseTupleAndKeywords(args, kwds, "s|O", kwlist,
                                      &template_name, &vargs))
        Py_RETURN_FALSE;

    if (vargs && PyTuple_Check(vargs)) {
        create_args = convert_tuple_to_char_pointer_array(vargs);
        if (!create_args) {
            return NULL;
        }
    }

    if (self->container->create(self->container, template_name, create_args)) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
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

    if (! PyArg_ParseTupleAndKeywords(args, kwds, "s|", kwlist,
                                      &key))
        Py_RETURN_FALSE;

    len = self->container->get_cgroup_item(self->container, key, NULL, 0);

    if (len <= 0) {
        Py_RETURN_FALSE;
    }

    char* value = (char*) malloc(sizeof(char)*len + 1);
    if (self->container->get_cgroup_item(self->container, key, value, len + 1) != len) {
        Py_RETURN_FALSE;
    }

    return PyUnicode_FromString(value);
}

static PyObject *
Container_get_config_item(Container *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"key", NULL};
    char* key = NULL;
    int len = 0;

    if (! PyArg_ParseTupleAndKeywords(args, kwds, "s|", kwlist,
                                      &key))
        Py_RETURN_FALSE;

    len = self->container->get_config_item(self->container, key, NULL, 0);

    if (len <= 0) {
        Py_RETURN_FALSE;
    }

    char* value = (char*) malloc(sizeof(char)*len + 1);
    if (self->container->get_config_item(self->container, key, value, len + 1) != len) {
        Py_RETURN_FALSE;
    }

    return PyUnicode_FromString(value);
}

static PyObject *
Container_get_config_path(Container *self, PyObject *args, PyObject *kwds)
{
    return PyUnicode_FromString(self->container->get_config_path(self->container));
}

static PyObject *
Container_get_keys(Container *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"key", NULL};
    char* key = NULL;
    int len = 0;

    if (! PyArg_ParseTupleAndKeywords(args, kwds, "|s", kwlist,
                                      &key))
        Py_RETURN_FALSE;

    len = self->container->get_keys(self->container, key, NULL, 0);

    if (len <= 0) {
        Py_RETURN_FALSE;
    }

    char* value = (char*) malloc(sizeof(char)*len + 1);
    if (self->container->get_keys(self->container, key, value, len + 1) != len) {
        Py_RETURN_FALSE;
    }

    return PyUnicode_FromString(value);
}

static PyObject *
Container_load_config(Container *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"path", NULL};
    char* path = NULL;

    if (! PyArg_ParseTupleAndKeywords(args, kwds, "|s", kwlist,
                                      &path))
        Py_RETURN_FALSE;

    if (self->container->load_config(self->container, path)) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static PyObject *
Container_save_config(Container *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"path", NULL};
    char* path = NULL;

    if (! PyArg_ParseTupleAndKeywords(args, kwds, "|s", kwlist,
                                      &path))
        Py_RETURN_FALSE;

    if (self->container->save_config(self->container, path)) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static PyObject *
Container_set_cgroup_item(Container *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"key", "value", NULL};
    char *key = NULL;
    char *value = NULL;

    if (! PyArg_ParseTupleAndKeywords(args, kwds, "ss|", kwlist,
                                      &key, &value))
        Py_RETURN_FALSE;

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

    if (! PyArg_ParseTupleAndKeywords(args, kwds, "ss|", kwlist,
                                      &key, &value))
        Py_RETURN_FALSE;

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

    if (! PyArg_ParseTupleAndKeywords(args, kwds, "s|", kwlist,
                                      &path))
        Py_RETURN_FALSE;

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
        Py_RETURN_FALSE;

    if (self->container->shutdown(self->container, timeout)) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static PyObject *
Container_start(Container *self, PyObject *args, PyObject *kwds)
{
    char** init_args = {NULL};
    PyObject *useinit = NULL, *vargs = NULL;
    int init_useinit = 0;
    static char *kwlist[] = {"useinit", "cmd", NULL};

    if (! PyArg_ParseTupleAndKeywords(args, kwds, "|OO", kwlist,
                                      &useinit, &vargs))
        Py_RETURN_FALSE;

    if (useinit && useinit == Py_True) {
        init_useinit = 1;
    }

    if (vargs && PyTuple_Check(vargs)) {
        init_args = convert_tuple_to_char_pointer_array(vargs);
        if (!init_args) {
            return NULL;
        }
    }

    self->container->want_daemonize(self->container);

    if (self->container->start(self->container, init_useinit, init_args)) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
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
        Py_RETURN_FALSE;

    if (self->container->wait(self->container, state, timeout)) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static PyGetSetDef Container_getseters[] = {
    {"config_file_name",
     (getter)Container_config_file_name, 0,
     "Path to the container configuration",
     NULL},
    {"defined",
     (getter)Container_defined, 0,
     "Boolean indicating whether the container configuration exists",
     NULL},
    {"init_pid",
     (getter)Container_init_pid, 0,
     "PID of the container's init process in the host's PID namespace",
     NULL},
    {"name",
     (getter)Container_name, 0,
     "Container name",
     NULL},
    {"running",
     (getter)Container_running, 0,
     "Boolean indicating whether the container is running or not",
     NULL},
    {"state",
     (getter)Container_state, 0,
     "Container state",
     NULL},
    {NULL, NULL, NULL, NULL, NULL}
};

static PyMethodDef Container_methods[] = {
    {"clear_config_item", (PyCFunction)Container_clear_config_item, METH_VARARGS | METH_KEYWORDS,
     "clear_config_item(key) -> boolean\n"
     "\n"
     "Clear the current value of a config key."
    },
    {"create", (PyCFunction)Container_create, METH_VARARGS | METH_KEYWORDS,
     "create(template, args = (,)) -> boolean\n"
     "\n"
     "Create a new rootfs for the container, using the given template "
     "and passing some optional arguments to it."
    },
    {"destroy", (PyCFunction)Container_destroy, METH_NOARGS,
     "destroy() -> boolean\n"
     "\n"
     "Destroys the container."
    },
    {"freeze", (PyCFunction)Container_freeze, METH_NOARGS,
     "freeze() -> boolean\n"
     "\n"
     "Freezes the container and returns its return code."
    },
    {"get_cgroup_item", (PyCFunction)Container_get_cgroup_item, METH_VARARGS | METH_KEYWORDS,
     "get_cgroup_item(key) -> string\n"
     "\n"
     "Get the current value of a cgroup entry."
    },
    {"get_config_item", (PyCFunction)Container_get_config_item, METH_VARARGS | METH_KEYWORDS,
     "get_config_item(key) -> string\n"
     "\n"
     "Get the current value of a config key."
    },
    {"get_config_path", (PyCFunction)Container_get_config_path, METH_NOARGS,
     "get_config_path() -> string\n"
     "\n"
     "Return the LXC config path (where the containers are stored)."
    },
    {"get_keys", (PyCFunction)Container_get_keys, METH_VARARGS | METH_KEYWORDS,
     "get_keys(key) -> string\n"
     "\n"
     "Get a list of valid sub-keys for a key."
    },
    {"load_config", (PyCFunction)Container_load_config, METH_VARARGS | METH_KEYWORDS,
     "load_config(path = DEFAULT) -> boolean\n"
     "\n"
     "Read the container configuration from its default "
     "location or from an alternative location if provided."
    },
    {"save_config", (PyCFunction)Container_save_config, METH_VARARGS | METH_KEYWORDS,
     "save_config(path = DEFAULT) -> boolean\n"
     "\n"
     "Save the container configuration to its default "
     "location or to an alternative location if provided."
    },
    {"set_cgroup_item", (PyCFunction)Container_set_cgroup_item, METH_VARARGS | METH_KEYWORDS,
     "set_cgroup_item(key, value) -> boolean\n"
     "\n"
     "Set a cgroup entry to the provided value."
    },
    {"set_config_item", (PyCFunction)Container_set_config_item, METH_VARARGS | METH_KEYWORDS,
     "set_config_item(key, value) -> boolean\n"
     "\n"
     "Set a config key to the provided value."
    },
    {"set_config_path", (PyCFunction)Container_set_config_path, METH_VARARGS | METH_KEYWORDS,
     "set_config_path(path) -> boolean\n"
     "\n"
     "Set the LXC config path (where the containers are stored)."
    },
    {"shutdown", (PyCFunction)Container_shutdown, METH_VARARGS | METH_KEYWORDS,
     "shutdown(timeout = -1) -> boolean\n"
     "\n"
     "Sends SIGPWR to the container and wait for it to shutdown "
     "unless timeout is set to a positive value, in which case "
     "the container will be killed when the timeout is reached."
    },
    {"start", (PyCFunction)Container_start, METH_VARARGS | METH_KEYWORDS,
     "start(useinit = False, cmd = (,)) -> boolean\n"
     "\n"
     "Start the container, optionally using lxc-init and "
     "an alternate init command, then returns its return code."
    },
    {"stop", (PyCFunction)Container_stop, METH_NOARGS,
     "stop() -> boolean\n"
     "\n"
     "Stop the container and returns its return code."
    },
    {"unfreeze", (PyCFunction)Container_unfreeze, METH_NOARGS,
     "unfreeze() -> boolean\n"
     "\n"
     "Unfreezes the container and returns its return code."
    },
    {"wait", (PyCFunction)Container_wait, METH_VARARGS | METH_KEYWORDS,
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
    {"get_default_config_path", (PyCFunction)LXC_get_default_config_path, METH_NOARGS,
     "Returns the current LXC config path"},
    {"get_version", (PyCFunction)LXC_get_version, METH_NOARGS,
     "Returns the current LXC library version"},
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

    if (PyType_Ready(&_lxc_ContainerType) < 0)
        return NULL;

    m = PyModule_Create(&_lxcmodule);
    if (m == NULL)
        return NULL;

    Py_INCREF(&_lxc_ContainerType);
    PyModule_AddObject(m, "Container", (PyObject *)&_lxc_ContainerType);
    return m;
}
