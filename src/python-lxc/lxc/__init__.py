#
# python-lxc: Python bindings for LXC
#
# (C) Copyright Canonical Ltd. 2012
#
# Authors:
# Stéphane Graber <stgraber@ubuntu.com>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

import _lxc
import glob
import os
import subprocess
import stat
import time
import warnings

warnings.warn("The python-lxc API isn't yet stable "
              "and may change at any point in the future.", Warning, 2)

default_config_path = _lxc.get_default_config_path()
version = _lxc.get_version()


class ContainerNetwork():
    props = {}

    def __init__(self, container, index):
        self.container = container
        self.index = index

        for key in self.container.get_keys("lxc.network.%s" % self.index):
            if "." in key:
                self.props[key.replace(".", "_")] = key
            else:
                self.props[key] = key

        if not self.props:
            return False

    def __delattr__(self, key):
        if key in ["container", "index", "props"]:
            return object.__delattr__(self, key)

        if key not in self.props:
            raise AttributeError("'%s' network has no attribute '%s'" % (
                                 self.__get_network_item("type"), key))

        return self.__clear_network_item(self.props[key])

    def __dir__(self):
        return sorted(self.props.keys())

    def __getattr__(self, key):
        if key in ["container", "index", "props"]:
            return object.__getattribute__(self, key)

        if key not in self.props:
            raise AttributeError("'%s' network has no attribute '%s'" % (
                                 self.__get_network_item("type"), key))

        return self.__get_network_item(self.props[key])

    def __hasattr__(self, key):
        if key in ["container", "index", "props"]:
            return object.__hasattr__(self, key)

        if key not in self.props:
            raise AttributeError("'%s' network has no attribute '%s'" % (
                                 self.__get_network_item("type"), key))

        return True

    def __repr__(self):
        return "'%s' network at index '%s'" % (
            self.__get_network_item("type"), self.index)

    def __setattr__(self, key, value):
        if key in ["container", "index", "props"]:
            return object.__setattr__(self, key, value)

        if key not in self.props:
            raise AttributeError("'%s' network has no attribute '%s'" % (
                                 self.__get_network_item("type"), key))

        return self.__set_network_item(self.props[key], value)

    def __clear_network_item(self, key):
        return self.container.clear_config_item("lxc.network.%s.%s" % (
                                                self.index, key))

    def __get_network_item(self, key):
        return self.container.get_config_item("lxc.network.%s.%s" % (
                                              self.index, key))

    def __set_network_item(self, key, value):
        return self.container.set_config_item("lxc.network.%s.%s" % (
                                              self.index, key), value)


class ContainerNetworkList():
    def __init__(self, container):
        self.container = container

    def __getitem__(self, index):
        if index >= len(self):
            raise IndexError("list index out of range")

        return ContainerNetwork(self.container, index)

    def __len__(self):
        values = self.container.get_config_item("lxc.network")

        if values:
            return len(values)
        else:
            return 0

    def add(self, network_type):
        index = len(self)

        return self.container.set_config_item("lxc.network.%s.type" % index,
                                              network_type)

    def remove(self, index):
        count = len(self)
        if index >= count:
            raise IndexError("list index out of range")

        return self.container.clear_config_item("lxc.network.%s" % index)


class Container(_lxc.Container):
    def __init__(self, name, config_path=None):
        """
            Creates a new Container instance.
        """

        if os.geteuid() != 0:
            raise Exception("Running as non-root.")

        if config_path:
            _lxc.Container.__init__(self, name, config_path)
        else:
            _lxc.Container.__init__(self, name)

        self.network = ContainerNetworkList(self)

    def add_device_node(self, path, destpath=None):
        """
            Add block/char device to running container.
        """

        if not self.running:
            return False

        if not destpath:
            destpath = path

        if not os.path.exists(path):
            return False

        # Lookup the source
        path_stat = os.stat(path)
        mode = stat.S_IMODE(path_stat.st_mode)

        # Allow the target
        if stat.S_ISBLK(path_stat.st_mode):
            self.set_cgroup_item("devices.allow",
                                 "b %s:%s rwm" %
                                 (int(path_stat.st_rdev / 256),
                                  int(path_stat.st_rdev % 256)))
        elif stat.S_ISCHR(path_stat.st_mode):
            self.set_cgroup_item("devices.allow",
                                 "c %s:%s rwm" %
                                 (int(path_stat.st_rdev / 256),
                                  int(path_stat.st_rdev % 256)))

        # Create the target
        rootfs = "/proc/%s/root/" % self.init_pid
        container_path = "%s/%s" % (rootfs, destpath)

        if os.path.exists(container_path):
            os.remove(container_path)

        os.mknod(container_path, path_stat.st_mode, path_stat.st_rdev)
        os.chmod(container_path, mode)
        os.chown(container_path, 0, 0)

        return True

    def add_device_net(self, name, destname=None):
        """
            Add network device to running container.
        """

        if not self.running:
            return False

        if not destname:
            destname = name

        if not os.path.exists("/sys/class/net/%s/" % name):
            return False

        return subprocess.call(['ip', 'link', 'set',
                                'dev', name,
                                'netns', str(self.init_pid),
                                'name', destname]) == 0

    def append_config_item(self, key, value):
        """
            Append 'value' to 'key', assuming 'key' is a list.
            If 'key' isn't a list, 'value' will be set as the value of 'key'.
        """

        return _lxc.Container.set_config_item(self, key, value)

    def create(self, template, args={}):
        """
            Create a new rootfs for the container.

            "template" must be a valid template name.

            "args" (optional) is a dictionary of parameters and values to pass
            to the template.
        """

        template_args = []
        for item in args.items():
            template_args.append("--%s" % item[0])
            template_args.append("%s" % item[1])

        return _lxc.Container.create(self, template, tuple(template_args))

    def clone(self, container):
        """
            Clone an existing container into a new one.
        """

        if self.defined:
            return False

        if isinstance(container, Container):
            source = container
        else:
            source = Container(container)

        if not source.defined:
            return False

        if subprocess.call(["lxc-clone", "-o", source.name, "-n", self.name],
                           universal_newlines=True) != 0:
            return False

        self.load_config()
        return True

    def console(self, ttynum=-1, stdinfd=0, stdoutfd=1, stderrfd=2, escape=1):
        """
            Attach to console of running container.
        """

        if not self.running:
            return False

        return _lxc.Container.console(self, ttynum, stdinfd, stdoutfd,
                                      stderrfd, escape)

    def console_getfd(self, ttynum=-1):
        """
            Attach to console of running container.
        """

        if not self.running:
            return False

        return _lxc.Container.console_getfd(self, ttynum)

    def get_cgroup_item(self, key):
        """
            Returns the value for a given cgroup entry.
            A list is returned when multiple values are set.
        """
        value = _lxc.Container.get_cgroup_item(self, key)

        if value is False:
            return False
        else:
            return value.rstrip("\n")

    def get_config_item(self, key):
        """
            Returns the value for a given config key.
            A list is returned when multiple values are set.
        """
        value = _lxc.Container.get_config_item(self, key)

        if value is False:
            return False
        elif value.endswith("\n"):
            return value.rstrip("\n").split("\n")
        else:
            return value

    def get_keys(self, key=None):
        """
            Returns a list of valid sub-keys.
        """
        if key:
            value = _lxc.Container.get_keys(self, key)
        else:
            value = _lxc.Container.get_keys(self)

        if value is False:
            return False
        elif value.endswith("\n"):
            return value.rstrip("\n").split("\n")
        else:
            return value

    def get_ips(self, interface=None, family=None, scope=None, timeout=0):
        """
            Get a tuple of IPs for the container.
        """

        kwargs = {}
        if interface:
            kwargs['interface'] = interface
        if family:
            kwargs['family'] = family
        if scope:
            kwargs['scope'] = scope

        ips = None
        timeout = int(os.environ.get('LXC_GETIP_TIMEOUT', timeout))

        while not ips:
            ips = _lxc.Container.get_ips(self, **kwargs)
            if timeout == 0:
                break

            timeout -= 1
            time.sleep(1)

        return ips

    def set_config_item(self, key, value):
        """
            Set a config key to a provided value.
            The value can be a list for the keys supporting multiple values.
        """
        try:
            old_value = self.get_config_item(key)
        except KeyError:
            old_value = None

        # Check if it's a list
        def set_key(key, value):
            self.clear_config_item(key)
            if isinstance(value, list):
                for entry in value:
                    if not _lxc.Container.set_config_item(self, key, entry):
                        return False
            else:
                _lxc.Container.set_config_item(self, key, value)

        set_key(key, value)
        new_value = self.get_config_item(key)

        if (isinstance(value, str) and isinstance(new_value, str) and
                value == new_value):
            return True
        elif (isinstance(value, list) and isinstance(new_value, list) and
                set(value) == set(new_value)):
            return True
        elif (isinstance(value, str) and isinstance(new_value, list) and
                set([value]) == set(new_value)):
            return True
        elif old_value:
            set_key(key, old_value)
            return False
        else:
            self.clear_config_item(key)
            return False

    def wait(self, state, timeout=-1):
        """
            Wait for the container to reach a given state or timeout.
        """

        if isinstance(state, str):
            state = state.upper()

        return _lxc.Container.wait(self, state, timeout)


def list_containers(as_object=False, config_path=None):
    """
        List the containers on the system.
    """

    if not config_path:
        config_path = default_config_path

    containers = []
    for entry in glob.glob("%s/*/config" % config_path):
        if as_object:
            containers.append(Container(entry.split("/")[-2], config_path))
        else:
            containers.append(entry.split("/")[-2])
    return containers

def attach_run_command(cmd):
    """
        Run a command when attaching
        
        Please do not call directly, this will execvp the command.
        This is to be used in conjunction with the attach method
        of a container.
    """
    if isinstance(cmd, tuple):
        return _lxc.attach_run_command(cmd)
    elif isinstance(cmd, list):
        return _lxc.attach_run_command((cmd[0], cmd))
    else:
        return _lxc.attach_run_command((cmd, [cmd]))

def attach_run_shell():
    """
        Run a shell when attaching
        
        Please do not call directly, this will execvp the shell.
        This is to be used in conjunction with the attach method
        of a container.
    """
    return _lxc.attach_run_shell(None)

# Some constants for attach
LXC_ATTACH_KEEP_ENV = _lxc.LXC_ATTACH_KEEP_ENV
LXC_ATTACH_CLEAR_ENV = _lxc.LXC_ATTACH_CLEAR_ENV
LXC_ATTACH_MOVE_TO_CGROUP = _lxc.LXC_ATTACH_MOVE_TO_CGROUP
LXC_ATTACH_DROP_CAPABILITIES = _lxc.LXC_ATTACH_DROP_CAPABILITIES
LXC_ATTACH_SET_PERSONALITY = _lxc.LXC_ATTACH_SET_PERSONALITY
LXC_ATTACH_APPARMOR = _lxc.LXC_ATTACH_APPARMOR
LXC_ATTACH_REMOUNT_PROC_SYS = _lxc.LXC_ATTACH_REMOUNT_PROC_SYS
LXC_ATTACH_DEFAULT = _lxc.LXC_ATTACH_DEFAULT
