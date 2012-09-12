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
import tempfile
import time
import warnings

warnings.warn("The python-lxc API isn't yet stable "
              "and may change at any point in the future.", Warning, 2)


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
        count = len(self.container.get_config_item("lxc.network"))
        if index >= count:
            raise IndexError("list index out of range")

        return ContainerNetwork(self.container, index)

    def __len__(self):
        return len(self.container.get_config_item("lxc.network"))

    def add(self, network_type):
        index = len(self.container.get_config_item("lxc.network"))

        return self.container.set_config_item("lxc.network.%s.type" % index,
                    network_type)

    def remove(self, index):
        count = len(self.container.get_config_item("lxc.network"))
        if index >= count:
            raise IndexError("list index out of range")

        return self.container.clear_config_item("lxc.network.%s" % index)


class Container(_lxc.Container):
    def __init__(self, name):
        """
            Creates a new Container instance.
        """

        if os.geteuid() != 0:
            raise Exception("Running as non-root.")

        _lxc.Container.__init__(self, name)
        self.network = ContainerNetworkList(self)

    def append_config_item(self, key, value):
        """
            Append 'value' to 'key', assuming 'key' is a list.
            If 'key' isn't a list, 'value' will be set as the value of 'key'.
        """

        return _lxc.Container.set_config_item(self, key, value)

    def attach(self, namespace="ALL", *cmd):
        """
            Attach to a running container.
        """

        if not self.running:
            return False

        attach = ["lxc-attach", "-n", self.name]
        if namespace != "ALL":
            attach += ["-s", namespace]

        if cmd:
            attach += ["--"] + list(cmd)

        if subprocess.call(
                attach,
                universal_newlines=True) != 0:
            return False
        return True

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

        if subprocess.call(
                    ["lxc-clone", "-o", source.name, "-n", self.name],
                    universal_newlines=True) != 0:
            return False

        self.load_config()
        return True

    def console(self, tty="1"):
        """
            Access the console of a container.
        """

        if not self.running:
            return False

        if subprocess.call(
                    ["lxc-console", "-n", self.name, "-t", "%s" % tty],
                    universal_newlines=True) != 0:
            return False
        return True

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

    def get_ips(self, timeout=60, interface=None, protocol=None):
        """
            Returns the list of IP addresses for the container.
        """

        if not self.defined or not self.running:
            return False

        try:
            os.makedirs("/run/netns")
        except:
            pass

        path = tempfile.mktemp(dir="/run/netns")

        os.symlink("/proc/%s/ns/net" % self.init_pid, path)

        ips = []

        count = 0
        while count < timeout:
            if count != 0:
                time.sleep(1)

            base_cmd = ["ip", "netns", "exec", path.split("/")[-1], "ip"]

            # Get IPv6
            if protocol in ("ipv6", None):
                ip6_cmd = base_cmd + ["-6", "addr", "show", "scope", "global"]
                if interface:
                    ip = subprocess.Popen(ip6_cmd + ["dev", interface],
                            stdout=subprocess.PIPE, universal_newlines=True)
                else:
                    ip = subprocess.Popen(ip6_cmd, stdout=subprocess.PIPE,
                            universal_newlines=True)

                ip.wait()
                for line in ip.stdout.read().split("\n"):
                    fields = line.split()
                    if len(fields) > 2 and fields[0] == "inet6":
                        ips.append(fields[1].split('/')[0])

            # Get IPv4
            if protocol in ("ipv4", None):
                ip4_cmd = base_cmd + ["-4", "addr", "show", "scope", "global"]
                if interface:
                    ip = subprocess.Popen(ip4_cmd + ["dev", interface],
                            stdout=subprocess.PIPE, universal_newlines=True)
                else:
                    ip = subprocess.Popen(ip4_cmd, stdout=subprocess.PIPE,
                            universal_newlines=True)

                ip.wait()
                for line in ip.stdout.read().split("\n"):
                    fields = line.split()
                    if len(fields) > 2 and fields[0] == "inet":
                        ips.append(fields[1].split('/')[0])

            if ips:
                break

            count += 1

        os.remove(path)
        return ips

    def get_keys(self, key):
        """
            Returns a list of valid sub-keys.
        """
        value = _lxc.Container.get_keys(self, key)

        if value is False:
            return False
        elif value.endswith("\n"):
            return value.rstrip("\n").split("\n")
        else:
            return value

    def set_config_item(self, key, value):
        """
            Set a config key to a provided value.
            The value can be a list for the keys supporting multiple values.
        """
        old_value = self.get_config_item(key)

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

        if isinstance(value, str) and isinstance(new_value, str) and \
           value == new_value:
            return True
        elif isinstance(value, list) and isinstance(new_value, list) and \
           set(value) == set(new_value):
            return True
        elif isinstance(value, str) and isinstance(new_value, list) and \
           set([value]) == set(new_value):
            return True
        elif old_value:
            set_key(key, old_value)
            return False
        else:
            self.clear_config_item(key)
            return False

    def wait(self, state, timeout = -1):
        """
            Wait for the container to reach a given state or timeout.
        """

        if isinstance(state, str):
            state = state.upper()

        return _lxc.Container.wait(self, state, timeout)

def list_containers(as_object=False):
    """
        List the containers on the system.
    """
    containers = []
    for entry in glob.glob("/var/lib/lxc/*/config"):
        if as_object:
            containers.append(Container(entry.split("/")[-2]))
        else:
            containers.append(entry.split("/")[-2])
    return containers
