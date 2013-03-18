#!/usr/bin/python3
#
# api_test.py: Test/demo of the python3-lxc API
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

import warnings
warnings.filterwarnings("ignore", "The python-lxc API isn't yet stable")

import lxc
import uuid
import sys

# Some constants
LXC_TEMPLATE = "ubuntu"

# Let's pick a random name, avoiding clashes
CONTAINER_NAME = str(uuid.uuid1())
CLONE_NAME = str(uuid.uuid1())

## Instantiate the container instance
print("Getting instance for '%s'" % CONTAINER_NAME)
container = lxc.Container(CONTAINER_NAME)

# A few basic checks of the current state
assert(container.config_file_name == "%s/%s/config" %
       (lxc.default_config_path, CONTAINER_NAME))
assert(not container.defined)
assert(container.init_pid == -1)
assert(container.name == CONTAINER_NAME)
assert(not container.running)
assert(container.state == "STOPPED")

## Create a rootfs
print("Creating rootfs using '%s'" % LXC_TEMPLATE)
container.create(LXC_TEMPLATE)

assert(container.defined)
assert(container.name == CONTAINER_NAME
       == container.get_config_item("lxc.utsname"))
assert(container.name in lxc.list_containers())

## Test the config
print("Testing the configuration")
capdrop = container.get_config_item("lxc.cap.drop")
container.clear_config_item("lxc.cap.drop")
container.set_config_item("lxc.cap.drop", capdrop[:-1])
container.append_config_item("lxc.cap.drop", capdrop[-1])
container.save_config()

# A few basic checks of the current state
assert(isinstance(capdrop, list))
assert(capdrop == container.get_config_item("lxc.cap.drop"))

## Test the networking
print("Testing the networking")

# A few basic checks of the current state
assert("name" in container.get_keys("lxc.network.0"))
assert(len(container.network) == 1)
assert(container.network[0].hwaddr.startswith("00:16:3e"))

## Starting the container
print("Starting the container")
container.start()
container.wait("RUNNING", 3)

# A few basic checks of the current state
assert(container.init_pid > 1)
assert(container.running)
assert(container.state == "RUNNING")

## Checking IP address
print("Getting the IP addresses")
ips = container.get_ips(timeout=10)
container.attach("NETWORK|UTSNAME", "/sbin/ifconfig", "eth0")

# A few basic checks of the current state
assert(len(ips) > 0)

## Testing cgroups a bit
print("Testing cgroup API")
max_mem = container.get_cgroup_item("memory.max_usage_in_bytes")
current_limit = container.get_cgroup_item("memory.limit_in_bytes")
assert(container.set_cgroup_item("memory.limit_in_bytes", max_mem))
assert(container.get_cgroup_item("memory.limit_in_bytes") != current_limit)

## Freezing the container
print("Freezing the container")
container.freeze()
container.wait("FROZEN", 3)

# A few basic checks of the current state
assert(container.init_pid > 1)
assert(container.running)
assert(container.state == "FROZEN")

## Unfreezing the container
print("Unfreezing the container")
container.unfreeze()
container.wait("RUNNING", 3)

# A few basic checks of the current state
assert(container.init_pid > 1)
assert(container.running)
assert(container.state == "RUNNING")

if len(sys.argv) > 1 and sys.argv[1] == "--with-console":
    ## Attaching to tty1
    print("Attaching to tty1")
    container.console(tty=1)

## Shutting down the container
print("Shutting down the container")
container.shutdown(3)

if container.running:
    print("Stopping the container")
    container.stop()
    container.wait("STOPPED", 3)

# A few basic checks of the current state
assert(container.init_pid == -1)
assert(not container.running)
assert(container.state == "STOPPED")

## Cloning the container
print("Cloning the container")
clone = lxc.Container(CLONE_NAME)
clone.clone(container)
clone.start()
clone.stop()
clone.destroy()

## Destroy the container
print("Destroying the container")
container.destroy()

assert(not container.defined)
