#!/usr/bin/env python3
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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
# USA
#

import lxc
import uuid
import os
import subprocess
import sys
import time

# Let's pick a random name, avoiding clashes
CONTAINER_NAME = str(uuid.uuid1())
CLONE_NAME = str(uuid.uuid1())
RENAME_NAME = str(uuid.uuid1())

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

# Try to get the host architecture for dpkg systems
arch = "i386"
try:
    with open(os.path.devnull, "w") as devnull:
        dpkg = subprocess.Popen(['dpkg', '--print-architecture'],
                                stderr=devnull, stdout=subprocess.PIPE,
                                universal_newlines=True)

        if dpkg.wait() == 0:
            arch = dpkg.stdout.read().strip()
except:
    pass

## Create a rootfs
print("Creating rootfs using 'download', arch=%s" % arch)
container.create("download", 0,
                 {"dist": "ubuntu",
                  "release": "trusty",
                  "arch": arch})

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

## Starting the container
print("Starting the container")
container.start()
container.wait("RUNNING", 3)

# A few basic checks of the current state
assert(container.init_pid > 1)
assert(container.running)
assert(container.state == "RUNNING")


## Checking IP address
print("Getting the interface names")
assert(set(container.get_interfaces()) == set(('lo', 'eth0')))

## Checking IP address
print("Getting the IP addresses")

count = 0
ips = []
while not ips or count == 10:
    ips = container.get_ips()
    time.sleep(1)
    count += 1

if os.geteuid():
    container.attach_wait(lxc.attach_run_command, ["ifconfig", "eth0"],
                          namespaces=(lxc.CLONE_NEWUSER + lxc.CLONE_NEWNET
                                      + lxc.CLONE_NEWUTS))
else:
    container.attach_wait(lxc.attach_run_command, ["ifconfig", "eth0"],
                          namespaces=(lxc.CLONE_NEWNET + lxc.CLONE_NEWUTS))

# A few basic checks of the current state
assert(len(ips) > 0)

## Test running config
assert(container.name == CONTAINER_NAME
       == container.get_config_item("lxc.utsname")
       == container.get_running_config_item("lxc.utsname"))

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
if not container.shutdown(3):
    container.stop()

if container.running:
    print("Stopping the container")
    container.stop()
    container.wait("STOPPED", 3)

# A few basic checks of the current state
assert(container.init_pid == -1)
assert(not container.running)
assert(container.state == "STOPPED")

## Snapshotting the container
print("Snapshotting the container")
assert(not container.snapshot_list())
assert(container.snapshot() == "snap0")
assert(len(container.snapshot_list()) == 1)
assert(container.snapshot_restore("snap0") is True)
assert(container.snapshot_destroy("snap0") is True)

## Cloning the container
print("Cloning the container as '%s'" % CLONE_NAME)
clone = container.clone(CLONE_NAME)
assert(clone is not False)

print ("Renaming the clone to '%s'" % RENAME_NAME)
rename = clone.rename(RENAME_NAME)
rename.start()
rename.stop()
rename.destroy()

## Destroy the container
print("Destroying the container")
container.destroy()

assert(not container.defined)
