# Yum plugin to re-patch container rootfs after a yum update is done
#
# Copyright (C) 2012 Oracle
#
# Authors:
# Dwight Engen <dwight.engen@oracle.com>
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

import os
from fnmatch import fnmatch
from yum.plugins import TYPE_INTERACTIVE
from yum.plugins import PluginYumExit

requires_api_version = '2.0'
plugin_type = (TYPE_INTERACTIVE,)

def posttrans_hook(conduit):
    pkgs = []
    patch_required = False

    # If we aren't root, we can't have updated anything
    if os.geteuid():
        return

    # See what packages have files that were patched
    confpkgs = conduit.confString('main', 'packages')
    if not confpkgs:
        return

    tmp = confpkgs.split(",")
    for confpkg in tmp:
        pkgs.append(confpkg.strip())

    conduit.info(2, "lxc-patch: checking if updated pkgs need patching...")
    ts = conduit.getTsInfo()
    for tsmem in ts.getMembers():
        for pkg in pkgs:
            if fnmatch(pkg, tsmem.po.name):
                patch_required = True
    if patch_required:
        conduit.info(2, "lxc-patch: patching container...")
        os.spawnlp(os.P_WAIT, "lxc-patch", "lxc-patch", "--patch", "/")
