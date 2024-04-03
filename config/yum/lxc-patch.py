# SPDX-License-Identifier: LGPL-2.1+
#
# Yum plugin to re-patch container rootfs after a yum update is done

import os
from fnmatch import fnmatch
from yum.plugins import TYPE_INTERACTIVE

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
