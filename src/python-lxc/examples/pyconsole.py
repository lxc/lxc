#!/usr/bin/env python3
#
# pyconsole: Example program showing use of console functions
#            in the lxc python binding
#
# (C) Copyright Oracle. 2013
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

import lxc
import sys
import time

if __name__ == '__main__':
    ttynum = -1
    escape = 1
    if len(sys.argv) < 2:
        sys.exit("Usage: %s container-name [ttynum [escape]]" % sys.argv[0])
    if len(sys.argv) > 2:
        ttynum = int(sys.argv[2])
    if len(sys.argv) > 3:
        escape = ord(sys.argv[3]) - ord('a') + 1

    ct = lxc.Container(sys.argv[1])

    print("Container:%s tty:%d Ctrl-%c q to quit" %
          (ct.name, ttynum, ord('a') + escape-1))
    time.sleep(1)
    if not ct.defined:
        sys.exit("Container %s not defined" % ct.name)
    if not ct.running:
        sys.exit("Container %s not running" % ct.name)

    ct.console(ttynum, 0, 1, 2, escape)
    print("Console done")
