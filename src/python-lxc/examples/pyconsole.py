#!/usr/bin/python3
#
# Example program showing use of console functions in the lxc python binding
#

import warnings
warnings.filterwarnings("ignore", "The python-lxc API isn't yet stable")

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

    print("Container:%s tty:%d Ctrl-%c q to quit" % (ct.name, ttynum, ord('a') + escape-1))
    time.sleep(1)
    if not ct.defined:
        sys.exit("Container %s not defined" % ct.name)
    if not ct.running:
        sys.exit("Container %s not running" % ct.name)

    ct.console(ttynum, 0, 1, 2, escape)
    print("Console done")
