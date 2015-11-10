#!/usr/bin/env python3
#
# pyconsole-vte: Example program showing use of console functions
#                in the lxc python binding
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

import gtk
import vte
import lxc
import sys


def gtk_exit_cb(terminal):
    gtk.main_quit()


def vte_con(ct, ttynum):
    print("Doing console in a VTE widget...")
    masterfd = ct.console_getfd(ttynum)
    term = vte.Terminal()
    term.set_cursor_blinks(True)
    term.set_scrollback_lines(1000)
    term.connect('eof', gtk_exit_cb)

    term.set_pty(masterfd)
    term.feed_child('\n')
    #term.feed_child('ps aux\n')

    vscrollbar = gtk.VScrollbar()
    vscrollbar.set_adjustment(term.get_adjustment())

    hbox = gtk.HBox()
    hbox.pack_start(term)
    hbox.pack_start(vscrollbar)

    window = gtk.Window()
    window.add(hbox)
    window.connect('delete-event', lambda window, event: gtk.main_quit())
    window.show_all()
    gtk.main()
    print("Console done")

if __name__ == '__main__':
    ttynum = -1
    if len(sys.argv) < 2:
        sys.exit("Usage: %s container-name [ttynum]" % sys.argv[0])
    if len(sys.argv) > 2:
        ttynum = int(sys.argv[2])

    ct = lxc.Container(sys.argv[1])

    print("Container:%s tty:%d" % (ct.name, ttynum))
    if not ct.defined:
        sys.exit("Container %s not defined" % ct.name)
    if not ct.running:
        sys.exit("Container %s not running" % ct.name)

    vte_con(ct, ttynum)
