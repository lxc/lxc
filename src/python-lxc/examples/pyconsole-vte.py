#!/usr/bin/python
#
# Example program showing use of console functions in the lxc python binding
#

import warnings
warnings.filterwarnings("ignore", "The python-lxc API isn't yet stable")

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
