#!/usr/bin/python3
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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

from distutils.core import setup, Extension

module = Extension('_lxc', sources=['lxc.c'], libraries=['lxc'])

setup(name='_lxc',
      version='0.1',
      description='LXC',
      packages=['lxc'],
      package_dir={'lxc': 'lxc'},
      ext_modules=[module])
