
===

Please note: This is a working copy of LXC used for patches.
If you need the real upstream, please see: https://linuxcontainers.org/

===

Please see the COPYING file for details on copying and usage.
Please refer to the INSTALL file for instructions on how to build.

What is lxc:

  The container technology is actively being pushed into the mainstream linux
  kernel. It provides the resource management through the control groups  aka
  process containers and resource isolation through the namespaces.

  The  linux  containers, lxc, aims to use these new functionalities to pro-
  vide a userspace container object which provides full  resource  isolation
  and resource control for an application or a system.

  The first objective of this project is to make the life easier for the ker-
  nel developers involved in the containers project and  especially  to  con-
  tinue  working  on  the  Checkpoint/Restart  new features. The lxc is small
  enough to easily manage a container with simple command lines and  complete
  enough to be used for other purposes.

Using lxc:

  Refer the lxc* man pages (generated from doc/* files)

Downloading the current source code:

  Source for the latest released version can always be downloaded from
  http://linuxcontainers.org/downloads/

  You can browse the up to the minute source code and change history online.
  http://github.com/lxc/lxc

  For detailed build instruction refer to INSTALL and man lxc man page
  but a short command line should work:
  ./autogen.sh && ./configure && make && sudo make install
  preceded by ./autogen.sh if configure do not exist yet.

Troubleshooting:

  If you get an error message at the autogen.sh or configure stage, make
  sure you have, autoconf, automake, pkg-config, make and gcc installed on
  your machine.

  The configure script will usually give you hints as to what you are missing,
  looking for those in your package manager will usually give you the package
  that you need to install.

  Also pay a close attention to the feature summary showed at the end of
  the configure run, features are automatically enabled/disabled based on
  whether the needed development packages are installed on your machine.
  If you want a feature but don't know what to install, force it with
  --enable-<feature> and look at the error message from configure.

Getting help:

  when you find you need help, you can check out one of the two
  lxc mailing list archives and register if interested:
  http://lists.linuxcontainers.org/listinfo/lxc-devel
  http://lists.linuxcontainers.org/listinfo/lxc-users

Portability:

  lxc  is  still  in  development, so the command syntax and the API can
  change. The version 1.0.0 will be the frozen version.

  lxc is developed and tested on Linux since kernel mainline version 2.6.27
  (without network) and 2.6.29 with network isolation.
  It's compiled with gcc, and should work on most architectures as long as the
  required kernel features are available. This includes (but isn't limited to):
  i686, x86_64, ppc, ppc64, S390, armel and armhf.

AUTHOR
       Daniel Lezcano <daniel.lezcano@free.fr>

Seccomp with LXC
----------------

To restrict a container with seccomp, you must specify a profile which is
basically a whitelist of system calls it may execute.  In the container
config file, add a line like

lxc.seccomp = /var/lib/lxc/q1/seccomp.full

I created a usable (but basically worthless) seccomp.full file using

cat > seccomp.full << EOF
1
whitelist
EOF
for i in `seq 0 300`; do
    echo $i >> seccomp.full
done
for i in `seq 1024 1079`; do
    echo $i >> seccomp.full
done

 -- Serge Hallyn <serge.hallyn@ubuntu.com>  Fri, 27 Jul 2012 15:47:02 +0600
