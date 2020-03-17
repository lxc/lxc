The template below is mostly useful for bug reports and support questions.
Feel free to remove anything which doesn't apply to you and add more information where it makes sense.

# Required information

 * Distribution:
 * Distribution version:
 * The output of
   * `lxc-start --version`
   * `lxc-checkconfig`
   * `uname -a`
   * `cat /proc/self/cgroup`
   * `cat /proc/1/mounts`

# Issue description

A brief description of what failed or what could be improved.

# Steps to reproduce

 1. Step one
 2. Step two
 3. Step three

# Information to attach

 - [ ] any relevant kernel output (`dmesg`)
 - [ ] container log (The <log> file from running `lxc-start -n <c> -l TRACE -o <logfile> `)
 - [ ] the containers configuration file
