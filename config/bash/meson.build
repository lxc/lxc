# SPDX-License-Identifier: LGPL-2.1-or-later

bash_completion = configure_file(
    configuration: conf,
    input: '_lxc.in',
    output: '_lxc',
    install: true,
    install_dir: bashcompletiondir)


foreach cmd: [
    'lxc-attach',
    'lxc-autostart',
    'lxc-cgroup',
    'lxc-checkpoint',
    'lxc-config',
    'lxc-console',
    'lxc-copy',
    'lxc-create',
    'lxc-destroy',
    'lxc-device',
    'lxc-execute',
    'lxc-freeze',
    'lxc-info',
    'lxc-ls',
    'lxc-monitor',
    'lxc-snapshot',
    'lxc-start',
    'lxc-stop',
    'lxc-top',
    'lxc-unfreeze',
    'lxc-unshare',
    'lxc-usernsexec',
    'lxc-wait',
]
    install_symlink(cmd,
        pointing_to: '_lxc',
        install_dir: bashcompletiondir)
endforeach
