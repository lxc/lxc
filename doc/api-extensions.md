# API extensions

The changes below were introduced to the LXC API after the 3.0 API was finalized.

They are all backward compatible and can be detected by client tools by
called the `lxc_has_api_extension` function.

## lxc\_log

This introduces a way to initialize a logging instance from the API for a given
container.

## lxc\_config\_item\_is\_supported

This introduces the `lxc_config_item_is_supported` function. It allows users to
check whether their LXC instance supports a given configuration key.

## console\_log

This adds support to container's console log. The console log is implemented as
an efficient ringbuffer.

## reboot2

This adds `reboot2()` as a new API extension. This function properly waits
until a reboot succeeded. It takes a timeout argument. When set to `> 0`
`reboot2()` will block until the timeout is reached, if timeout is set to zero
`reboot2()` will not block, if set to -1 `reboot2()` will block indefinitely.

## mount\_injection

This adds support for injecting and removing mounts into/from a running
containers. Two new API functions `mount()` and `umount()` are added. They
mirror the current mount and umount API of the kernel.
