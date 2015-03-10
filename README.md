# ABUSE user space block device driver

This is a Linux kernel module to implement block devices in userspace.

This work is mostly based on a patch by Zachary Amsden.

http://lwn.net/Articles/343514/

## Howto

"make" execute some simple test script.

## Kernel module parameters

- max_abuse: Maximum number of abuse devices
- max_part: Maximum number of partitions per abuse device

## Kernel interfaces

Userland program for disk /dev/abuseN communicate with the kernel using ioctl() via corresponding /dev/abctlX.

- ABUSE_GET_STATUS
- ABUSE_SET_STATUS
- ABUSE_RESET
- ABUSE_GET_BIO
- ABUSE_PUT_BIO
