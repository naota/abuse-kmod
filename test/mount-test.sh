#!/bin/bash

set -xe

DEV=/dev/abuse0
MNT=/mnt/tmp

wipefs -af ${DEV}

dmesg -C
mkfs.ext4 ${DEV}
fsck -fy ${DEV}
# debugfs -R "stat lost+found" ${DEV}
# debugfs -R "ls lost+found" ${DEV}
mount ${DEV} ${MNT}
for x in `seq 10`;do
  tar -C ${MNT} -xf /usr/portage/distfiles/bash-4.3.tar.gz
done
find ${MNT} >/dev/null
umount ${MNT}
# debugfs -R "stat lost+found" ${DEV}
# debugfs -R "ls lost+found" ${DEV}
fsck -fy ${DEV}
dmesg
