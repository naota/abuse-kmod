#!/bin/bash

N=0
SIZE=16

DEV=/dev/abuse${N}
CTL=/dev/abctl

die() {
    err=$?
    set +x
    echo -e "\033[1;4;31mError exit $err\033[0m"
}

set -x

./userland/abmem ${DEV} &
pid=$!
sleep 1
dd if=/dev/zero of=${DEV} bs=4096 count=1 oflag=sync || die
dd if=${DEV} of=/dev/stdout bs=4096 count=1 | hexdump -C || die
kill $pid
