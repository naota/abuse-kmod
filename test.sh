#!/bin/bash

N=0
SIZE=16

DEV=/dev/abuse${N}
CTL=/dev/abctl${N}

die() {
    err=$?
    set +x
    echo -e "\033[1;4;31mError exit $err\033[0m"
}

set -x

dd if=/dev/zero of=${DEV} bs=1M count=${SIZE} || die
