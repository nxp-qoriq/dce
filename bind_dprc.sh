# SPDX-License-Identifier:     BSD-3-Clause
# Copyright 2014-2016 Freescale Semiconductor, Inc.
# All rights reserved.

DPRC=/sys/bus/fsl-mc/devices/$1

# Mount HUGETLB Pages first
HUGE=$(grep -E '/mnt/\<hugepages\>.*hugetlbfs' /proc/mounts)
if [[ -z $HUGE ]]
then
        cd /mnt
        mkdir hugepages
        cd ~
        mount -t hugetlbfs none /mnt/hugepages
else
        echo "Already mounted :  " $HUGE
        echo
fi

if [ -e /sys/module/vfio_iommu_type1 ];
then
        echo "#1)    Allow unsafe interrupts"
        echo 1 > /sys/module/vfio_iommu_type1/parameters/allow_unsafe_interrupts
else
        echo " Can't Run DPAA2 without VFIO support"
        exit
fi

if [ -d $DPRC ];
then
        echo "#1.1)    "$1" container driver override"
        echo vfio-fsl-mc > /sys/bus/fsl-mc/devices/$1/driver_override
        echo "#1.2)    Binding "$1" to VFIO driver"
        echo $1 > /sys/bus/fsl-mc/drivers/vfio-fsl-mc/bind
else
        echo "Container not available"
fi

if [ -e /dev/vfio ];
then
        ls /dev/vfio/
else
        echo " Can't Run DPAA2 without VFIO support"
fi
