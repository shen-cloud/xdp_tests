#!/bin/bash
set -ex

sudo insmod /lib/modules/$(uname -r)/kernel/net/core/pktgen.ko || true
PRE=/proc/net/pktgen

BASE_IF=$1
START=$2
END=$3
DST_MAC=$4
DST_IP=$5

echo "Base interface name: $BASE_IF, DST_MAC=$DST_MAC, DST_IP=$DST_IP, Dev $START - $END"

for i in $(seq $START $END); do
	DEV=$PRE/kpktgend_$i
	IF=$PRE/$BASE_IF@$i
	SRC_PORT=$((10000+$i))
	echo "rem_device_all" > $DEV
	echo "add_device $BASE_IF@$i" > $DEV
	echo "count 0" > $IF
	echo "pkt_size 64" > $IF
	echo "ratep 10000000" > $IF
	echo "dst_min $DST_IP" > $IF
	echo "dst_mac $DST_MAC" > $IF
	echo "udp_src_min $SRC_PORT" > $IF
	echo "udp_src_max $SRC_PORT" > $IF
	echo "udp_dst_min 12345" > $IF
	echo "udp_dst_max 12345" > $IF
	echo "flag QUEUE_MAP_CPU" > $IF
done

