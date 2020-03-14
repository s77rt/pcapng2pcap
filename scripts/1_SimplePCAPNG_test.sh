#!/bin/bash
echo -n "Testing: Simple PCAPNG to PCAP "

eval $1 $2SimplePCAPNG.pcapng $3SimplePCAPNG /dev/null 2>&1
md5=($(md5sum $3SimplePCAPNG.1.pcap /dev/null 2>&1))

if [ $md5 == "7ddc946b644831528c1ec8e69bd68b18" ]; then
	echo "[OK]"
else
	echo "[NOT OK]"
	exit 1
fi