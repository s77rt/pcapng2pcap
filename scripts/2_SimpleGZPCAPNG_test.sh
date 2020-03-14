#!/bin/bash
echo -n "Testing: Simple GZipped PCAPNG to PCAP "

eval $1 $2SimpleGZPCAPNG.pcapng.gz $3SimpleGZPCAPNG /dev/null 2>&1
md5=($(md5sum $3SimpleGZPCAPNG.1.pcap /dev/null 2>&1))

if [ $md5 == "7ddc946b644831528c1ec8e69bd68b18" ]; then
	echo "[OK]"
else
	echo "[NOT OK]"
	exit 1
fi