#!/bin/bash
echo -n "Testing: Complex GZipped PCAPNG to PCAP "

eval $1 $2ComplexGZPCAPNG.pcapng.gz $3ComplexGZPCAPNG /dev/null 2>&1
md5=($(md5sum $3ComplexGZPCAPNG.1.pcap /dev/null 2>&1))
md5_2=($(md5sum $3ComplexGZPCAPNG.2.pcap /dev/null 2>&1))

if [[ $md5 == "7ddc946b644831528c1ec8e69bd68b18" && $md5_2 == "7ddc946b644831528c1ec8e69bd68b18" ]]; then
	echo "[OK]"
else
	echo "[NOT OK]"
	exit 1
fi