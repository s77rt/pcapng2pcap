#!/bin/bash
echo -n "Testing: Complex PCAPNG to PCAP "

eval $1 $2ComplexPCAPNG.pcapng $3ComplexPCAPNG /dev/null 2>&1
md5=($(md5sum $3ComplexPCAPNG.1.pcap /dev/null 2>&1))
md5_2=($(md5sum $3ComplexPCAPNG.2.pcap /dev/null 2>&1))

if [[ $md5 == "7ddc946b644831528c1ec8e69bd68b18" && $md5_2 == "7ddc946b644831528c1ec8e69bd68b18" ]]; then
	echo "[OK]"
else
	echo "[NOT OK]"
	exit 1
fi