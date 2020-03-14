package main

import (
	"os"
	"log"
	"fmt"
	"strings"
	LZREADER "github.com/s77rt/pcapng2pcap/pkg/lzreader"
	PCAPNG "github.com/s77rt/pcapng2pcap/pkg/libpcapng"
)

var version = "dev"
var gitCommit = "n/a"

func print_help() {
	fmt.Print(
		"pcapng2pcap ", version, " (Git commit ", gitCommit, ")\n",
		"convert pcapng capture file to pcap.\n",
		"\n",
		"Usage:   pcapng2pcap <INPUT_FILENAME> <OUTPUT_PREFIX>\n",
		"\n",
		"Example: pcapng2pcap mycapture.pcapng mycapture\n",
		"         Will produce mycapture.1.pcap,\n",
		"                      mycapture.2.pcap,\n",
		"                             ...      \n",
		"                      mycapture.n.pcap\n",
		"         Where n is the number of section header blocks in mycapture.pcapng\n",
		"\n",
		"Limits:  PCAPNG BigEndian (Endianness) files are not supported\n",
		"         PCAPNG timestamps's resolutions that are different than 10^-6 are not supported\n",
		"\n",
		"MIT License\n",
		"Copyright (c) 2020 Abdelhafidh Belalia (s77rt) <admin@abdelhafidh.com>\n",
	)
}

func main() {
	// Parse Arguments
    if l := len(os.Args); l < 3 {
        print_help()
        if l == 1 {
        	os.Exit(0)
        } else {
        	os.Exit(1)
        }
    }
	// Open File (PCAPNG)
	pcapng_file_handler, err := os.Open(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	defer pcapng_file_handler.Close()

	// Read File (PCAPNG)
	pcapng_file := &LZREADER.FILE{pcapng_file_handler, []byte{}, []byte{}}
	if !strings.HasSuffix(strings.ToLower(os.Args[1]), ".gz") {
		pcapng_file.Load()
	} else {
		pcapng_file.LoadGZIP()
	}
	
	// Write File(s) (PCAP)
	PCAPNG.To_PCAP(pcapng_file, os.Args[2])
}
