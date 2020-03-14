package libpcapng

import (
	"os"
	"log"
	"bufio"
	"fmt"
	LZREADER "github.com/s77rt/pcapng2pcap/pkg/lzreader"
	PCAP "github.com/s77rt/pcapng2pcap/pkg/libpcap"
)

const (
	// https://pcapng.github.io/pcapng/#section_block_code_registry
	Interface_Description_Block = 0x00000001
	Packet_Block                = 0x00000002
	Simple_Packet_Block         = 0x00000003
	Name_Resolution_Block       = 0x00000004
	Interface_Statistics_Block  = 0x00000005
	Enhanced_Packet_Block       = 0x00000006
	IRIG_Timestamp_Block        = 0x00000007
	ARINC_429_in_AFDX_Encapsulation_Information_Block = 0x00000008
	Custom_Block                = 0x00000BAD
	Section_Header_Block        = 0x0A0D0D0A

	opt_endofopt = 0
	nrb_record_end = 0x0000
	if_tsresol_code = 9
)

type PCAPNG struct {
	Blocks []Logical_Block_Hierarchy
}

type General_Block_Structure struct {
/*
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Block Type                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Block Total Length                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                          Block Body                           /
/              variable length, padded to 32 bits               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Block Total Length                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
	Block_Type uint32
	Block_Total_Length uint32
	Block_Body []byte
	Block_Total_Length_2 uint32
}

type Logical_Block_Hierarchy struct {
/*
	Section Header
	|
	+- Interface Description         (Interface)
	|  +- Simple Packet              (Interface)
	|  +- Enhanced Packet            (Interface)
	|  +- Interface Statistics       (Interface)
	|
	+- Name Resolution
*/
	Section_Header Section_Header
	Interface []Interface
	Name_Resolution Name_Resolution
}

type Interface struct {
	Interface_Description Interface_Description
	Simple_Packet []Simple_Packet
	Enhanced_Packet []Enhanced_Packet
	Interface_Statistics Interface_Statistics
}

type Section_Header struct {
/*
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +---------------------------------------------------------------+
 0 |                   Block Type = 0x0A0D0D0A                     |
   +---------------------------------------------------------------+
 4 |                      Block Total Length                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 8 |                      Byte-Order Magic                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
12 |          Major Version        |         Minor Version         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
16 |                                                               |
   |                          Section Length                       |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
24 /                                                               /
   /                      Options (variable)                       /
   /                                                               /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Block Total Length                       |
   +---------------------------------------------------------------+
*/
	Block_Type uint32
	Block_Total_Length uint32
	ByteOrder_Magic uint32
	Major_Version, Minor_Version uint16
	Section_Length uint64
	Options []Option
	Block_Total_Length_2 uint32
}

type Interface_Description struct {
/*
	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +---------------------------------------------------------------+
 0 |                    Block Type = 0x00000001                    |
   +---------------------------------------------------------------+
 4 |                      Block Total Length                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 8 |           LinkType            |           Reserved            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
12 |                            SnapLen                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
16 /                                                               /
   /                      Options (variable)                       /
   /                                                               /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Block Total Length                       |
   +---------------------------------------------------------------+
*/
	Block_Type uint32
	Block_Total_Length uint32
	LinkType, Reserved uint16
	SnapLen uint32
	Options []Option
	Block_Total_Length_2 uint32
}

type Simple_Packet struct {
/*
	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +---------------------------------------------------------------+
 0 |                    Block Type = 0x00000003                    |
   +---------------------------------------------------------------+
 4 |                      Block Total Length                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 8 |                    Original Packet Length                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
12 /                                                               /
   /                          Packet Data                          /
   /              variable length, padded to 32 bits               /
   /                                                               /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Block Total Length                       |
   +---------------------------------------------------------------+
*/
	Block_Type uint32
	Block_Total_Length uint32
	Original_Packet_Length uint32
	Packet_Data []byte
	Block_Total_Length_2 uint32
}

type Enhanced_Packet struct {
/*
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +---------------------------------------------------------------+
 0 |                    Block Type = 0x00000006                    |
   +---------------------------------------------------------------+
 4 |                      Block Total Length                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 8 |                         Interface ID                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
12 |                        Timestamp (High)                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
16 |                        Timestamp (Low)                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
20 |                    Captured Packet Length                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
24 |                    Original Packet Length                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
28 /                                                               /
   /                          Packet Data                          /
   /              variable length, padded to 32 bits               /
   /                                                               /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                                                               /
   /                      Options (variable)                       /
   /                                                               /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Block Total Length                       |
   +---------------------------------------------------------------+
*/
	Block_Type uint32
	Block_Total_Length uint32
	Interface_ID uint32
	Timestamp_High uint32
	Timestamp_Low uint32
	Captured_Packet_Length uint32
	Original_Packet_Length uint32
	Packet_Data []byte
	Options []Option
	Block_Total_Length_2 uint32
}

type Interface_Statistics struct {
/*
	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +---------------------------------------------------------------+
 0 |                   Block Type = 0x00000005                     |
   +---------------------------------------------------------------+
 4 |                      Block Total Length                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 8 |                         Interface ID                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
12 |                        Timestamp (High)                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
16 |                        Timestamp (Low)                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
20 /                                                               /
   /                      Options (variable)                       /
   /                                                               /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Block Total Length                       |
   +---------------------------------------------------------------+
*/
	Block_Type uint32
	Block_Total_Length uint32
	Interface_ID uint32
	Timestamp_High uint32
	Timestamp_Low uint32
	Options []Option
	Block_Total_Length_2 uint32
}

type Name_Resolution struct {
/*
	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +---------------------------------------------------------------+
 0 |                    Block Type = 0x00000004                    |
   +---------------------------------------------------------------+
 4 |                      Block Total Length                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 8 /                                                               /
   /                      Records (variable)                       /
   /                                                               /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                                                               /
   /                      Options (variable)                       /
   /                                                               /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Block Total Length                       |
   +---------------------------------------------------------------+
*/
	Block_Type uint32
	Block_Total_Length uint32
	Records []Record
	Options []Option
	Block_Total_Length_2 uint32
}

type Option struct {
/*
	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      Option Code              |         Option Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                       Option Value                            /
   /              variable length, padded to 32 bits               /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                                                               /
   /                 . . . other options . . .                     /
   /                                                               /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Option Code == opt_endofopt  |  Option Length == 0          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/	
	Code uint16
	Length uint16
	Value []byte
}

type Record struct {
/*
	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      Record Type              |      Record Value Length      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                       Record Value                            /
   /              variable length, padded to 32 bits               /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                                                               /
   /                  . . . other records . . .                    /
   /                                                               /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Record Type = nrb_record_end |   Record Value Length = 0     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
	Type uint16
	Length uint16
	Value []byte
}

// ^_^ ^_^ ^_^ ^_^ ^_^ ^_^ ^_^ ^_^ ^_^ ^_^ ^_^ ^_^ ^_^ ^_^ ^_^ ^_^ ^_^ ^_^ ^_^ ^_^ ^_^ \\

/*
Read pcapng file in binary and write to PCAP (2in1)
*/
func To_PCAP(pcapng_file *LZREADER.FILE, pcap_filename_prefix string) {
	var writer *bufio.Writer
	pcap_file_count := 0
	for {
		// Try to read 8 bytes (Block_Type and Block_Total_Length)
		if err := pcapng_file.Read(8); err != nil {
			break
		}

		// General_Block_Structure
		var GBS = General_Block_Structure{
			Block_Type: (uint32(pcapng_file.Buff[0]) | uint32(pcapng_file.Buff[1])<<8 | uint32(pcapng_file.Buff[2])<<16 | uint32(pcapng_file.Buff[3])<<24),
			Block_Total_Length: (uint32(pcapng_file.Buff[4]) | uint32(pcapng_file.Buff[5])<<8 | uint32(pcapng_file.Buff[6])<<16 | uint32(pcapng_file.Buff[7])<<24),
			// Block_Body
			// Block_Total_Length_2
		}

		// Block_Body
		pcapng_file.Read(int64(GBS.Block_Total_Length)-12) // Length of Block_Body = Block_Total_Length - (SizeOf(Block_Type)+SizeOf(Block_Total_Length)+SizeOf(Block_Total_Length_2))
		GBS.Block_Body = pcapng_file.Buff[:]
		// Padding to 32 bits (4 bytes)
		if len(GBS.Block_Body) == 0 {
			pcapng_file.Read(4)
			GBS.Block_Body = pcapng_file.Buff[:]
		} else {
			pcapng_file.Read(int64(-len(GBS.Block_Body)%4))
			GBS.Block_Body = append(GBS.Block_Body, pcapng_file.Buff[:]...)
		}
		// Block_Total_Length_2
		pcapng_file.Read(4)
		GBS.Block_Total_Length_2 = uint32(pcapng_file.Buff[0]) | uint32(pcapng_file.Buff[1])<<8 | uint32(pcapng_file.Buff[2])<<16 | uint32(pcapng_file.Buff[3])<<24

		// Act based on the block type
		switch GBS.Block_Type {
		case Section_Header_Block:
			// Make sure to write everything we have for the current pcap file before moving to a new one
			if writer != nil {
				if err := writer.Flush(); err != nil {
					log.Fatal(err)
				}
			}
			pcap_file_count++

			// New PCAP File
			output_pcap_filename := fmt.Sprintf("%s.%d.pcap", pcap_filename_prefix, pcap_file_count)
			output_pcap_file, err := os.Create(output_pcap_filename)
			defer output_pcap_file.Close()
			if err != nil {
				log.Fatal(err)
			}
			writer = bufio.NewWriter(output_pcap_file)

			// Write
			writer.Write(PCAP.Global_Header_15_LE) // Refer to libpcap/libpcap.go

		case Interface_Description_Block:
			// Check timestamps's resolution
			var options []Option
			read_Options(GBS.Block_Body[8:], &options)
			for _, option := range(options) {
				if option.Code == if_tsresol_code {
					if option.Value[0] != byte(6) {
						fmt.Println(
							"WARNING: Unsupported timestamps's resolution (if_tsresol != 6).",
							"This may result in incorrect timestamps",
						)
					}
					break
				}
			}

			// Write
			writer.Write([]byte{
				GBS.Block_Body[4], GBS.Block_Body[5], GBS.Block_Body[6], GBS.Block_Body[7], // SnapLen
				GBS.Block_Body[0], GBS.Block_Body[1], // LinkType
				0, 0, // LinkType in pcap is 4 bytes, and the line above will write only 2 bytes (bcz pcapng uses 2 bytes only)
			})

		case Enhanced_Packet_Block:
			// Convert the 64bit timestamp (high + low) into two 32bit timestamps (sec, usec)
			timestamp := uint64(GBS.Block_Body[8]) | uint64(GBS.Block_Body[9])<<8 | uint64(GBS.Block_Body[10])<<16 | uint64(GBS.Block_Body[11])<<24 | uint64(GBS.Block_Body[4])<<32 | uint64(GBS.Block_Body[5])<<40 | uint64(GBS.Block_Body[6])<<48 | uint64(GBS.Block_Body[7])<<56
			timestamp_sec, timestamp_usec := uint32(timestamp/1000000), uint32(timestamp%1000000)

			// Write
			writer.Write([]byte{
				byte(timestamp_sec), byte(timestamp_sec >> 8), byte(timestamp_sec >> 16), byte(timestamp_sec >> 24), // TS_Sec
				byte(timestamp_usec), byte(timestamp_usec >> 8), byte(timestamp_usec >> 16), byte(timestamp_usec >> 24), // TS_uSec
			})
			writer.Write(GBS.Block_Body[12:20+(uint32(GBS.Block_Body[12]) | uint32(GBS.Block_Body[13])<<8 | uint32(GBS.Block_Body[14])<<16 | uint32(GBS.Block_Body[15])<<24)]) // Incl_Len, Orig_Len, Packet_Data (Limited to Incl_Len)
		}
	}
	if err := writer.Flush(); err != nil {
		log.Fatal(err)
	}
}
