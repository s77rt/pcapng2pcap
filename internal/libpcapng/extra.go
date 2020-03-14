package libpcapng

/*
Kept for ref/future use.
*/

import (
	"encoding/binary"
	LZREADER "github.com/s77rt/pcapng2pcap/pkg/lzreader"
	// PCAP "github.com/s77rt/pcapng2pcap/internal/libpcap"
)

/*
Read pcapng file in binary to struct blocks
*/
func Read_Blocks(pcapng_file *LZREADER.FILE, pcapng_blocks *PCAPNG) {
	// For easy append, we store the addresses of the main structs (structs that holds other []structs) in variables (pointers)
	// Example: If an enhanced packet is found, we append directly to current_I.Enhanced_Packet instead of looking for it's parent
	// We assume that all the structs respects the Logical_Block_Hierarchy
	// TODO: Write a better explanation.
	var current_LBH = &Logical_Block_Hierarchy{}
	var current_I = &Interface{}

	for {
		// Try to read 8 bytes (Block_Type and Block_Total_Length)
		if err := pcapng_file.Read(8); err != nil {
			break
		}

		// General_Block_Structure
		var GBS = General_Block_Structure{
			Block_Type: binary.LittleEndian.Uint32(pcapng_file.Buff[:4]),
			Block_Total_Length: binary.LittleEndian.Uint32(pcapng_file.Buff[4:8]),
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
		GBS.Block_Total_Length_2 = binary.LittleEndian.Uint32(pcapng_file.Buff[:])

		// Act based on the block type
		switch GBS.Block_Type {
		case Section_Header_Block:
			var SH = Section_Header{}
			GBS.read_Section_Header_Block(&SH)

			// New Logical_Block_Hierarchy
			var LBH = Logical_Block_Hierarchy{}
			LBH.Section_Header = SH
			pcapng_blocks.Blocks = append(pcapng_blocks.Blocks, LBH)

			// Set current_LBH
			current_LBH = &pcapng_blocks.Blocks[len(pcapng_blocks.Blocks) - 1]

		case Interface_Description_Block:
			var ID = Interface_Description{}
			GBS.read_Interface_Description_Block(&ID)

			// New Interface
			var I = Interface{}
			I.Interface_Description = ID
			current_LBH.Interface = append(current_LBH.Interface, I)

			// Set current_I
			current_I = &current_LBH.Interface[len(current_LBH.Interface) - 1]

		case Simple_Packet_Block:
			var SP = Simple_Packet{}
			GBS.read_Simple_Packet_Block(&SP)

			// Append to the current interface
			current_I.Simple_Packet = append(current_I.Simple_Packet, SP)
		
		case Enhanced_Packet_Block:
			var EP = Enhanced_Packet{}
			GBS.read_Enhanced_Packet_Block(&EP)

			// Append to the current interface
			current_I.Enhanced_Packet = append(current_I.Enhanced_Packet, EP)

		case Interface_Statistics_Block:
			var IS = Interface_Statistics{}
			GBS.read_Interface_Statistics_Block(&IS)

			// Append to the current interface
			current_I.Interface_Statistics = IS

		case Name_Resolution_Block:
			var NR = Name_Resolution{}
			GBS.read_Name_Resolution_Block(&NR)

			// // Append to the current logical block hierarchy
			current_LBH.Name_Resolution = NR
		}
	}
}

/*
Convert from PCAPNG Struct Blocks to PCAP Struct Blocks
*/
/*
func (pcapng_blocks *PCAPNG) Convert_To_PCAP(pcap_blocks *PCAP.PCAP) {
	for _, b := range(pcapng_blocks.Blocks) {
		for _, i := range(b.Interface) {
			var block = PCAP.Logical_Block_Hierarchy{
				PCAP.Global_Header{
					PCAP.Magic_Number,
					PCAP.Version_Major,
					PCAP.Version_Minor,
					PCAP.Thiszone,
					PCAP.Sigfigs,
					i.Interface_Description.SnapLen,
					uint32(i.Interface_Description.LinkType),
				},
				[]PCAP.Packet{},
			}
			for _, p := range(i.Enhanced_Packet) {
				block.Packet = append(block.Packet, PCAP.Packet{
					PCAP.Packet_Header{
						p.Timestamp_High, // TODO: Fix timestamp
						p.Timestamp_Low, // TODO: Fix timestamp
						p.Captured_Packet_Length,
						p.Original_Packet_Length,
					},
					p.Packet_Data[:p.Captured_Packet_Length], // Limit to Captured_Packet_Length. pcap does not use any byte alignment (specifically it does not use 4 bytes alignment as pcapng), thus copy only the data.
				})
			}
			pcap_blocks.Blocks = append(pcap_blocks.Blocks, block)
		}
	}
}
*/

/*
Convert from PCAPNG Struct Blocks to PCAP Bytes
*/
/*
func (pcapng_blocks *PCAPNG) Convert_To_PCAP_Bytes(pcap_bytes *[]byte) {
	for _, b := range(pcapng_blocks.Blocks) {
		for _, i := range(b.Interface) {
			Buff := make([]byte, 24)
			binary.LittleEndian.PutUint32(Buff[0:4], PCAP.Magic_Number)
			binary.LittleEndian.PutUint16(Buff[4:6], PCAP.Version_Major)
			binary.LittleEndian.PutUint16(Buff[6:8], PCAP.Version_Minor)
			binary.LittleEndian.PutUint32(Buff[8:12], uint32(PCAP.Thiszone))
			binary.LittleEndian.PutUint32(Buff[12:16], PCAP.Sigfigs)
			binary.LittleEndian.PutUint32(Buff[16:20], i.Interface_Description.SnapLen)
			binary.LittleEndian.PutUint32(Buff[20:24], uint32(i.Interface_Description.LinkType))
			*pcap_bytes = append(*pcap_bytes, Buff...)
			for _, p := range(i.Enhanced_Packet) {
				Buff := make([]byte, 16)
				binary.LittleEndian.PutUint32(Buff[0:4], p.Timestamp_High) // TODO: Fix timestamp
				binary.LittleEndian.PutUint32(Buff[4:8], p.Timestamp_Low) // TODO: Fix timestamp
				binary.LittleEndian.PutUint32(Buff[8:12], p.Captured_Packet_Length)
				binary.LittleEndian.PutUint32(Buff[12:16], p.Original_Packet_Length)
				*pcap_bytes = append(*pcap_bytes, Buff...)
				*pcap_bytes = append(*pcap_bytes, p.Packet_Data[:p.Captured_Packet_Length]...) // Limit to Captured_Packet_Length. pcap does not use any byte alignment (specifically it does not use 4 bytes alignment as pcapng), thus copy only the data.
			}
		}
	}
}
*/
