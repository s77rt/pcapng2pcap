package libpcap

/*
Kept for ref/future use.
*/

import "encoding/binary"

/*
Convert from PCAP Struct Blocks to PCAP Bytes
*/
func (pcap_blocks *PCAP) To_Bytes(pcap_bytes *[]byte) {
	for _, b := range(pcap_blocks.Blocks) {
		Buff := make([]byte, 24)
		binary.LittleEndian.PutUint32(Buff[0:4], b.Global_Header.Magic_Number)
		binary.LittleEndian.PutUint16(Buff[4:6], b.Global_Header.Version_Major)
		binary.LittleEndian.PutUint16(Buff[6:8], b.Global_Header.Version_Minor)
		binary.LittleEndian.PutUint32(Buff[8:12], uint32(b.Global_Header.Thiszone))
		binary.LittleEndian.PutUint32(Buff[12:16], b.Global_Header.Sigfigs)
		binary.LittleEndian.PutUint32(Buff[16:20], b.Global_Header.SnapLen)
		binary.LittleEndian.PutUint32(Buff[20:24], b.Global_Header.Network)
		*pcap_bytes = append(*pcap_bytes, Buff...)
		for _, p := range(b.Packet) {
			Buff := make([]byte, 16)
			binary.LittleEndian.PutUint32(Buff[0:4], p.Packet_Header.TS_Sec)
			binary.LittleEndian.PutUint32(Buff[4:8], p.Packet_Header.TS_uSec)
			binary.LittleEndian.PutUint32(Buff[8:12], p.Packet_Header.Incl_Len)
			binary.LittleEndian.PutUint32(Buff[12:16], p.Packet_Header.Orig_Len)
			*pcap_bytes = append(*pcap_bytes, Buff...)
			*pcap_bytes = append(*pcap_bytes, p.Packet_Data...)
		}
	}
}
