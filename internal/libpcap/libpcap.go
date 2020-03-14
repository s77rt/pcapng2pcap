package libpcap

const (
	Magic_Number = 0xA1B2C3D4
	Version_Major = 0x02
	Version_Minor = 0x04
	Thiszone = 0x00
	Sigfigs = 0x00
)

// Little Endian Bytes Representation for:
// Magic_Number
// Version_Major
// Version_Minor
// Thiszone
// Sigfigs
var Global_Header_15_LE = []byte{212, 195, 178, 161, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0}

type PCAP struct {
	Blocks []Logical_Block_Hierarchy
}

type Logical_Block_Hierarchy struct {
	Global_Header Global_Header
	Packet []Packet
}

type Global_Header struct {
	Magic_Number uint32
	Version_Major uint16
	Version_Minor uint16
	Thiszone int32
	Sigfigs uint32
	SnapLen uint32
	Network uint32
}

type Packet struct {
	Packet_Header Packet_Header
	Packet_Data []byte
}

type Packet_Header struct {
	TS_Sec uint32
	TS_uSec uint32
	Incl_Len uint32
	Orig_Len uint32
}
