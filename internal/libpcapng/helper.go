package libpcapng

import (
	"encoding/binary"
)

func (GBS *General_Block_Structure) read_Section_Header_Block(SH *Section_Header) {
	*SH = Section_Header{
		Block_Type: GBS.Block_Type,
		Block_Total_Length: GBS.Block_Total_Length,
		ByteOrder_Magic: binary.LittleEndian.Uint32(GBS.Block_Body[:4]),
		Major_Version: binary.LittleEndian.Uint16(GBS.Block_Body[4:6]),
		Minor_Version: binary.LittleEndian.Uint16(GBS.Block_Body[6:8]),
		Section_Length: binary.LittleEndian.Uint64(GBS.Block_Body[8:16]),
		// Options
		Block_Total_Length_2: GBS.Block_Total_Length_2,
	}
	// Options
	read_Options(GBS.Block_Body[16:], &SH.Options)
}

func (GBS *General_Block_Structure) read_Interface_Description_Block(ID *Interface_Description) {
	*ID = Interface_Description{
		Block_Type: GBS.Block_Type,
		Block_Total_Length: GBS.Block_Total_Length,
		LinkType: binary.LittleEndian.Uint16(GBS.Block_Body[:2]),
		Reserved: binary.LittleEndian.Uint16(GBS.Block_Body[2:4]),
		SnapLen: binary.LittleEndian.Uint32(GBS.Block_Body[4:8]),
		// Options
		Block_Total_Length_2: GBS.Block_Total_Length_2,
	}
	// Options
	read_Options(GBS.Block_Body[8:], &ID.Options)
}

func (GBS *General_Block_Structure) read_Simple_Packet_Block(SP *Simple_Packet) {
	*SP = Simple_Packet{
		Block_Type: GBS.Block_Type,
		Block_Total_Length: GBS.Block_Total_Length,
		Original_Packet_Length: binary.LittleEndian.Uint32(GBS.Block_Body[:4]),
		// Packet_Data
		Block_Total_Length_2: GBS.Block_Total_Length_2,
	}
	// Packet_Data
	// Padding to 32 bits (4 bytes)
	Captured_Packet_Length := SP.Block_Total_Length-16 // (4+4+4+4)
	var LengthPadded int
	if Captured_Packet_Length == 0 {
		LengthPadded = 4
	} else {
		LengthPadded = int(Captured_Packet_Length + (-Captured_Packet_Length%4))
	}
	SP.Packet_Data = GBS.Block_Body[4:4+LengthPadded]
}

func (GBS *General_Block_Structure) read_Enhanced_Packet_Block(EP *Enhanced_Packet) {
	*EP = Enhanced_Packet{
		Block_Type: GBS.Block_Type,
		Block_Total_Length: GBS.Block_Total_Length,
		Interface_ID: binary.LittleEndian.Uint32(GBS.Block_Body[:4]),
		Timestamp_High: binary.LittleEndian.Uint32(GBS.Block_Body[4:8]),
		Timestamp_Low: binary.LittleEndian.Uint32(GBS.Block_Body[8:12]),
		Captured_Packet_Length: binary.LittleEndian.Uint32(GBS.Block_Body[12:16]),
		Original_Packet_Length: binary.LittleEndian.Uint32(GBS.Block_Body[16:20]),
		// Packet_Data
		// Options
		Block_Total_Length_2: GBS.Block_Total_Length_2,
	}
	// Packet_Data
	// Padding to 32 bits (4 bytes)
	var LengthPadded int

	if EP.Captured_Packet_Length == 0 {
		LengthPadded = 4
	} else {
		LengthPadded = int(EP.Captured_Packet_Length + (-EP.Captured_Packet_Length%4))
	}
	EP.Packet_Data = GBS.Block_Body[20:20+LengthPadded]

	// Options
	read_Options(GBS.Block_Body[20+LengthPadded:], &EP.Options)
}

func (GBS *General_Block_Structure) read_Interface_Statistics_Block(IS *Interface_Statistics) {
	*IS = Interface_Statistics{
		Block_Type: GBS.Block_Type,
		Block_Total_Length: GBS.Block_Total_Length,
		Interface_ID: binary.LittleEndian.Uint32(GBS.Block_Body[:4]),
		Timestamp_High: binary.LittleEndian.Uint32(GBS.Block_Body[4:8]),
		Timestamp_Low: binary.LittleEndian.Uint32(GBS.Block_Body[8:12]),
		// Options
		Block_Total_Length_2: GBS.Block_Total_Length_2,
	}
	// Options
	read_Options(GBS.Block_Body[12:], &IS.Options)
}

func (GBS *General_Block_Structure) read_Name_Resolution_Block(NR *Name_Resolution) {
	*NR = Name_Resolution{
		Block_Type: GBS.Block_Type,
		Block_Total_Length: GBS.Block_Total_Length,
		// Records
		// Options
		Block_Total_Length_2: GBS.Block_Total_Length_2,
	}
	// Records and Options
	read_Records_and_Options(GBS.Block_Body, &NR.Records, &NR.Options)
}

func read_Options(options_data []byte, options *[]Option) {
	for {
		// If the option_data is less than 8 bytes, break; because an option is at least 8 bytes (2 2 4)
		if len(options_data) < 8 {
			break
		}

		// Option
		option := Option{
			Code: binary.LittleEndian.Uint16(options_data[:2]),
			Length: binary.LittleEndian.Uint16(options_data[2:4]),
			// Value
		}

		// Value
		// Padding to 32 bits (4 bytes)
		var LengthPadded int
		if option.Length == 0 {
			LengthPadded = 4
		} else {
			LengthPadded = int(option.Length + (-option.Length%4))
		}
		option.Value = options_data[4:4+LengthPadded]

		// Append the option to our options
		*options = append(*options, option)

		// If this is the last option than break, else cut the option_data for the next iteration
		if option.Code == opt_endofopt {
			break
		} else {
			options_data = options_data[4+LengthPadded:]
		}
	}
}

func read_Records(records_data []byte, records *[]Record) {
	for {
		// If the record_data is less than 8 bytes, break; because an record is at least 8 bytes (2 2 4)
		if len(records_data) < 8 {
			break
		}

		// Record
		record := Record{
			Type: binary.LittleEndian.Uint16(records_data[:2]),
			Length: binary.LittleEndian.Uint16(records_data[2:4]),
			// Value
		}

		// Value
		// Padding to 32 bits (4 bytes)
		var LengthPadded int
		if record.Length == 0 {
			LengthPadded = 4
		} else {
			LengthPadded = int(record.Length + (-record.Length%4))
		}
		record.Value = records_data[4:4+LengthPadded]

		// Append the record to our records
		*records = append(*records, record)

		// If this is the last record than break, else cut the record_data for the next iteration
		if record.Type == nrb_record_end {
			break
		} else {
			records_data = records_data[4+LengthPadded:]
		}
	}
}

func read_Records_and_Options(records_or_options_data []byte, records *[]Record, options *[]Option) {
	var still_records = true
	for {
		// If the record_or_option_data is less than 8 bytes, break; because an record_or_option is at least 8 bytes (2 2 4)
		if len(records_or_options_data) < 8 {
			break
		}

		// At first we would have records than options, thus we parse the records first
		// After the last record (nrb_record_end) we parse the options till the end (opt_endofopt)
		if still_records {
			// Record
			record := Record{
				Type: binary.LittleEndian.Uint16(records_or_options_data[:2]),
				Length: binary.LittleEndian.Uint16(records_or_options_data[2:4]),
				// Value
			}

			// Value
			// Padding to 32 bits (4 bytes)
			var LengthPadded int
			if record.Length == 0 {
				LengthPadded = 4
			} else {
				LengthPadded = int(record.Length + (-record.Length%4))
			}
			record.Value = records_or_options_data[4:4+LengthPadded]

			// Append the record to our records
			*records = append(*records, record)

			// If this is the last record than the next iteration is going for options
			if record.Type == nrb_record_end {
				still_records = false
			}

			// Cut the records_or_options_data for the next iteration
			records_or_options_data = records_or_options_data[4+LengthPadded:]
		} else {
			// Option
			option := Option{
				Code: binary.LittleEndian.Uint16(records_or_options_data[:2]),
				Length: binary.LittleEndian.Uint16(records_or_options_data[2:4]),
				// Value
			}

			// Value
			// Padding to 32 bits (4 bytes)
			var LengthPadded int
			if option.Length == 0 {
				LengthPadded = 4
			} else {
				LengthPadded = int(option.Length + (-option.Length%4))
			}
			option.Value = records_or_options_data[4:4+LengthPadded]

			// Append the option to our options
			*options = append(*options, option)

			// If this is the last option than break, else cut the records_or_options_data for the next iteration
			if option.Code == opt_endofopt {
				break
			} else {
				records_or_options_data = records_or_options_data[4+LengthPadded:]
			}
		}
	}
}
