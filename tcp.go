package main

import (
	"encoding/binary"
	"fmt"
)

const (
	TCPHeaderLen = 20
)

type TCPHeader struct {
	Source uint16
	Dest   uint16
	Seq    uint32
	AckSeq uint32
	// 4 bits of DataOffset, 4 bits Reserved
	DataOffsetRes uint8
	// CWR, ECE, URG, ACK, PSH, RST, SYNC, FIN
	Flags  uint8
	Window uint16
	Check  uint16
	// When URG flag is set
	UrgentPtr uint16
}

func ReadTCPHeader(p []byte) (*TCPHeader, int, error) {
	if len(p) < TCPHeaderLen {
		return nil, 0, fmt.Errorf("expected at least %d bytes, got %d", TCPHeaderLen, len(p))
	}
	hdr := &TCPHeader{
		Source:        binary.BigEndian.Uint16(p[0:2]),
		Dest:          binary.BigEndian.Uint16(p[2:4]),
		Seq:           binary.BigEndian.Uint32(p[4:8]),
		AckSeq:        binary.BigEndian.Uint32(p[8:12]),
		DataOffsetRes: p[12],
		Flags:         p[13],
		Window:        binary.BigEndian.Uint16(p[14:16]),
		Check:         binary.BigEndian.Uint16(p[16:18]),
		UrgentPtr:     binary.BigEndian.Uint16(p[18:20]),
	}
	if hdr.DataOffset() < 5 {
		return nil, 0, fmt.Errorf("expected data offset >=5, got %d", hdr.DataOffset())
	}
	return hdr, TCPHeaderLen, nil
}

func (h *TCPHeader) String() string {
	return fmt.Sprintf("Src:%d,Dst:%d,Seq:%d,AckSeq:%d,Offset:%d,Flags:%08b,Window:%d,Check:%d,UrgPtr:%04x",
		h.Source, h.Dest, h.Seq, h.AckSeq, h.DataOffset(), h.Flags, h.Window, h.Check, h.UrgentPtr)
}

//go:inline
func (h *TCPHeader) DataOffset() uint8 {
	return h.DataOffsetRes >> 4 & 0x0F
}

func (h *TCPHeader) OptionBytes() int {
	return (int(h.DataOffset()) - 5) * 4
}
