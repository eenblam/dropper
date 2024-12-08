package main

import (
	"encoding/binary"
	"fmt"
)

const (
	UDPHeaderLen = 8
)

// See linux/udp.h
type UDPHeader struct {
	Source uint16
	Dest   uint16
	Len    uint16
	// May be 0, since it's optional in IPv4
	Check uint16
}

func ReadUDPHeader(p []byte) (*UDPHeader, int, error) {
	if len(p) < UDPHeaderLen {
		return nil, 0, fmt.Errorf("expected at least %d bytes, got %d", UDPHeaderLen, len(p))
	}
	// Can't check the checksum here since we also need the IPv4/6 pseudoheader to do so.
	return &UDPHeader{
		Source: binary.BigEndian.Uint16(p[0:2]),
		Dest:   binary.BigEndian.Uint16(p[2:4]),
		Len:    binary.BigEndian.Uint16(p[4:6]),
		Check:  binary.BigEndian.Uint16(p[6:8]),
	}, UDPHeaderLen, nil
}

func (u *UDPHeader) String() string {
	return fmt.Sprintf("Dst:%d,Src:%d,Len:%d,Check:%04x", u.Source, u.Dest, u.Len, u.Check)
}
