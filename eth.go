package main

import (
	"encoding/binary"
	"fmt"
)

const (
	// Length of an address
	EthAddrLen = 6
	// Length of EtherType
	EthTypeLen = 2
	// Length of a header
	EthHeaderLen = 14
)

type EtherType uint16

const (
	EtherTypeIPv4  EtherType = 0x0800 // IPv4 Protocol
	EtherTypeARP   EtherType = 0x0806 // ARP
	EtherType8021Q EtherType = 0x8100 // 802.1Q VLAN extended header
	EtherTypeIPv6  EtherType = 0x86DD // IPv6 Protocol
)

func (e EtherType) String() string {
	switch e {
	case EtherTypeIPv4:
		return "IPv4"
	case EtherTypeARP:
		return "ARP"
	case EtherTypeIPv6:
		return "IPv6"
	case EtherType8021Q:
		return "802.1Q"
	default:
		return fmt.Sprintf("0x%04x", uint16(e))
	}

}

// Ethhdr implements the header bytes of an ethernet frame.
// See linux/if_ether.h.
type Ethhdr struct {
	// h_dest: Destination eth address
	Dest [EthAddrLen]byte
	// h_source: Source eth address
	Source [EthAddrLen]byte
	// h_proto: EtherType
	Proto EtherType // BigEndian
}

// ReadEthhdr loads an ethhdr
func ReadEthhdr(p []byte) (*Ethhdr, int, error) {
	if len(p) < EthHeaderLen {
		return nil, 0, fmt.Errorf("expected at least %d bytes, got %d", EthHeaderLen, len(p))
	}
	e := &Ethhdr{}
	copy(e.Dest[:], p[:6])
	copy(e.Source[:], p[6:12])
	e.Proto = EtherType(binary.BigEndian.Uint16(p[12:14]))
	return e, EthHeaderLen, nil
}

func (e *Ethhdr) String() string {
	return fmt.Sprintf("Dst:%x,Src:%x,EtherType:%s", e.Dest, e.Source, e.Proto)
}
