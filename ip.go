package main

import (
	"encoding/binary"
	"fmt"
)

const (
	IpHeaderLen = 20
)

// Parity with linux/in.h
type IpProto uint8

const (
	IpProtoIP       = 0   // Dummy protocol for TCP
	IpProtoICMP     = 1   // Internet Control Message Protocol
	IpProtoIGMP     = 2   // Internet Group Management Protocol
	IpProtoIPIP     = 4   // IPIP tunnels (older KA9Q tunnels use 94)
	IpProtoTCP      = 6   // Transmission Control Protocol
	IpProtoEGP      = 8   // Exterior Gateway Protocol
	IpProtoPUP      = 12  // PUP protocol
	IpProtoUDP      = 17  // User Datagram Protocol
	IpProtoIDP      = 22  // XNS IDP protocol
	IpProtoTP       = 29  // SO Transport Protocol Class 4
	IpProtoDCCP     = 33  // Datagram Congestion Control Protocol
	IpProtoIPV6     = 41  // IPv6-in-IPv4 tunnelling
	IpProtoRSVP     = 46  // RSVP Protocol
	IpProtoGRE      = 47  // Cisco GRE tunnels (rfc 1701,1702)
	IpProtoESP      = 50  // Encapsulation Security Payload protocol
	IpProtoAH       = 51  // Authentication Header protocol
	IpProtoMTP      = 92  // Multicast Transport Protocol
	IpProtoBEETPH   = 94  // IP option pseudo header for BEET
	IpProtoENCAP    = 98  // Encapsulation Header
	IpProtoPIM      = 103 // Protocol Independent Multicast
	IpProtoCOMP     = 108 // Compression Header Protocol
	IpProtoL2TP     = 115 // Layer 2 Tunnelling Protocol
	IpProtoSCTP     = 132 // Stream Control Transport Protocol
	IpProtoUDPLITE  = 136 // UDP-Lite (RFC 3828)
	IpProtoMPLS     = 137 // MPLS in IP (RFC 4023)
	IpProtoETHERNET = 143 // Ethernet-within-IPv6 Encapsulation
	IpProtoRAW      = 255 // Raw IP packets
	// Ignoring MPTCP and MAX
)

func (p IpProto) String() string {
	switch p {
	case IpProtoIP:
		return "IP"
	case IpProtoICMP:
		return "ICMP"
	case IpProtoIGMP:
		return "IGMP"
	case IpProtoIPIP:
		return "IPIP"
	case IpProtoTCP:
		return "TCP"
	case IpProtoEGP:
		return "EGP"
	case IpProtoPUP:
		return "PUP"
	case IpProtoUDP:
		return "UDP"
	case IpProtoIDP:
		return "IDP"
	case IpProtoTP:
		return "TP"
	case IpProtoDCCP:
		return "DCCP"
	case IpProtoIPV6:
		return "IPv6"
	case IpProtoRSVP:
		return "RSVP"
	case IpProtoGRE:
		return "GRE"
	case IpProtoESP:
		return "ESP"
	case IpProtoAH:
		return "AH"
	case IpProtoMTP:
		return "MTP"
	case IpProtoBEETPH:
		return "BEETPH"
	case IpProtoENCAP:
		return "ENCAP"
	case IpProtoPIM:
		return "PIM"
	case IpProtoCOMP:
		return "COMP"
	case IpProtoL2TP:
		return "L2TP"
	case IpProtoSCTP:
		return "SCTP"
	case IpProtoUDPLITE:
		return "UDPLite"
	case IpProtoMPLS:
		return "MPLS"
	case IpProtoETHERNET:
		return "ETHERNET"
	case IpProtoRAW:
		return "RAW"
	default:
		return fmt.Sprintf("0x%02x", uint8(p))
	}
}

// See linux/ip.h
type Iphdr struct {
	VersionIHL uint8 // 4 bits for Version, 4 bits for IHL
	TOS        uint8
	TotalLen   uint16
	ID         uint16
	FragOffset uint16
	TTL        uint8
	Proto      uint8
	Checksum   uint16
	SrcAddr    [4]byte
	DstAddr    [4]byte
}

func ReadIphdr(p []byte) (*Iphdr, int, error) {
	if len(p) < IpHeaderLen {
		return nil, 0, fmt.Errorf("expected at least %d bytes, got %d", IpHeaderLen, len(p))
	}
	hdr := &Iphdr{
		VersionIHL: p[0],
		TOS:        p[1],
		TotalLen:   binary.BigEndian.Uint16(p[2:4]),
		ID:         binary.BigEndian.Uint16(p[4:6]),
		FragOffset: binary.BigEndian.Uint16(p[6:8]),
		TTL:        p[8],
		Proto:      p[9],
		Checksum:   binary.BigEndian.Uint16(p[10:12]),
	}
	if hdr.Version() != 4 {
		return nil, 0, fmt.Errorf("iphdr: expected version==4, got %d (V+IHL=%02x)", hdr.Version(), hdr.VersionIHL)
	}
	if hdr.IHL() < 5 {
		return nil, 0, fmt.Errorf("expected IHL>=5, got %d", hdr.IHL())
	}

	copy(hdr.SrcAddr[:], p[12:16])
	copy(hdr.DstAddr[:], p[16:20])
	return hdr, IpHeaderLen, nil
}

func (i *Iphdr) Version() uint8 {
	return i.VersionIHL >> 4 & 0x0F
}

func (i *Iphdr) IHL() uint8 {
	return i.VersionIHL & 0x0F
}

func (i *Iphdr) String() string {
	return fmt.Sprintf("IPv4: Version=%d, IHL=%d, TOS=0x%02x, TotalLen=%d, ID=0x%04x, FragOffset=0x%04x, TTL=%d, Protocol=%d, Checksum=0x%04x, Src=%v, Dst=%v",
		i.VersionIHL>>4, i.VersionIHL&0x0F, i.TOS, i.TotalLen, i.ID, i.FragOffset,
		i.TTL, i.Proto, i.Checksum, i.SrcAddr, i.DstAddr)
}

// OptionBytes returns the number of Option bytes to read to finish parsing the IPv4 header.
func (i *Iphdr) OptionBytes() int {
	// IHL counts header sides in 4-byte words.
	// Since the default header size is 20 bytes, more than 5 means we have options to read.
	// Return
	return (int(i.IHL()) - 5) * 4
}
