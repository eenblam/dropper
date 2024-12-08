package main

import (
	"fmt"
)

type Layers struct {
	Eth         *Ethhdr
	IPv4        *Iphdr
	IPv4Options []byte
	TCP         *TCPHeader
	TCPOptions  []byte
	UDP         *UDPHeader
}

func ReadLayers(p []byte) (*Layers, int, error) {
	var (
		total int
		n     int
		err   error
	)
	ls := &Layers{}
	ls.Eth, n, err = ReadEthhdr(p)
	if err != nil {
		return nil, n, err
	}
	total += n
	p = p[n:]

	switch ls.Eth.Proto {
	case EtherTypeIPv4:
		ls.IPv4, n, err = ReadIphdr(p)
		if err != nil {
			return nil, total, err
		}
		total += n
		p = p[n:]
		if o := ls.IPv4.OptionBytes(); o > 0 {
			if o > len(p) {
				return nil, total, fmt.Errorf("encountered IHL of %d but only %d bytes available after initial IPv4 header",
					ls.IPv4.IHL(), len(p))
			}
			ls.IPv4Options = append(ls.IPv4Options, p[:o]...)
			total += o
			p = p[o:]
		}

		// Parse transport layer
		switch ls.IPv4.Proto {
		case IpProtoTCP:
			ls.TCP, n, err = ReadTCPHeader(p)
			total += n
			p = p[n:]
			if err != nil {
				return nil, total, fmt.Errorf("failed to parse UDP header: %w", err)
			}
			if o := ls.TCP.OptionBytes(); o > 0 {
				if o > len(p) {
					return nil, total, fmt.Errorf("encountered DataOffset of %d but only %d bytes available after initial TCP header",
						ls.TCP.DataOffset(), len(p))
				}
				ls.TCPOptions = append(ls.TCPOptions, p[:o]...)
				total += o
				p = p[o:]
			}
		case IpProtoUDP:
			ls.UDP, n, err = ReadUDPHeader(p)
			total += n
			if err != nil {
				return nil, total, fmt.Errorf("failed to parse UDP header: %w", err)
			}
		default:
			return nil, total, fmt.Errorf("unsupported value for IPv4 Protocol field: %v", ls.IPv4.Proto)
		}
	//TODO case EtherTypeIPv6:
	default:
		return nil, total, fmt.Errorf("unsupported EtherType: %v", ls.Eth.Proto)
	}

	return ls, total, nil
}
