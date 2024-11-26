// Code generated by bpf2go; DO NOT EDIT.
//go:build mips || mips64 || ppc64 || s390x

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type dropperIpv4LpmKey struct {
	Prefixlen uint32
	Data      uint32
}

// loadDropper returns the embedded CollectionSpec for dropper.
func loadDropper() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_DropperBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load dropper: %w", err)
	}

	return spec, err
}

// loadDropperObjects loads dropper and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*dropperObjects
//	*dropperPrograms
//	*dropperMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadDropperObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadDropper()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// dropperSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type dropperSpecs struct {
	dropperProgramSpecs
	dropperMapSpecs
}

// dropperSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type dropperProgramSpecs struct {
	DropPacketsByIp *ebpf.ProgramSpec `ebpf:"drop_packets_by_ip"`
	GetStats        *ebpf.ProgramSpec `ebpf:"get_stats"`
}

// dropperMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type dropperMapSpecs struct {
	DropStatsMap *ebpf.MapSpec `ebpf:"drop_stats_map"`
	Ipv4LpmTrie  *ebpf.MapSpec `ebpf:"ipv4_lpm_trie"`
	JmpTable     *ebpf.MapSpec `ebpf:"jmp_table"`
}

// dropperObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadDropperObjects or ebpf.CollectionSpec.LoadAndAssign.
type dropperObjects struct {
	dropperPrograms
	dropperMaps
}

func (o *dropperObjects) Close() error {
	return _DropperClose(
		&o.dropperPrograms,
		&o.dropperMaps,
	)
}

// dropperMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadDropperObjects or ebpf.CollectionSpec.LoadAndAssign.
type dropperMaps struct {
	DropStatsMap *ebpf.Map `ebpf:"drop_stats_map"`
	Ipv4LpmTrie  *ebpf.Map `ebpf:"ipv4_lpm_trie"`
	JmpTable     *ebpf.Map `ebpf:"jmp_table"`
}

func (m *dropperMaps) Close() error {
	return _DropperClose(
		m.DropStatsMap,
		m.Ipv4LpmTrie,
		m.JmpTable,
	)
}

// dropperPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadDropperObjects or ebpf.CollectionSpec.LoadAndAssign.
type dropperPrograms struct {
	DropPacketsByIp *ebpf.Program `ebpf:"drop_packets_by_ip"`
	GetStats        *ebpf.Program `ebpf:"get_stats"`
}

func (p *dropperPrograms) Close() error {
	return _DropperClose(
		p.DropPacketsByIp,
		p.GetStats,
	)
}

func _DropperClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed dropper_bpfeb.o
var _DropperBytes []byte
