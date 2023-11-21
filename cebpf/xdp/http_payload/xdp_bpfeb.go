// Code generated by bpf2go; DO NOT EDIT.
//go:build arm64be || armbe || mips || mips64 || mips64p32 || ppc64 || s390 || s390x || sparc || sparc64

package http_payload

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadXdp returns the embedded CollectionSpec for xdp.
func loadXdp() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_XdpBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load xdp: %w", err)
	}

	return spec, err
}

// loadXdpObjects loads xdp and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*xdpObjects
//	*xdpPrograms
//	*xdpMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadXdpObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadXdp()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// xdpSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type xdpSpecs struct {
	xdpProgramSpecs
	xdpMapSpecs
}

// xdpSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type xdpProgramSpecs struct {
	MyPass *ebpf.ProgramSpec `ebpf:"my_pass"`
}

// xdpMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type xdpMapSpecs struct {
	AllowIpsMap *ebpf.MapSpec `ebpf:"allow_ips_map"`
	IpMap       *ebpf.MapSpec `ebpf:"ip_map"`
}

// xdpObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadXdpObjects or ebpf.CollectionSpec.LoadAndAssign.
type xdpObjects struct {
	xdpPrograms
	xdpMaps
}

func (o *xdpObjects) Close() error {
	return _XdpClose(
		&o.xdpPrograms,
		&o.xdpMaps,
	)
}

// xdpMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadXdpObjects or ebpf.CollectionSpec.LoadAndAssign.
type xdpMaps struct {
	AllowIpsMap *ebpf.Map `ebpf:"allow_ips_map"`
	IpMap       *ebpf.Map `ebpf:"ip_map"`
}

func (m *xdpMaps) Close() error {
	return _XdpClose(
		m.AllowIpsMap,
		m.IpMap,
	)
}

// xdpPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadXdpObjects or ebpf.CollectionSpec.LoadAndAssign.
type xdpPrograms struct {
	MyPass *ebpf.Program `ebpf:"my_pass"`
}

func (p *xdpPrograms) Close() error {
	return _XdpClose(
		p.MyPass,
	)
}

func _XdpClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed xdp_bpfeb.o
var _XdpBytes []byte
