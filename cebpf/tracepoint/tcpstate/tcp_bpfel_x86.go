// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64

package tcpstate

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadTcp returns the embedded CollectionSpec for tcp.
func loadTcp() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_TcpBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load tcp: %w", err)
	}

	return spec, err
}

// loadTcpObjects loads tcp and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*tcpObjects
//	*tcpPrograms
//	*tcpMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadTcpObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadTcp()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// tcpSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tcpSpecs struct {
	tcpProgramSpecs
	tcpMapSpecs
}

// tcpSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tcpProgramSpecs struct {
	InetSockSetState *ebpf.ProgramSpec `ebpf:"inet_sock_set_state"`
}

// tcpMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tcpMapSpecs struct {
	Events     *ebpf.MapSpec `ebpf:"events"`
	Timestamps *ebpf.MapSpec `ebpf:"timestamps"`
}

// tcpObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadTcpObjects or ebpf.CollectionSpec.LoadAndAssign.
type tcpObjects struct {
	tcpPrograms
	tcpMaps
}

func (o *tcpObjects) Close() error {
	return _TcpClose(
		&o.tcpPrograms,
		&o.tcpMaps,
	)
}

// tcpMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadTcpObjects or ebpf.CollectionSpec.LoadAndAssign.
type tcpMaps struct {
	Events     *ebpf.Map `ebpf:"events"`
	Timestamps *ebpf.Map `ebpf:"timestamps"`
}

func (m *tcpMaps) Close() error {
	return _TcpClose(
		m.Events,
		m.Timestamps,
	)
}

// tcpPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadTcpObjects or ebpf.CollectionSpec.LoadAndAssign.
type tcpPrograms struct {
	InetSockSetState *ebpf.Program `ebpf:"inet_sock_set_state"`
}

func (p *tcpPrograms) Close() error {
	return _TcpClose(
		p.InetSockSetState,
	)
}

func _TcpClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed tcp_bpfel_x86.o
var _TcpBytes []byte
