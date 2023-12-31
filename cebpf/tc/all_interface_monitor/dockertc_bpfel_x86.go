// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64

package all_interface_monitor

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadDockertc returns the embedded CollectionSpec for dockertc.
func loadDockertc() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_DockertcBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load dockertc: %w", err)
	}

	return spec, err
}

// loadDockertcObjects loads dockertc and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*dockertcObjects
//	*dockertcPrograms
//	*dockertcMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadDockertcObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadDockertc()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// dockertcSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type dockertcSpecs struct {
	dockertcProgramSpecs
	dockertcMapSpecs
}

// dockertcSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type dockertcProgramSpecs struct {
	IpPackageExample *ebpf.ProgramSpec `ebpf:"ip_package_example"`
}

// dockertcMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type dockertcMapSpecs struct {
	TrafficControllerMap *ebpf.MapSpec `ebpf:"traffic_controller_map"`
}

// dockertcObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadDockertcObjects or ebpf.CollectionSpec.LoadAndAssign.
type dockertcObjects struct {
	dockertcPrograms
	dockertcMaps
}

func (o *dockertcObjects) Close() error {
	return _DockertcClose(
		&o.dockertcPrograms,
		&o.dockertcMaps,
	)
}

// dockertcMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadDockertcObjects or ebpf.CollectionSpec.LoadAndAssign.
type dockertcMaps struct {
	TrafficControllerMap *ebpf.Map `ebpf:"traffic_controller_map"`
}

func (m *dockertcMaps) Close() error {
	return _DockertcClose(
		m.TrafficControllerMap,
	)
}

// dockertcPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadDockertcObjects or ebpf.CollectionSpec.LoadAndAssign.
type dockertcPrograms struct {
	IpPackageExample *ebpf.Program `ebpf:"ip_package_example"`
}

func (p *dockertcPrograms) Close() error {
	return _DockertcClose(
		p.IpPackageExample,
	)
}

func _DockertcClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed dockertc_bpfel_x86.o
var _DockertcBytes []byte
