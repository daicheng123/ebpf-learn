// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64

package exec

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadExec returns the embedded CollectionSpec for exec.
func loadExec() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_ExecBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load exec: %w", err)
	}

	return spec, err
}

// loadExecObjects loads exec and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*execObjects
//	*execPrograms
//	*execMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadExecObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadExec()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// execSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type execSpecs struct {
	execProgramSpecs
	execMapSpecs
}

// execSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type execProgramSpecs struct {
	TracepointSyscallsSysEnterExecve *ebpf.ProgramSpec `ebpf:"tracepoint_syscalls_sys_enter_execve"`
}

// execMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type execMapSpecs struct {
	Events *ebpf.MapSpec `ebpf:"events"`
}

// execObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadExecObjects or ebpf.CollectionSpec.LoadAndAssign.
type execObjects struct {
	execPrograms
	execMaps
}

func (o *execObjects) Close() error {
	return _ExecClose(
		&o.execPrograms,
		&o.execMaps,
	)
}

// execMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadExecObjects or ebpf.CollectionSpec.LoadAndAssign.
type execMaps struct {
	Events *ebpf.Map `ebpf:"events"`
}

func (m *execMaps) Close() error {
	return _ExecClose(
		m.Events,
	)
}

// execPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadExecObjects or ebpf.CollectionSpec.LoadAndAssign.
type execPrograms struct {
	TracepointSyscallsSysEnterExecve *ebpf.Program `ebpf:"tracepoint_syscalls_sys_enter_execve"`
}

func (p *execPrograms) Close() error {
	return _ExecClose(
		p.TracepointSyscallsSysEnterExecve,
	)
}

func _ExecClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed exec_bpfel_x86.o
var _ExecBytes []byte
