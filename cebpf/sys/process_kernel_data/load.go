package process_kernel_data

import (
	"bytes"
	"errors"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"log"
	"unsafe"
)

type Proc struct {
	PID         uint32
	PPID        uint32
	ProcessName [256]byte
}

func LoadSystemExecProcess() (err error) {
	object := new(sysObjects)

	if err := loadSysObjects(object, nil); err != nil {
		return err
	}
	defer object.Close()

	tp, err := link.Tracepoint("syscalls", "sys_exit_execve", object.HandleTp, nil)

	if err != nil {
		return err
	}

	defer tp.Close()

	rd, err := ringbuf.NewReader(object.ProcessMap)

	if err != nil {
		return err
	}

	defer rd.Close()

	log.Println("开始监听execve")
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				log.Println("received signal, exit...")
				break
			}
			log.Printf("reading from reader err:%+v", err)
			continue
		}
		if len(record.RawSample) > 0 {
			data := (*Proc)(unsafe.Pointer(&record.RawSample[0]))
			log.Printf("父进程id:%d,进程id:%d,进程名:%s\n", data.PPID, data.PID, bytes.TrimRight(data.ProcessName[:], "0x00"))
		}
	}
	return err
}
