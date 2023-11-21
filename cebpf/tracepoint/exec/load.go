package exec

import (
	"bytes"
	"errors"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"log"
	"os"
	"unsafe"
)

type Event struct {
	PID uint32
	UID uint32
	PPID uint32
	Comm [256]byte
}

func LoadSystemExecProcess() (err error) {
	object := new(execObjects)

	if err := loadExecObjects(object, nil); err != nil {
		return err
	}
	defer object.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", object.TracepointSyscallsSysEnterExecve, nil)

	defer tp.Close()

	rd, err := perf.NewReader(object.Events, os.Getpagesize())
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
			event := (*Event)(unsafe.Pointer(&record.RawSample[0]))
			log.Printf("进程id:%d,进程名:%s,父进程id:%d,用户id:%d\n",
				event.PID,
				bytes.TrimRight(event.Comm[:], "0x00"),
				event.PPID,
				event.UID,
			)
		}
	}
	return err
}
