package bash_monitor

import (
	"errors"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
	"log"
	"os"
	"os/signal"
	"syscall"
	"unsafe"
)

const (
	binPath = "/usr/bin/bash"
	symbol  = "readline"
)

func LoadBashUserProbeProcess() (err error) {

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	object := new(bash_monitorObjects)

	if err := loadBash_monitorObjects(object, nil); err != nil {
		return err
	}
	defer object.Close()

	ex, err := link.OpenExecutable(binPath)
	if err != nil {
		//log.Fatalf("opening executable: %s", err)
		return err
	}

	up, err := ex.Uretprobe(symbol, object.UretprobeBashReadline, nil)
	if err != nil {
		//log.Fatalf("creating uretprobe: %s", err)
		return err
	}
	defer up.Close()

	rd, err := perf.NewReader(object.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer rd.Close()

	go func() {
		<-stopper
		log.Println("Received signal, exiting program..")
		if err := rd.Close(); err != nil {
			log.Fatalf("closing perf event reader: %s", err)
		}
	}()
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return err
			}
			log.Printf("reading from perf event reader: %s", err)
			continue
		}

		if record.LostSamples != 0 {
			log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
			continue
		}

		if len(record.RawSample) > 0 {
			data := (*Event)(unsafe.Pointer(&record.RawSample[0]))
			log.Printf("%s:%s return value: %s", binPath, symbol, unix.ByteSliceToString(data.Line[:]))
		}
	}
	return err
}

type Event struct {
	PID  uint32
	Line [80]byte
}
