package main

import (
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

func refuseExtendedDataFD(file *os.File) error {
	query := func(b []byte) (int, error) {
		var p unsafe.Pointer
		if len(b) > 0 {
			p = unsafe.Pointer(&b[0])
		}
		n, _, e := syscall.Syscall6(syscall.SYS_FLISTXATTR, file.Fd(), uintptr(p), uintptr(len(b)), 0, 0, 0)
		runtime.KeepAlive(file)
		runtime.KeepAlive(b)
		if e != 0 {
			return 0, e
		}
		return int(n), nil
	}
	return refuseRemoteAttributeList(query)
}
func refuseSymlinkExtendedDataAt(parent *os.File, name string, pinned *os.File) error {
	if err := refuseExtendedDataFD(pinned); err != nil {
		return err
	}
	return nil
}
