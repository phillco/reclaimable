package main

import (
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

func refuseExtendedDataFD(file *os.File) error {
	query := func(b []byte) (int, error) {
		n, _, e := syscall.Syscall(syscall.SYS_FLISTXATTR, file.Fd(), bytesPointer(b), uintptr(len(b)))
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
	p, err := linkProcPath(parent, name)
	if err != nil {
		return err
	}
	query := func(b []byte) (int, error) {
		n, _, e := syscall.Syscall(syscall.SYS_LLISTXATTR, uintptr(unsafe.Pointer(p)), bytesPointer(b), uintptr(len(b)))
		runtime.KeepAlive(parent)
		runtime.KeepAlive(p)
		runtime.KeepAlive(b)
		if e != 0 {
			return 0, e
		}
		return int(n), nil
	}
	if err = refuseRemoteAttributeList(query); err != nil {
		return err
	}
	return nil
}
