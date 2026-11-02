//go:build darwin && (amd64 || arm64)

package main

import (
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

func pinSymlinkAt(parent *os.File, name string) (*os.File, error) {
	// O_SYMLINK itself prevents following the link; adding O_NOFOLLOW makes
	// Darwin reject even legitimate symlink handles with ELOOP. NONBLOCK
	// prevents a swapped FIFO from blocking before its type is checked.
	return requireSymlinkFile(openAt(parent, name, os.O_RDONLY|syscall.O_SYMLINK|syscall.O_NONBLOCK, 0))
}
func fdSetTimes(file *os.File, atime, mtime time.Time) error {
	// fsetattrlist's attribute buffer follows ascending common-attribute bits:
	// modification time before access time. Both are full native timespecs.
	attrs := struct {
		Count, Reserved                       uint16
		Common, Volume, Directory, File, Fork uint32
	}{Count: 5, Common: 5120}
	times := [2]syscall.Timespec{{Sec: mtime.Unix(), Nsec: int64(mtime.Nanosecond())}, {Sec: atime.Unix(), Nsec: int64(atime.Nanosecond())}}
	_, _, e := syscall.Syscall6(229, file.Fd(), uintptr(unsafe.Pointer(&attrs)), uintptr(unsafe.Pointer(&times)), unsafe.Sizeof(times), 0, 0)
	runtime.KeepAlive(file)
	if e != 0 {
		return &os.PathError{Op: "fsetattrlist", Path: file.Name(), Err: e}
	}
	return nil
}
