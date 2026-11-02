//go:build linux && (amd64 || arm64)

package main

import (
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

func pinSymlinkAt(parent *os.File, name string) (*os.File, error) {
	const openPath = 2097152
	return requireSymlinkFile(openAt(parent, name, openPath|syscall.O_NOFOLLOW, 0))
}
func fdSetTimes(file *os.File, atime, mtime time.Time) error {
	times := [2]syscall.Timespec{{Sec: atime.Unix(), Nsec: int64(atime.Nanosecond())}, {Sec: mtime.Unix(), Nsec: int64(mtime.Nanosecond())}}
	var path *byte
	flags := uintptr(0)
	var empty byte
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		path = &empty
		flags = 4096 | 256
	}
	_, _, e := syscall.Syscall6(syscall.SYS_UTIMENSAT, file.Fd(), uintptr(unsafe.Pointer(path)), uintptr(unsafe.Pointer(&times)), flags, 0, 0)
	runtime.KeepAlive(file)
	runtime.KeepAlive(&empty)
	if e != 0 {
		return &os.PathError{Op: "utimensat", Path: file.Name(), Err: e}
	}
	return nil
}
