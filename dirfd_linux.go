//go:build linux && (amd64 || arm64)

package main

import (
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

func openAt(parent *os.File, name string, flags int, mode uint32) (*os.File, error) {
	if _, err := atName(name); err != nil {
		return nil, err
	}
	fd, err := syscall.Openat(int(parent.Fd()), name, flags|syscall.O_CLOEXEC, mode)
	runtime.KeepAlive(parent)
	if err != nil {
		return nil, &os.PathError{Op: "openat", Path: name, Err: err}
	}
	return os.NewFile(uintptr(fd), name), nil
}
func statAt(parent *os.File, name string, follow bool) (os.FileInfo, error) {
	p, err := atName(name)
	if err != nil {
		return nil, err
	}
	var stat syscall.Stat_t
	flags := uintptr(0)
	if !follow {
		flags = 256
	}
	number := uintptr(262)
	if runtime.GOARCH == "arm64" {
		number = 79
	}
	_, _, e := syscall.Syscall6(number, parent.Fd(), uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&stat)), flags, 0, 0)
	runtime.KeepAlive(parent)
	runtime.KeepAlive(p)
	if e != 0 {
		return nil, &os.PathError{Op: "fstatat", Path: name, Err: e}
	}
	return makeAtInfo(name, &stat, time.Unix(stat.Mtim.Sec, stat.Mtim.Nsec)), nil
}
func unlinkAt(parent *os.File, name string, dir bool) error {
	p, err := atName(name)
	if err != nil {
		return err
	}
	flags := uintptr(0)
	if dir {
		flags = 512
	}
	_, _, e := syscall.Syscall(syscall.SYS_UNLINKAT, parent.Fd(), uintptr(unsafe.Pointer(p)), flags)
	runtime.KeepAlive(parent)
	runtime.KeepAlive(p)
	if e != 0 {
		return &os.PathError{Op: "unlinkat", Path: name, Err: e}
	}
	return nil
}
func readlinkAt(parent *os.File, name string) (string, error) {
	p, err := atName(name)
	if err != nil {
		return "", err
	}
	for size := 128; size <= 1<<20; size *= 2 {
		buffer := make([]byte, size)
		n, _, e := syscall.Syscall6(syscall.SYS_READLINKAT, parent.Fd(), uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), 0, 0)
		runtime.KeepAlive(parent)
		runtime.KeepAlive(p)
		if e != 0 {
			return "", &os.PathError{Op: "readlinkat", Path: name, Err: e}
		}
		if n < uintptr(len(buffer)) {
			return string(buffer[:n]), nil
		}
	}
	return "", &os.PathError{Op: "readlinkat", Path: name, Err: syscall.ENAMETOOLONG}
}
func mkdirAt(parent *os.File, name string, mode uint32) error {
	if _, err := atName(name); err != nil {
		return err
	}
	err := syscall.Mkdirat(int(parent.Fd()), name, mode)
	runtime.KeepAlive(parent)
	if err != nil {
		return &os.PathError{Op: "mkdirat", Path: name, Err: err}
	}
	return nil
}
func symlinkAt(target string, parent *os.File, name string) error {
	p, err := atName(name)
	if err != nil {
		return err
	}
	t, err := syscall.BytePtrFromString(target)
	if err != nil {
		return err
	}
	_, _, e := syscall.Syscall(syscall.SYS_SYMLINKAT, uintptr(unsafe.Pointer(t)), parent.Fd(), uintptr(unsafe.Pointer(p)))
	runtime.KeepAlive(parent)
	runtime.KeepAlive(p)
	runtime.KeepAlive(t)
	if e != 0 {
		return &os.LinkError{Op: "symlinkat", Old: target, New: name, Err: e}
	}
	return nil
}
func renameAt(oldParent *os.File, oldName string, newParent *os.File, newName string) error {
	if _, err := atName(oldName); err != nil {
		return err
	}
	if _, err := atName(newName); err != nil {
		return err
	}
	err := syscall.Renameat(int(oldParent.Fd()), oldName, int(newParent.Fd()), newName)
	runtime.KeepAlive(oldParent)
	runtime.KeepAlive(newParent)
	if err != nil {
		return &os.LinkError{Op: "renameat", Old: oldName, New: newName, Err: err}
	}
	return nil
}
