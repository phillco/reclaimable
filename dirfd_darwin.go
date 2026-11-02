//go:build darwin && (amd64 || arm64)

package main

import (
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

// Stable BSD syscall numbers from the macOS SDK sys/syscall.h. The syscall
// package exposes direct kernel traps on both supported Darwin architectures.
const (
	darwinOpenAt     = 463
	darwinRenameAtX  = 488
	darwinRenameExcl = 0x00000004 // RENAME_EXCL from sys/stdio.h.
	darwinStatAt     = 470
	darwinUnlinkAt   = 472
	darwinReadlinkAt = 473
	darwinSymlinkAt  = 474
	darwinMkdirAt    = 475
	darwinNoFollow   = 32
	darwinRemoveDir  = 128
)

func openAt(parent *os.File, name string, flags int, mode uint32) (*os.File, error) {
	p, err := atName(name)
	if err != nil {
		return nil, err
	}
	fd, _, e := syscall.Syscall6(darwinOpenAt, parent.Fd(), uintptr(unsafe.Pointer(p)), uintptr(flags|syscall.O_CLOEXEC), uintptr(mode), 0, 0)
	runtime.KeepAlive(parent)
	runtime.KeepAlive(p)
	if e != 0 {
		return nil, &os.PathError{Op: "openat", Path: name, Err: e}
	}
	return os.NewFile(fd, name), nil
}
func statAt(parent *os.File, name string, follow bool) (os.FileInfo, error) {
	p, err := atName(name)
	if err != nil {
		return nil, err
	}
	var stat syscall.Stat_t
	flags := uintptr(0)
	if !follow {
		flags = darwinNoFollow
	}
	_, _, e := syscall.Syscall6(darwinStatAt, parent.Fd(), uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&stat)), flags, 0, 0)
	runtime.KeepAlive(parent)
	runtime.KeepAlive(p)
	if e != 0 {
		return nil, &os.PathError{Op: "fstatat", Path: name, Err: e}
	}
	return makeAtInfo(name, &stat, time.Unix(stat.Mtimespec.Sec, stat.Mtimespec.Nsec)), nil
}
func unlinkAt(parent *os.File, name string, dir bool) error {
	p, err := atName(name)
	if err != nil {
		return err
	}
	flags := uintptr(0)
	if dir {
		flags = darwinRemoveDir
	}
	_, _, e := syscall.Syscall(darwinUnlinkAt, parent.Fd(), uintptr(unsafe.Pointer(p)), flags)
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
		n, _, e := syscall.Syscall6(darwinReadlinkAt, parent.Fd(), uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), 0, 0)
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
	p, err := atName(name)
	if err != nil {
		return err
	}
	_, _, e := syscall.Syscall(darwinMkdirAt, parent.Fd(), uintptr(unsafe.Pointer(p)), uintptr(mode))
	runtime.KeepAlive(parent)
	runtime.KeepAlive(p)
	if e != 0 {
		return &os.PathError{Op: "mkdirat", Path: name, Err: e}
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
	_, _, e := syscall.Syscall(darwinSymlinkAt, uintptr(unsafe.Pointer(t)), parent.Fd(), uintptr(unsafe.Pointer(p)))
	runtime.KeepAlive(parent)
	runtime.KeepAlive(p)
	runtime.KeepAlive(t)
	if e != 0 {
		return &os.LinkError{Op: "symlinkat", Old: target, New: name, Err: e}
	}
	return nil
}
func renameAt(oldParent *os.File, oldName string, newParent *os.File, newName string) error {
	old, err := atName(oldName)
	if err != nil {
		return err
	}
	next, err := atName(newName)
	if err != nil {
		return err
	}
	// Quarantine and rollback must never replace an entry that already exists.
	// Unsupported exclusive renames fail closed; there is no ordinary-rename fallback.
	_, _, e := syscall.Syscall6(darwinRenameAtX, oldParent.Fd(), uintptr(unsafe.Pointer(old)), newParent.Fd(), uintptr(unsafe.Pointer(next)), darwinRenameExcl, 0)
	runtime.KeepAlive(oldParent)
	runtime.KeepAlive(newParent)
	runtime.KeepAlive(old)
	runtime.KeepAlive(next)
	if e != 0 {
		return &os.LinkError{Op: "renameatx_np", Old: oldName, New: newName, Err: e}
	}
	return nil
}
