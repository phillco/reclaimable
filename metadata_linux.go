package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

func accessTime(info os.FileInfo) time.Time {
	st := info.Sys().(*syscall.Stat_t)
	return time.Unix(int64(st.Atim.Sec), int64(st.Atim.Nsec))
}
func bytesPointer(b []byte) uintptr {
	if len(b) == 0 {
		return 0
	}
	return uintptr(unsafe.Pointer(&b[0]))
}
func fdXattrs(file *os.File) ([]string, error) {
	query := func(b []byte) (int, error) {
		n, _, e := syscall.Syscall(syscall.SYS_FLISTXATTR, file.Fd(), bytesPointer(b), uintptr(len(b)))
		runtime.KeepAlive(file)
		runtime.KeepAlive(b)
		if e != 0 {
			return 0, e
		}
		return int(n), nil
	}
	return xattrNames(query)
}
func xattrNames(query func([]byte) (int, error)) ([]string, error) {
	n, err := query(nil)
	if err == syscall.ENOTSUP {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	b := make([]byte, n)
	n, err = query(b)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	if n > len(b) {
		return nil, fmt.Errorf("attribute names changed during copy")
	}
	return strings.Split(strings.TrimSuffix(string(b[:n]), "\x00"), "\x00"), nil
}
func fdGetXattr(file *os.File, name string) ([]byte, error) {
	p, err := syscall.BytePtrFromString(name)
	if err != nil {
		return nil, err
	}
	query := func(b []byte) (int, error) {
		n, _, e := syscall.Syscall6(syscall.SYS_FGETXATTR, file.Fd(), uintptr(unsafe.Pointer(p)), bytesPointer(b), uintptr(len(b)), 0, 0)
		runtime.KeepAlive(file)
		runtime.KeepAlive(p)
		runtime.KeepAlive(b)
		if e != 0 {
			return 0, e
		}
		return int(n), nil
	}
	return xattrValue(query)
}
func xattrValue(query func([]byte) (int, error)) ([]byte, error) {
	n, err := query(nil)
	if err != nil {
		return nil, err
	}
	b := make([]byte, n)
	got, err := query(b)
	if err != nil {
		return nil, err
	}
	if got != n {
		return nil, fmt.Errorf("attribute changed during copy")
	}
	return b, nil
}
func fdSetXattr(file *os.File, name string, value []byte) error {
	p, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	_, _, e := syscall.Syscall6(syscall.SYS_FSETXATTR, file.Fd(), uintptr(unsafe.Pointer(p)), bytesPointer(value), uintptr(len(value)), 0, 0)
	runtime.KeepAlive(file)
	runtime.KeepAlive(p)
	runtime.KeepAlive(value)
	if e != 0 {
		return e
	}
	return nil
}
func copyMetadataFD(src, dest *os.File, info os.FileInfo) error {
	if err := fdSetTimes(dest, accessTime(info), info.ModTime()); err != nil {
		return err
	}
	names, err := fdXattrs(src)
	if err != nil {
		return err
	}
	for _, name := range names {
		value, err := fdGetXattr(src, name)
		if err != nil {
			return err
		}
		if err = fdSetXattr(dest, name, value); err != nil {
			return err
		}
	}
	return dest.Chmod(info.Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky))
}

// Linux xattr syscalls cannot operate on an O_PATH symlink descriptor. These
// no-follow leaf operations use the kernel's procfs handle to an already pinned
// parent, with identity checks on both sides; no user-controlled ancestor path
// is traversed. Missing procfs or unsupported link timestamps refuse the copy.
func linkProcPath(parent *os.File, name string) (*byte, error) {
	if _, err := atName(name); err != nil {
		return nil, err
	}
	return syscall.BytePtrFromString(fmt.Sprintf("/proc/self/fd/%d/%s", parent.Fd(), name))
}
func linkXattrs(parent *os.File, name string) ([]string, error) {
	p, err := linkProcPath(parent, name)
	if err != nil {
		return nil, err
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
	return xattrNames(query)
}
func linkGetXattr(parent *os.File, leaf, name string) ([]byte, error) {
	p, err := linkProcPath(parent, leaf)
	if err != nil {
		return nil, err
	}
	attr, err := syscall.BytePtrFromString(name)
	if err != nil {
		return nil, err
	}
	query := func(b []byte) (int, error) {
		n, _, e := syscall.Syscall6(syscall.SYS_LGETXATTR, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(attr)), bytesPointer(b), uintptr(len(b)), 0, 0)
		runtime.KeepAlive(parent)
		runtime.KeepAlive(p)
		runtime.KeepAlive(attr)
		runtime.KeepAlive(b)
		if e != 0 {
			return 0, e
		}
		return int(n), nil
	}
	return xattrValue(query)
}
func linkSetXattr(parent *os.File, leaf, name string, value []byte) error {
	p, err := linkProcPath(parent, leaf)
	if err != nil {
		return err
	}
	attr, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	_, _, e := syscall.Syscall6(syscall.SYS_LSETXATTR, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(attr)), bytesPointer(value), uintptr(len(value)), 0, 0)
	runtime.KeepAlive(parent)
	runtime.KeepAlive(p)
	runtime.KeepAlive(attr)
	runtime.KeepAlive(value)
	if e != 0 {
		return e
	}
	return nil
}
func copySymlinkMetadataAt(srcParent *os.File, srcName string, destParent *os.File, destName string, info, destInfo os.FileInfo) error {
	src, err := pinSymlinkAt(srcParent, srcName)
	if err != nil {
		return err
	}
	defer src.Close()
	dest, err := pinSymlinkAt(destParent, destName)
	if err != nil {
		return err
	}
	defer dest.Close()
	if err = fdSetTimes(dest, accessTime(info), info.ModTime()); err != nil {
		return err
	}
	names, err := linkXattrs(srcParent, srcName)
	if err != nil {
		return err
	}
	for _, name := range names {
		value, err := linkGetXattr(srcParent, srcName, name)
		if err != nil {
			return err
		}
		if err = linkSetXattr(destParent, destName, name, value); err != nil {
			return err
		}
	}
	return nil
}
