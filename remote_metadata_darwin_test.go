package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"unsafe"
)

func TestArchiveExportRefusesExtendedPayloads(t *testing.T) {
	e := newTestEnv(t)
	src := e.make(t, "extended-export", 30*day, map[string][]byte{"file": []byte("fixture")}, nil)
	file, err := os.Open(filepath.Join(src, "file"))
	must(t, err)
	defer file.Close()
	name, err := syscall.BytePtrFromString("user.fixture")
	must(t, err)
	value := []byte("must retain")
	_, _, errno := syscall.Syscall6(syscall.SYS_FSETXATTR, file.Fd(), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&value[0])), uintptr(len(value)), 0, 0)
	runtime.KeepAlive(file)
	runtime.KeepAlive(name)
	runtime.KeepAlive(value)
	must(t, errnoToError(errno))
	check(t, refuseExtendedDataFD(file) != nil, "extended payload inspection accepted data")
	var archive bytes.Buffer
	check(t, e.A.exportArchive(src, &archive, map[string]string{}) != nil, "archive accepted unverified extended payload")
}
func errnoToError(e syscall.Errno) error {
	if e != 0 {
		return e
	}
	return nil
}
