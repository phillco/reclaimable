package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
)

// Operations accept a single child name: intermediate components must be opened
// independently with O_NOFOLLOW so traversal stays anchored to verified handles.
func atName(name string) (*byte, error) {
	if name == "" || name == ".." || strings.ContainsAny(name, "/\x00") {
		return nil, fmt.Errorf("invalid descriptor-relative child name %q", name)
	}
	return syscall.BytePtrFromString(name)
}

type atFileInfo struct {
	name  string
	stat  *syscall.Stat_t
	mode  os.FileMode
	mtime time.Time
}

func (f *atFileInfo) Name() string       { return f.name }
func (f *atFileInfo) Size() int64        { return f.stat.Size }
func (f *atFileInfo) Mode() os.FileMode  { return f.mode }
func (f *atFileInfo) ModTime() time.Time { return f.mtime }
func (f *atFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f *atFileInfo) Sys() any           { return f.stat }
func makeAtInfo(name string, stat *syscall.Stat_t, mtime time.Time) os.FileInfo {
	bits := uint32(stat.Mode)
	mode := os.FileMode(bits & 511)
	switch bits & syscall.S_IFMT {
	case syscall.S_IFDIR:
		mode |= os.ModeDir
	case syscall.S_IFLNK:
		mode |= os.ModeSymlink
	case syscall.S_IFIFO:
		mode |= os.ModeNamedPipe
	case syscall.S_IFSOCK:
		mode |= os.ModeSocket
	case syscall.S_IFBLK:
		mode |= os.ModeDevice
	case syscall.S_IFCHR:
		mode |= os.ModeDevice | os.ModeCharDevice
	}
	if bits&syscall.S_ISUID != 0 {
		mode |= os.ModeSetuid
	}
	if bits&syscall.S_ISGID != 0 {
		mode |= os.ModeSetgid
	}
	if bits&syscall.S_ISVTX != 0 {
		mode |= os.ModeSticky
	}
	return &atFileInfo{name, stat, mode, mtime}
}

func requireSymlinkFile(file *os.File, err error) (*os.File, error) {
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		file.Close()
		return nil, fmt.Errorf("opened entry is not a symlink")
	}
	return file, nil
}
