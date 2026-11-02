package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Directory descriptors are opened one component at a time from the filesystem
// root. A swapped ancestor is either rejected or leaves us anchored to the
// original directory; it cannot redirect an operation through a symlink.
func openPathDir(path string) (*os.File, error)   { return openPathDirs(path, false) }
func mkdirPathDirs(path string) (*os.File, error) { return openPathDirs(path, true) }
func openPathDirs(path string, create bool) (*os.File, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile("/", os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	for _, name := range strings.Split(strings.TrimPrefix(filepath.Clean(absolute), "/"), "/") {
		if name == "" {
			continue
		}
		next, e := openAt(f, name, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		if os.IsNotExist(e) && create {
			if e = mkdirAt(f, name, 0755); e == nil || os.IsExist(e) {
				next, e = openAt(f, name, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
			}
		}
		f.Close()
		if e != nil {
			return nil, fmt.Errorf("open directory %s: %w", absolute, e)
		}
		f = next
	}
	return f, nil
}
func sameIdentity(a, b os.FileInfo) bool {
	return a != nil && b != nil && device(a) == device(b) && inode(a) == inode(b) && a.Mode().Type() == b.Mode().Type()
}
func (a *App) fsBefore(op, parent, name string) {
	if a.FSBefore != nil {
		a.FSBefore(op, parent, name)
	}
}
