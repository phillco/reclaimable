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

// walkPayload centralizes the no-follow, same-device and extended-data rules
// shared by hashing and archive export. Files are valid only during visit.
func (a *App) walkPayload(root *os.File, visit func(*os.File, *os.File, string, string, os.FileInfo) error) error {
	info, err := root.Stat()
	if err != nil {
		return err
	}
	var walk func(*os.File, string) error
	walk = func(dir *os.File, relative string) error {
		if err := refuseExtendedDataFD(dir); err != nil {
			return err
		}
		entries, err := dir.ReadDir(-1)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			name := entry.Name()
			st, err := a.StatAt(dir, name, false)
			if err != nil {
				return err
			}
			if name == ".DS_Store" && !st.IsDir() {
				continue
			}
			rel := filepath.Join(relative, name)
			if device(st) != device(info) {
				return fmt.Errorf("payload crosses filesystem at %s", rel)
			}
			var child *os.File
			switch {
			case st.Mode()&os.ModeSymlink != 0:
				child, err = pinSymlinkAt(dir, name)
			case st.IsDir(), st.Mode().IsRegular():
				flags := os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
				if st.IsDir() {
					flags |= syscall.O_DIRECTORY
				}
				child, err = openAt(dir, name, flags, 0)
			default:
				return fmt.Errorf("cannot read special file %s", rel)
			}
			if err != nil {
				return err
			}
			err = func() error {
				defer child.Close()
				if st.Mode()&os.ModeSymlink != 0 {
					if err := refuseSymlinkExtendedDataAt(dir, name, child); err != nil {
						return err
					}
				} else if err := refuseExtendedDataFD(child); err != nil {
					return err
				}
				if err := visit(dir, child, name, rel, st); err != nil {
					return err
				}
				if st.IsDir() {
					return walk(child, rel)
				}
				return nil
			}()
			if err != nil {
				return err
			}
		}
		return nil
	}
	// A separate directory description keeps the caller's enumeration intact.
	dir, err := openAt(root, ".", os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer dir.Close()
	return walk(dir, "")
}
