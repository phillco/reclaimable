package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
)

func accessTime(info os.FileInfo) time.Time {
	st := info.Sys().(*syscall.Stat_t)
	return time.Unix(int64(st.Atim.Sec), int64(st.Atim.Nsec))
}
func copyMetadata(src, dest string, info os.FileInfo) error {
	if err := os.Chtimes(dest, accessTime(info), info.ModTime()); err != nil {
		return err
	}
	n, err := syscall.Listxattr(src, nil)
	if err != nil && err != syscall.ENOTSUP {
		return err
	}
	if n > 0 {
		names := make([]byte, n)
		got, err := syscall.Listxattr(src, names)
		if err != nil {
			return err
		}
		names = names[:got]
		for _, name := range strings.Split(strings.TrimSuffix(string(names), "\x00"), "\x00") {
			size, err := syscall.Getxattr(src, name, nil)
			if err != nil {
				return err
			}
			value := make([]byte, size)
			got, err := syscall.Getxattr(src, name, value)
			if err != nil {
				return err
			}
			if got != size {
				return fmt.Errorf("attribute %q changed during copy", name)
			}
			if err = syscall.Setxattr(dest, name, value, 0); err != nil {
				return err
			}
		}
	}
	return os.Chmod(dest, info.Mode()&(os.ModePerm|os.ModeSetuid|os.ModeSetgid|os.ModeSticky))
}

func symlinkCopyArgs(src, dest string) []string {
	return []string{"/bin/cp", "-pRP", "--preserve=xattr", src, dest}
}
