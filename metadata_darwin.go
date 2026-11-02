package main

import (
	"fmt"
	"os"
	"syscall"
	"time"
)

func accessTime(info os.FileInfo) time.Time {
	st := info.Sys().(*syscall.Stat_t)
	return time.Unix(st.Atimespec.Sec, st.Atimespec.Nsec)
}
func copyMetadata(src, dest string, info os.FileInfo) error {
	if err := os.Chtimes(dest, accessTime(info), info.ModTime()); err != nil {
		return err
	}
	if err := os.Chmod(dest, info.Mode()&(os.ModePerm|os.ModeSetuid|os.ModeSetgid|os.ModeSticky)); err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot read metadata for %s", src)
	}
	return syscall.Chflags(dest, int(st.Flags))
}

func symlinkCopyArgs(src, dest string) []string { return []string{"/bin/cp", "-pRP", src, dest} }
