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
func copyMetadataFD(src, dest *os.File, info os.FileInfo) error {
	if err := fdSetTimes(dest, accessTime(info), info.ModTime()); err != nil {
		return err
	}
	if err := dest.Chmod(info.Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)); err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot read descriptor metadata")
	}
	return syscall.Fchflags(int(dest.Fd()), int(st.Flags))
}
func copySymlinkMetadataAt(srcParent *os.File, srcName string, destParent *os.File, destName string, info, destInfo os.FileInfo) error {
	source, err := pinSymlinkAt(srcParent, srcName)
	if err != nil {
		return err
	}
	defer source.Close()
	sourceInfo, err := source.Stat()
	if err != nil {
		return err
	}
	if !sameIdentity(sourceInfo, info) {
		return fmt.Errorf("source symlink changed during metadata copy")
	}
	dest, err := pinSymlinkAt(destParent, destName)
	if err != nil {
		return err
	}
	defer dest.Close()
	openedDest, err := dest.Stat()
	if err != nil {
		return err
	}
	if !sameIdentity(openedDest, destInfo) {
		return fmt.Errorf("destination symlink changed during metadata copy")
	}
	if err = fdSetTimes(dest, accessTime(info), info.ModTime()); err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot read symlink descriptor metadata")
	}
	if err = syscall.Fchflags(int(dest.Fd()), int(st.Flags)); err != nil {
		return err
	}
	if err = verifyCopyLeaf(srcParent, srcName, source); err != nil {
		return err
	}
	return verifyCopyLeaf(destParent, destName, dest)
}
