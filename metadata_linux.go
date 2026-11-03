package main

import (
	"fmt"
	"os"
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
func copyMetadataFD(src, dest *os.File, info os.FileInfo) error {
	if err := fdSetTimes(dest, accessTime(info), info.ModTime()); err != nil {
		return err
	}
	return dest.Chmod(info.Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky))
}

// Linux xattr inspection uses a no-follow leaf below the pinned parent.
// Missing procfs refuses inspection and therefore keeps the source.
func linkProcPath(parent *os.File, name string) (*byte, error) {
	if _, err := atName(name); err != nil {
		return nil, err
	}
	return syscall.BytePtrFromString(fmt.Sprintf("/proc/self/fd/%d/%s", parent.Fd(), name))
}
func copySymlinkMetadataAt(srcParent *os.File, srcName string, destParent *os.File, destName string, info, destInfo os.FileInfo) error {
	dest, err := pinSymlinkAt(destParent, destName)
	if err != nil {
		return err
	}
	defer dest.Close()
	return fdSetTimes(dest, accessTime(info), info.ModTime())
}
