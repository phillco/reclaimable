//go:build !darwin && !linux

package main

import (
	"fmt"
	"os"
	"time"
)

func accessTime(info os.FileInfo) time.Time { return info.ModTime() }
func copyMetadataFD(src, dest *os.File, info os.FileInfo) error {
	return fmt.Errorf("descriptor metadata copying is supported on macOS and Linux")
}
func copySymlinkMetadataAt(srcParent *os.File, srcName string, destParent *os.File, destName string, info, destInfo os.FileInfo) error {
	return fmt.Errorf("descriptor symlink metadata copying is supported on macOS and Linux")
}
