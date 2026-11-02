//go:build !darwin && !linux

package main

import (
	"fmt"
	"os"
	"time"
)

func accessTime(info os.FileInfo) time.Time { return info.ModTime() }
func copyMetadata(src, dest string, info os.FileInfo) error {
	return fmt.Errorf("metadata-preserving local moves are supported on macOS and Linux")
}

func symlinkCopyArgs(src, dest string) []string { return []string{"/bin/cp", "-pRP", src, dest} }
