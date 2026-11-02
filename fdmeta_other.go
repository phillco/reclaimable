//go:build (!darwin && !linux) || (!amd64 && !arm64)

package main

import (
	"os"
	"time"
)

func pinSymlinkAt(parent *os.File, name string) (*os.File, error) { return nil, unsupportedAt() }
func fdSetTimes(file *os.File, atime, mtime time.Time) error      { return unsupportedAt() }
