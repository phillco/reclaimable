//go:build !darwin && !linux

package main

import (
	"fmt"
	"os"
)

func refuseExtendedDataFD(file *os.File) error {
	return fmt.Errorf("extended attribute inspection unavailable")
}
func refuseSymlinkExtendedDataAt(parent *os.File, name string, pinned *os.File) error {
	return fmt.Errorf("symlink attribute inspection unavailable")
}
