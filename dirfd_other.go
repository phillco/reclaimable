//go:build (!darwin && !linux) || (!amd64 && !arm64)

package main

import (
	"fmt"
	"os"
)

func unsupportedAt() error {
	return fmt.Errorf("descriptor-relative operations require macOS or Linux on amd64 or arm64")
}
func openAt(parent *os.File, name string, flags int, mode uint32) (*os.File, error) {
	return nil, unsupportedAt()
}
func statAt(parent *os.File, name string, follow bool) (os.FileInfo, error) {
	return nil, unsupportedAt()
}
func unlinkAt(parent *os.File, name string, dir bool) error       { return unsupportedAt() }
func readlinkAt(parent *os.File, name string) (string, error)     { return "", unsupportedAt() }
func mkdirAt(parent *os.File, name string, mode uint32) error     { return unsupportedAt() }
func symlinkAt(target string, parent *os.File, name string) error { return unsupportedAt() }
func renameAt(oldParent *os.File, oldName string, newParent *os.File, newName string) error {
	return unsupportedAt()
}
