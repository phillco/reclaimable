//go:build !darwin && !linux

package main

import (
	"os"
	"time"
)

func changeTime(info os.FileInfo) time.Time { return info.ModTime() }
