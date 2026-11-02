package main

import (
	"os"
	"syscall"
	"time"
)

func changeTime(info os.FileInfo) time.Time {
	s := info.Sys().(*syscall.Stat_t)
	return time.Unix(int64(s.Ctim.Sec), int64(s.Ctim.Nsec))
}
