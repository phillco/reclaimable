package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCommandKillsDetachedDescendantsOnReturn(t *testing.T) {
	for _, pipes := range []string{"", ">/dev/null 2>&1"} {
		t.Run(pipes, func(t *testing.T) {
			pidFile := filepath.Join(t.TempDir(), "pid")
			r := runCommand([]string{"sh", "-c", "sleep 30 " + pipes + " & echo $! > \"$1\"", "fixture", pidFile}, 2, "", nil)
			check(t, !r.Timeout, "leader should exit first: %+v", r)
			b, err := os.ReadFile(pidFile)
			must(t, err)
			pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
			must(t, err)
			defer syscall.Kill(pid, syscall.SIGKILL)
			// A killed child can remain a zombie until reaped by init. It must
			// never execute a later write after the caller releases its lock.
			time.Sleep(20 * time.Millisecond)
			r = runCommand([]string{"ps", "-o", "stat=", "-p", strconv.Itoa(pid)}, 2, "", nil)
			check(t, r.Code == 1 || strings.HasPrefix(strings.TrimSpace(r.Stdout), "Z"), "descendant still running: %+v", r)
		})
	}
}

func TestCommandTimeoutBoundsDescendants(t *testing.T) {
	start := time.Now()
	r := runCommand([]string{"sh", "-c", "sleep 10 & wait"}, 0.05, "", nil)
	check(t, r.Timeout && time.Since(start) < 2*time.Second, "timeout did not bound descendant pipes: %+v %s", r, time.Since(start))
	r = runCommand([]string{"sleep", "1"}, 0, "", nil)
	check(t, r.Timeout, "zero timeout must be immediate")
}
func TestCommandSignalExitMatchesPython(t *testing.T) {
	r := runCommand([]string{"sh", "-c", "kill -TERM $$"}, 2, "", nil)
	check(t, r.Code == -15, "got code %d want -15", r.Code)
}
