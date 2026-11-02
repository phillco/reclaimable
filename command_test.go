package main

import (
	"testing"
	"time"
)

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
