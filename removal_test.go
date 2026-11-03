package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func removalWrite(t *testing.T, path, text string) {
	t.Helper()
	must(t, os.MkdirAll(filepath.Dir(path), 0755))
	must(t, os.WriteFile(path, []byte(text), 0644))
}
func removalAge(t *testing.T, path string, age float64) {
	t.Helper()
	when := time.Now().Add(-time.Duration(age * float64(time.Second)))
	must(t, os.Chtimes(filepath.Join(path, markerName), when, when))
}
func makeMovable(t *testing.T, e *testEnv, rel string) (string, string) {
	t.Helper()
	dest := filepath.Join(e.Root, "archive")
	f := e.make(t, rel, 30*day, map[string][]byte{"a.txt": []byte("hello"), "d/b.txt": []byte("bye")}, map[string]any{"owner": "t", "regenerate": "r", "kind": "scratch", "move_to": dest})
	return f, dest
}
func linkedWorktree(t *testing.T, e *testEnv, rel string) (string, string) {
	t.Helper()
	main := makeRepoWithRemote(t, e)
	wt := filepath.Join(e.Root, "data", rel)
	gitTest(t, main, "worktree", "add", "-q", "--detach", wt)
	must(t, writeJSON(filepath.Join(wt, markerName), map[string]any{"owner": "t", "regenerate": "git worktree add", "kind": "worktree"}))
	removalAge(t, wt, 30*day)
	return main, wt
}
func TestMoveVerifiesThenDeletes(t *testing.T) {
	e := newTestEnv(t)
	f, dest := makeMovable(t, e, "scratch1")
	v := e.A.evaluate(f, e.Cfg, e.Reg, true)
	check(t, v.Action == "move", "%+v", v)
	ok, detail := e.A.removeFolder(v, true, e.Cfg, e.Reg)
	check(t, ok && !exists(f), "%v %s", ok, detail)
	p := filepath.Join(dest, e.A.Hostname(), strings.TrimLeft(f, "/"), "d/b.txt")
	b, err := os.ReadFile(p)
	must(t, err)
	check(t, string(b) == "bye", "copied %q", b)
}
func TestHashMismatchKeepsSource(t *testing.T) {
	e := newTestEnv(t)
	f := e.make(t, "scratch2", 30*day, map[string][]byte{"a.txt": []byte("hello")}, nil)
	real := e.A.HashDir
	calls := 0
	e.A.HashDir = func(dir *os.File, root string) (map[string]string, error) {
		out, err := real(dir, root)
		calls++
		if calls == 2 {
			out["a.txt"] = strings.Repeat("0", 64)
		}
		return out, err
	}
	ok, detail := e.A.moveAndVerify(f, filepath.Join(e.Root, "archive"), nil, nil)
	check(t, !ok && strings.Contains(detail, "hash mismatch") && exists(filepath.Join(f, "a.txt")), "%v %s", ok, detail)
}
func TestMarkerTouchedAfterEvaluationIsKept(t *testing.T) {
	e := newTestEnv(t)
	f := e.make(t, "race", 30*day, nil, nil)
	v := e.A.evaluate(f, e.Cfg, e.Reg, true)
	must(t, os.Chtimes(filepath.Join(f, markerName), time.Now(), time.Now()))
	ok, detail := e.A.removeFolder(v, true, e.Cfg, e.Reg)
	check(t, !ok && exists(f) && strings.Contains(detail, "touched"), "%v %s", ok, detail)
}
func TestHoldAddedDuringMoveKeepsSource(t *testing.T) {
	e := newTestEnv(t)
	f, _ := makeMovable(t, e, "scratch1")
	v := e.A.evaluate(f, e.Cfg, e.Reg, true)
	real := e.A.MoveAndVerify
	e.A.MoveAndVerify = func(folder, dest string, remote []string, src map[string]string) (bool, string) {
		ok, detail := real(folder, dest, remote, src)
		check(t, e.A.main([]string{"hold", f, "late-reader"}) == 0, "hold command failed")
		return ok, detail
	}
	ok, detail := e.A.removeFolder(v, true, e.Cfg, e.Reg)
	check(t, !ok && exists(f) && strings.Contains(detail, "held"), "%v %s", ok, detail)
}
func TestLeaseAppearingDuringMoveKeepsSource(t *testing.T) {
	e := newTestEnv(t)
	f, _ := makeMovable(t, e, "scratch1")
	v := e.A.evaluate(f, e.Cfg, e.Reg, true)
	real := e.A.MoveAndVerify
	e.A.MoveAndVerify = func(folder, dest string, remote []string, src map[string]string) (bool, string) {
		ok, detail := real(folder, dest, remote, src)
		must(t, writeJSON(filepath.Join(e.Root, "leases/9.json"), map[string]any{"pid": os.Getpid(), "what": f}))
		return ok, detail
	}
	ok, detail := e.A.removeFolder(v, true, e.Cfg, e.Reg)
	check(t, !ok && exists(f) && strings.Contains(detail, "lease"), "%v %s", ok, detail)
}
func TestSourceModifiedDuringMoveKeepsSource(t *testing.T) {
	e := newTestEnv(t)
	f, _ := makeMovable(t, e, "scratch1")
	v := e.A.evaluate(f, e.Cfg, e.Reg, true)
	real := e.A.MoveAndVerify
	e.A.MoveAndVerify = func(folder, dest string, remote []string, src map[string]string) (bool, string) {
		ok, detail := real(folder, dest, remote, src)
		removalWrite(t, filepath.Join(f, "a.txt"), "changed after copy")
		return ok, detail
	}
	ok, detail := e.A.removeFolder(v, true, e.Cfg, e.Reg)
	check(t, !ok && exists(filepath.Join(f, "a.txt")) && strings.Contains(detail, "changed"), "%v %s", ok, detail)
}
func TestHoldAndRemovalShareOneLock(t *testing.T) {
	e := newTestEnv(t)
	f := e.make(t, "locked", 30*day, nil, nil)
	v := e.A.evaluate(f, e.Cfg, e.Reg, true)
	real := e.A.HoldLock
	entered := 0
	depth := 0
	e.A.HoldLock = func() (func(), error) {
		unlock, err := real()
		if err != nil {
			return nil, err
		}
		entered++
		depth++
		return func() { depth--; unlock() }, nil
	}
	realOpen := e.A.OpenFiles
	e.A.OpenFiles = func(folder string) string {
		check(t, depth == 1, "final check outside hold lock")
		return realOpen(folder)
	}
	ok, detail := e.A.removeFolder(v, true, e.Cfg, e.Reg)
	check(t, ok && entered == 1, "%v %s (%d locks)", ok, detail, entered)
	// The hold command must use this same boundary too.
	g := e.make(t, "held", 30*day, nil, nil)
	check(t, e.A.main([]string{"hold", g, "reader"}) == 0 && entered == 2, "hold did not take shared lock")
}

type removalInfo struct {
	os.FileInfo
	stat syscall.Stat_t
}

func (i removalInfo) Sys() any { return &i.stat }
func TestRmtreeDoesNotCrossFilesystems(t *testing.T) {
	e := newTestEnv(t)
	d := filepath.Join(e.Root, "t")
	removalWrite(t, filepath.Join(d, "sub/f"), "x")
	removalWrite(t, filepath.Join(d, "mnt/keep"), "other fs")
	real := e.A.StatAt
	e.A.StatAt = func(parent *os.File, name string, follow bool) (os.FileInfo, error) {
		info, err := real(parent, name, follow)
		if err == nil && name == "mnt" {
			st := *info.Sys().(*syscall.Stat_t)
			st.Dev++
			return removalInfo{info, st}, nil
		}
		return info, err
	}

	left, err := e.A.rmtreeSameDev(d)
	must(t, err)
	check(t, len(left) == 1 && left[0] == filepath.Join(d, "mnt") && exists(filepath.Join(d, "mnt/keep")) && !exists(filepath.Join(d, "sub")), "left %v", left)
}
func TestSymlinkRootAndAncestorRefusedEverywhere(t *testing.T) {
	e := newTestEnv(t)
	real := e.make(t, "real", 30*day, map[string][]byte{"keep.txt": []byte("precious")}, nil)
	link := filepath.Join(e.Root, "data/link")
	must(t, os.Symlink(real, link))
	for _, p := range []string{link, filepath.Join(link, "sub")} {
		check(t, e.A.main([]string{"mark", p, "-o", "t", "-r", "r"}) == 2, "mark accepted symlink %s", p)
	}
	v := e.A.evaluate(link, e.Cfg, e.Reg, true)
	check(t, !v.Safe && strings.Contains(v.Reason, "symlink"), "%+v", v)
	v.Safe = true
	v.Action = "delete"
	ok, detail := e.A.removeFolder(v, true, e.Cfg, e.Reg)
	info, err := os.Lstat(link)
	must(t, err)
	b, err := os.ReadFile(filepath.Join(real, "keep.txt"))
	must(t, err)
	check(t, !ok && info.Mode()&os.ModeSymlink != 0 && string(b) == "precious", "%v %s", ok, detail)
	_, err = e.A.rmtreeSameDev(link)
	check(t, err != nil && exists(filepath.Join(real, "keep.txt")), "rmtree accepted symlink")
}
func TestDirtyFileAddedAfterEvaluationBlocksRemoval(t *testing.T) {
	e := newTestEnv(t)
	_, wt := linkedWorktree(t, e, "wt2")
	v := e.A.evaluate(wt, e.Cfg, e.Reg, true)
	check(t, v.Safe && v.Repo == "git-linked", "%+v", v)
	p := filepath.Join(wt, "uncommitted.txt")
	removalWrite(t, p, "precious")
	ok, detail := e.A.removeFolder(v, true, e.Cfg, e.Reg)
	b, err := os.ReadFile(p)
	must(t, err)
	check(t, !ok && strings.Contains(detail, "dirty") && string(b) == "precious", "%v %s", ok, detail)
}
func TestUnpushedCommitAfterEvaluationBlocksRemoval(t *testing.T) {
	e := newTestEnv(t)
	_, wt := linkedWorktree(t, e, "wt3")
	v := e.A.evaluate(wt, e.Cfg, e.Reg, true)
	check(t, v.Safe, "%+v", v)
	removalWrite(t, filepath.Join(wt, "c"), "1")
	gitTest(t, wt, "add", "c")
	gitTest(t, wt, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "c")
	ok, detail := e.A.removeFolder(v, true, e.Cfg, e.Reg)
	check(t, !ok && strings.Contains(detail, "unpushed") && exists(wt), "%v %s", ok, detail)
}
func TestNestedRepoDirtiedAfterEvaluationBlocksRemoval(t *testing.T) {
	e := newTestEnv(t)
	main := makeRepoWithRemote(t, e)
	f := e.make(t, "mir4", 30*day, nil, map[string]any{"kind": "mirror"})
	gitTest(t, main, "worktree", "add", "-q", "--detach", filepath.Join(f, "wt"))
	v := e.A.evaluate(f, e.Cfg, e.Reg, true)
	check(t, v.Safe, "%+v", v)
	p := filepath.Join(f, "wt/new.txt")
	removalWrite(t, p, "x")
	ok, detail := e.A.removeFolder(v, true, e.Cfg, e.Reg)
	check(t, !ok && strings.Contains(detail, "nested repo wt") && exists(p), "%v %s", ok, detail)
}
func TestDirtyFileAddedDuringMoveKeepsSource(t *testing.T) {
	e := newTestEnv(t)
	_, wt := linkedWorktree(t, e, "wt5")
	m, err := e.A.readMarker(wt)
	must(t, err)
	m.MoveTo = filepath.Join(e.Root, "arch")
	must(t, e.A.writeMarker(m))
	removalAge(t, wt, 30*day)
	v := e.A.evaluate(wt, e.Cfg, e.Reg, true)
	check(t, v.Safe && v.Action == "move", "%+v", v)
	real := e.A.MoveAndVerify
	e.A.MoveAndVerify = func(folder, dest string, remote []string, src map[string]string) (bool, string) {
		ok, detail := real(folder, dest, remote, src)
		removalWrite(t, filepath.Join(wt, "late.txt"), "late")
		return ok, detail
	}
	ok, detail := e.A.removeFolder(v, true, e.Cfg, e.Reg)
	check(t, !ok && exists(filepath.Join(wt, "late.txt")), "%v %s", ok, detail)
}

func TestHashWalkErrorKeepsSource(t *testing.T) {
	e := newTestEnv(t)
	f, _ := makeMovable(t, e, "hash-error")
	v := e.A.evaluate(f, e.Cfg, e.Reg, true)
	real := e.A.FileHashes
	e.A.FileHashes = func(path string) (map[string]string, error) {
		if path == f {
			return nil, os.ErrPermission
		}
		return real(path)
	}
	ok, detail := e.A.removeFolder(v, true, e.Cfg, e.Reg)
	check(t, !ok && exists(f) && strings.Contains(detail, "hash failed"), "%v %s", ok, detail)
}
func TestRemoteHashFailuresFailClosed(t *testing.T) {
	e := newTestEnv(t)
	remote := []string{"sh", "-c", "{script}"}
	_, err := e.A.remoteHashes("unused", filepath.Join(e.Root, "missing"), remote)
	check(t, err != nil, "failed cd accepted as manifest")
	e.A.Run = func(argv []string, timeout float64, cwd string, env []string) Result {
		return Result{Code: 0, Stdout: "not-a-checksum  ./f\n"}
	}
	_, err = e.A.remoteHashes("unused", e.Root, remote)
	check(t, err != nil, "malformed checksum accepted")
	e.A.Run = func(argv []string, timeout float64, cwd string, env []string) Result {
		return Result{Code: 1, Stdout: strings.Repeat("a", 64) + "  ./f\n"}
	}
	_, err = e.A.remoteHashes("unused", e.Root, remote)
	check(t, err != nil, "partial failed manifest accepted")
}
func TestRemoteHashSymlinksMatchLocal(t *testing.T) {
	e := newTestEnv(t)
	root := filepath.Join(e.Root, "hashes")
	removalWrite(t, filepath.Join(root, "space name"), "content")
	must(t, os.Symlink("space name", filepath.Join(root, "link")))
	local, err := e.A.fileHashes(root)
	must(t, err)
	remote, err := e.A.remoteHashes("unused", root, []string{"sh", "-c", "{script}"})
	must(t, err)
	check(t, len(local) == len(remote), "local %v remote %v", local, remote)
	for k, v := range local {
		check(t, remote[k] == v, "path %q local %q remote %q", k, v, remote[k])
	}
}
func TestHashingAndCopyingDoNotFollowSymlinks(t *testing.T) {
	e := newTestEnv(t)
	f, dest := makeMovable(t, e, "links")
	outside := filepath.Join(e.Root, "outside")
	removalWrite(t, filepath.Join(outside, "keep"), "precious")
	must(t, os.Symlink(outside, filepath.Join(f, "directory-link")))
	must(t, os.Symlink(filepath.Join(outside, "keep"), filepath.Join(f, "file-link")))
	v := e.A.evaluate(f, e.Cfg, e.Reg, true)
	check(t, v.Safe, "%+v", v)
	ok, detail := e.A.removeFolder(v, true, e.Cfg, e.Reg)
	check(t, ok, "%v %s", ok, detail)
	_, copied := e.A.moveDestination(dest, f)
	for _, name := range []string{"directory-link", "file-link"} {
		st, err := os.Lstat(filepath.Join(copied, name))
		must(t, err)
		check(t, st.Mode()&os.ModeSymlink != 0, "link copied as content: %s", name)
	}
	b, err := os.ReadFile(filepath.Join(outside, "keep"))
	must(t, err)
	check(t, string(b) == "precious", "symlink target modified")
}

func TestLocalCopyPreservesTimesAndModes(t *testing.T) {
	e := newTestEnv(t)
	src := filepath.Join(e.Root, "metadata-source")
	file := filepath.Join(src, "sub/file")
	removalWrite(t, file, "content")
	must(t, os.Chmod(file, 0640))
	must(t, os.Chmod(filepath.Dir(file), 0750|os.ModeSticky))
	at := time.Unix(1600000000, 123000000)
	mt := time.Unix(1600000100, 456000000)
	for _, p := range []string{file, filepath.Dir(file), src} {
		must(t, os.Chtimes(p, at, mt))
	}
	dest := filepath.Join(e.Root, "metadata-copy")
	must(t, e.A.copyTree(src, dest))
	for _, rel := range []string{"sub/file", "sub", "."} {
		got, err := os.Stat(filepath.Join(dest, rel))
		must(t, err)
		check(t, got.ModTime().Equal(mt) && accessTime(got).Equal(at), "%s times at=%v mt=%v", rel, accessTime(got), got.ModTime())
	}
	copied, err := os.Stat(filepath.Join(dest, "sub/file"))
	must(t, err)
	check(t, copied.Mode().Perm() == 0640, "mode %v", copied.Mode())
	dir, err := os.Stat(filepath.Join(dest, "sub"))
	must(t, err)
	check(t, dir.Mode()&os.ModeSticky != 0 && dir.Mode().Perm() == 0750, "directory mode %v", dir.Mode())
}
func TestJobStateChangeAfterEvaluationBlocksRemoval(t *testing.T) {
	for _, later := range []string{"open", "garbage", "missing"} {
		t.Run(later, func(t *testing.T) {
			e := newTestEnv(t)
			e.setJob(t, "9", "closed 2020-01-01T00:00:00Z")
			f := e.make(t, "job1", 30*day, nil, map[string]any{"job": "9", "kind": "scratch"})
			v := e.A.evaluate(f, e.Cfg, e.Reg, true)
			check(t, v.Safe && v.Expired, "%s", debugVerdict(v))
			if later == "missing" {
				must(t, os.Remove(filepath.Join(e.Jobs, "9")))
			} else {
				e.setJob(t, "9", later)
			}
			ok, detail := e.A.removeFolder(v, true, e.Cfg, e.Reg)
			check(t, !ok && exists(f) && strings.Contains(detail, "job 9"), "%v %s", ok, detail)
			cached := dict(mapEntry(e.Reg, "jobs")["9"])
			check(t, !truth(cached["closed"]), "stale positive answer retained")
		})
	}
}
func TestJobStillClosedRemoves(t *testing.T) {
	e := newTestEnv(t)
	e.setJob(t, "9", "closed 2020-01-01T00:00:00Z")
	f := e.make(t, "job2", 30*day, nil, map[string]any{"job": "9", "kind": "scratch"})
	v := e.A.evaluate(f, e.Cfg, e.Reg, true)
	ok, detail := e.A.removeFolder(v, true, e.Cfg, e.Reg)
	check(t, ok && !exists(f), "%v %s", ok, detail)
}
func TestJobLabelAddedDuringMoveKeepsSource(t *testing.T) {
	e := newTestEnv(t)
	e.setJob(t, "9", "closed 2020-01-01T00:00:00Z")
	f, _ := makeMovable(t, e, "job3")
	m, err := e.A.readMarker(f)
	must(t, err)
	m.Job = "9"
	must(t, e.A.writeMarker(m))
	removalAge(t, f, 30*day)
	v := e.A.evaluate(f, e.Cfg, e.Reg, true)
	check(t, v.Safe && v.Action == "move", "%s", debugVerdict(v))
	real := e.A.MoveAndVerify
	e.A.MoveAndVerify = func(folder, dest string, remote []string, src map[string]string) (bool, string) {
		ok, detail := real(folder, dest, remote, src)
		must(t, os.Remove(filepath.Join(e.Jobs, "9")))
		return ok, detail
	}
	ok, detail := e.A.removeFolder(v, true, e.Cfg, e.Reg)
	check(t, !ok && exists(f) && strings.Contains(detail, "job 9"), "%v %s", ok, detail)
}
func TestSessionStartsAfterEvaluationBlocksRemoval(t *testing.T) {
	e := newTestEnv(t)
	e.A.SessionRunning = func(string) string { return "gone" }
	f := e.make(t, "session-race", 30*day, nil, map[string]any{"session": "999999"})
	v := e.A.evaluate(f, e.Cfg, e.Reg, true)
	check(t, v.Safe, "%s", debugVerdict(v))
	e.A.SessionRunning = func(string) string { return "alive" }
	ok, detail := e.A.removeFolder(v, true, e.Cfg, e.Reg)
	check(t, !ok && exists(f) && strings.Contains(detail, "still running"), "%v %s", ok, detail)
}

func TestReclosedJobRestartsTTLBeforeRemoval(t *testing.T) {
	e := newTestEnv(t)
	e.setJob(t, "9", "closed 2020-01-01T00:00:00Z")
	f := e.make(t, "reclosed", 30*day, nil, map[string]any{"job": "9", "kind": "scratch"})
	v := e.A.evaluate(f, e.Cfg, e.Reg, true)
	check(t, v.Safe && v.Expired, "%s", debugVerdict(v))
	e.setJob(t, "9", fmt.Sprintf("closed %.0f", e.A.Now()-60))
	ok, detail := e.A.removeFolder(v, true, e.Cfg, e.Reg)
	check(t, !ok && exists(f) && strings.Contains(detail, "no longer expired"), "%v %s", ok, detail)
}

func TestJobReclosedRecentlyKeepsTtlCandidate(t *testing.T) {
	e := newTestEnv(t)
	e.setJob(t, "9", fmt.Sprintf("closed %.0f", e.A.Now()-30*day))
	f := e.make(t, "rc1", 30*day, nil, map[string]any{"job": "9", "kind": "scratch"})
	v := e.A.evaluate(f, e.Cfg, e.Reg, true)
	check(t, v.Safe && v.Expired, "%s", debugVerdict(v))
	e.setJob(t, "9", fmt.Sprintf("closed %.0f", e.A.Now()-60))
	ok, detail := e.A.removeFolder(v, true, e.Cfg, e.Reg)
	check(t, !ok && exists(f) && strings.Contains(detail, "no longer expired"), "%v %s", ok, detail)
}
func TestFloorPressureCandidateIgnoresRecomputedClock(t *testing.T) {
	e := newTestEnv(t)
	e.setJob(t, "9", fmt.Sprintf("closed %.0f", e.A.Now()-30*day))
	f := e.make(t, "rc2", 30*day, nil, map[string]any{"job": "9", "kind": "scratch"})
	v := e.A.evaluate(f, e.Cfg, e.Reg, true)
	e.setJob(t, "9", fmt.Sprintf("closed %.0f", e.A.Now()-60))
	ok, detail := e.A.removeFolder(v, true, e.Cfg, e.Reg, true)
	check(t, ok && !exists(f), "%v %s", ok, detail)
}
func TestJobReclosedDuringMoveKeepsSource(t *testing.T) {
	e := newTestEnv(t)
	e.setJob(t, "9", fmt.Sprintf("closed %.0f", e.A.Now()-30*day))
	f, _ := makeMovable(t, e, "rc3")
	m, err := e.A.readMarker(f)
	must(t, err)
	m.Job = "9"
	must(t, e.A.writeMarker(m))
	removalAge(t, f, 30*day)
	v := e.A.evaluate(f, e.Cfg, e.Reg, true)
	check(t, v.Safe && v.Expired && v.Action == "move", "%s", debugVerdict(v))
	real := e.A.MoveAndVerify
	e.A.MoveAndVerify = func(folder, dest string, remote []string, src map[string]string) (bool, string) {
		ok, detail := real(folder, dest, remote, src)
		e.setJob(t, "9", fmt.Sprintf("closed %.0f", e.A.Now()-30))
		return ok, detail
	}
	ok, detail := e.A.removeFolder(v, true, e.Cfg, e.Reg)
	check(t, !ok && exists(f) && strings.Contains(detail, "no longer expired"), "%v %s", ok, detail)
}
func TestSweepTtlSelectedCandidateStillRemoved(t *testing.T) {
	e := newTestEnv(t)
	e.setJob(t, "9", fmt.Sprintf("closed %.0f", e.A.Now()-30*day))
	f := e.make(t, "rc4", 30*day, nil, map[string]any{"job": "9", "kind": "scratch"})
	must(t, writeJSON(e.A.ArmedFile, map[string]any{"armed_at": e.A.Now() - 2*day}))
	check(t, e.A.sweep(Args{Scan: true}, e.Cfg) == 0, "sweep failed")
	check(t, !exists(f), "TTL-selected folder kept")
}
