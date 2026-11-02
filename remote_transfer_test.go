package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestArchiveExportMatchesVerifiedManifest(t *testing.T) {
	e := newTestEnv(t)
	src := e.make(t, "export", 30*day, map[string][]byte{"a.txt": []byte("hello"), "d/b.txt": []byte("bye"), ".DS_Store": []byte("ignored"), "d/.DS_Store": []byte("ignored")}, nil)
	must(t, os.Symlink("../a.txt", filepath.Join(src, "d/link")))
	must(t, os.Mkdir(filepath.Join(src, "empty"), 0750))
	hashes, err := e.A.FileHashes(src)
	must(t, err)
	var out bytes.Buffer
	must(t, e.A.exportArchive(src, &out, withoutMarker(hashes)))
	got := map[string]string{}
	names := map[string]bool{}
	tr := tar.NewReader(bytes.NewReader(out.Bytes()))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		must(t, err)
		names[h.Name] = true
		switch h.Typeflag {
		case tar.TypeReg:
			b, err := io.ReadAll(tr)
			must(t, err)
			if h.Name != markerName {
				got[h.Name] = fmt.Sprintf("%x", sha256.Sum256(b))
			}
		case tar.TypeSymlink:
			got[h.Name] = "link:" + h.Linkname
		}
	}
	check(t, names[markerName] && names["empty/"] && !names[".DS_Store"] && !names["d/.DS_Store"], "archive names %v", names)
	check(t, len(got) == 3 && got["a.txt"] == hashes["a.txt"] && got["d/b.txt"] == hashes["d/b.txt"] && got["d/link"] == "link:../a.txt", "exported hashes %v", got)
}
func TestArchiveExportRejectsSwappedSourceEntries(t *testing.T) {
	for _, kind := range []string{"file", "directory", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			e := newTestEnv(t)
			src := e.make(t, "export", 30*day, map[string][]byte{"sub/file": []byte("fixture")}, nil)
			victim := filepath.Join(e.Root, "outside")
			removalWrite(t, filepath.Join(victim, "precious"), "outside bytes")
			must(t, os.Symlink("sub/file", filepath.Join(src, "link")))
			hashes, err := e.A.FileHashes(src)
			must(t, err)
			op, name, parent := "archive-read", "file", filepath.Join(src, "sub")
			if kind == "directory" {
				op, name, parent = "archive-descend", "sub", src
			}
			if kind == "symlink" {
				op, name, parent = "archive-link", "link", src
			}
			fired := false
			e.A.FSBefore = func(gotOp, gotParent, gotName string) {
				if fired || gotOp != op || gotParent != parent || gotName != name {
					return
				}
				fired = true
				must(t, os.Rename(filepath.Join(parent, name), filepath.Join(e.Root, "saved")))
				must(t, os.Symlink(victim, filepath.Join(parent, name)))
			}
			var archive bytes.Buffer
			err = e.A.exportArchive(src, &archive, withoutMarker(hashes))
			check(t, fired && err != nil, "archive accepted swapped %s: %v", kind, err)
			check(t, !bytes.Contains(archive.Bytes(), []byte("outside bytes")), "archive read outside sentinel")
			b, err := os.ReadFile(filepath.Join(victim, "precious"))
			must(t, err)
			check(t, string(b) == "outside bytes", "outside bytes changed")
		})
	}
}
func TestArchiveExportRefusesChangedBytes(t *testing.T) {
	e := newTestEnv(t)
	src := e.make(t, "export", 30*day, map[string][]byte{"file": []byte("fixture")}, nil)
	hashes, err := e.A.FileHashes(src)
	must(t, err)
	must(t, os.WriteFile(filepath.Join(src, "file"), []byte("changed"), 0600))
	var out bytes.Buffer
	check(t, e.A.exportArchive(src, &out, withoutMarker(hashes)) != nil, "archive accepted content changed since verification")
}

func TestArchiveExportPinsRenamedSourceRoot(t *testing.T) {
	e := newTestEnv(t)
	src := e.make(t, "export-root", 30*day, map[string][]byte{"file": []byte("fixture")}, nil)
	victim := filepath.Join(e.Root, "outside")
	removalWrite(t, filepath.Join(victim, "precious"), "outside bytes")
	hashes, err := e.A.FileHashes(src)
	must(t, err)
	fired := false
	e.A.FSBefore = func(op, parent, name string) {
		if fired || op != "archive-read" || parent != src || name != "file" {
			return
		}
		fired = true
		must(t, os.Rename(src, filepath.Join(e.Root, "saved-root")))
		must(t, os.Symlink(victim, src))
	}
	var archive bytes.Buffer
	err = e.A.exportArchive(src, &archive, withoutMarker(hashes))
	check(t, fired && err != nil, "archive accepted renamed source root")
	check(t, !bytes.Contains(archive.Bytes(), []byte("outside bytes")), "archive read outside target")
	b, err := os.ReadFile(filepath.Join(victim, "precious"))
	must(t, err)
	check(t, string(b) == "outside bytes", "outside bytes changed")
}
func TestArchiveExportRejectsMutationDuringRead(t *testing.T) {
	e := newTestEnv(t)
	src := e.make(t, "export-mutated", 30*day, map[string][]byte{"file": []byte("fixture")}, nil)
	hashes, err := e.A.FileHashes(src)
	must(t, err)
	fired := false
	e.A.FSBefore = func(op, parent, name string) {
		if fired || op != "archive-after-read" || parent != src || name != "file" {
			return
		}
		fired = true
		must(t, os.WriteFile(filepath.Join(parent, name), []byte("changed after archive read"), 0600))
	}
	var archive bytes.Buffer
	err = e.A.exportArchive(src, &archive, withoutMarker(hashes))
	check(t, fired && err != nil, "archive accepted mutation during read")
}

func TestRemoteTransferPreservesFilesAndLinks(t *testing.T) {
	e := newTestEnv(t)
	src := e.make(t, "transfer", 30*day, map[string][]byte{"nested/a\nb": []byte("payload")}, nil)
	must(t, os.Symlink("nested/a\nb", filepath.Join(src, "link")))
	hashes, err := e.A.FileHashes(src)
	must(t, err)
	dest := filepath.Join(e.Root, "archive's path", "received")
	ran := false
	real := e.A.RunInput
	e.A.RunInput = func(argv []string, timeout float64, cwd string, env []string, input io.Reader) Result {
		ran = true
		check(t, timeout == 300, "unbounded receiver timeout %v", timeout)
		return real(argv, timeout, cwd, env, input)
	}
	ok, detail := e.A.remoteCopyVerified(src, dest, "fixture", []string{"sh", "-c", "{script}"}, hashes)
	check(t, ran && ok && detail == dest, "remote transfer failed: %s", detail)
	got, err := e.A.FileHashes(dest)
	must(t, err)
	check(t, reflect.DeepEqual(withoutMarker(got), withoutMarker(hashes)), "remote bytes differ: %v", got)
	remoteHashes, err := e.A.remoteHashes("fixture", dest, []string{"sh", "-c", "{script}"})
	must(t, err)
	check(t, reflect.DeepEqual(remoteHashes, hashes), "remote manifest changed newline names: %v", remoteHashes)
	b, err := os.ReadFile(filepath.Join(dest, "nested/a\nb"))
	must(t, err)
	check(t, string(b) == "payload", "newline file lost")
	link, err := os.Readlink(filepath.Join(dest, "link"))
	must(t, err)
	check(t, link == "nested/a\nb", "newline link target lost")
	check(t, exists(src), "transfer removed source")
}
func TestRemoteTransferRefusesExistingDestination(t *testing.T) {
	e := newTestEnv(t)
	src := e.make(t, "transfer", 30*day, nil, nil)
	hashes, err := e.A.FileHashes(src)
	must(t, err)
	dest := filepath.Join(e.Root, "received")
	sentinel := filepath.Join(dest, "precious")
	removalWrite(t, sentinel, "outside bytes")
	ok, detail := e.A.remoteCopyVerified(src, dest, "fixture", []string{"sh", "-c", "{script}"}, hashes)
	check(t, !ok && strings.Contains(detail, "remote transfer failed") && exists(src), "accepted existing destination: %v %s", ok, detail)
	b, err := os.ReadFile(sentinel)
	must(t, err)
	entries, err := os.ReadDir(dest)
	must(t, err)
	check(t, string(b) == "outside bytes" && len(entries) == 1, "existing destination modified")
}
func TestRemoteTransferRefusesSymlinkDestinationParent(t *testing.T) {
	e := newTestEnv(t)
	src := e.make(t, "transfer", 30*day, nil, nil)
	hashes, err := e.A.FileHashes(src)
	must(t, err)
	outside := filepath.Join(e.Root, "outside")
	removalWrite(t, filepath.Join(outside, "precious"), "outside bytes")
	link := filepath.Join(e.Root, "redirect")
	must(t, os.Symlink(outside, link))
	ok, detail := e.A.remoteCopyVerified(src, filepath.Join(link, "received"), "fixture", []string{"sh", "-c", "{script}"}, hashes)
	check(t, !ok && exists(src), "accepted symlink ancestor: %s", detail)
	entries, err := os.ReadDir(outside)
	must(t, err)
	check(t, len(entries) == 1 && entries[0].Name() == "precious", "outside destination mutated")
}
func TestRemoteTransferNeverInvokesReceiverAfterExportFailure(t *testing.T) {
	e := newTestEnv(t)
	src := e.make(t, "transfer", 30*day, map[string][]byte{"file": []byte("fixture")}, nil)
	hashes, err := e.A.FileHashes(src)
	must(t, err)
	outside := filepath.Join(e.Root, "outside")
	removalWrite(t, outside, "outside bytes")
	fired, ran := false, false
	e.A.FSBefore = func(op, parent, name string) {
		if fired || op != "archive-read" || parent != src || name != "file" {
			return
		}
		fired = true
		must(t, os.Rename(filepath.Join(src, "file"), filepath.Join(e.Root, "saved-file")))
		must(t, os.Symlink(outside, filepath.Join(src, "file")))
	}
	e.A.RunInput = func([]string, float64, string, []string, io.Reader) Result { ran = true; return Result{Code: 0} }
	ok, detail := e.A.remoteCopyVerified(src, filepath.Join(e.Root, "received"), "fixture", []string{"unused"}, hashes)
	check(t, fired && !ran && !ok && exists(src), "receiver saw failed archive: %v %v %s", fired, ran, detail)
	b, err := os.ReadFile(outside)
	must(t, err)
	check(t, string(b) == "outside bytes", "outside bytes changed")
}
func TestRemoteTransferFailureKeepsSource(t *testing.T) {
	for _, result := range []Result{{Code: 2, Stderr: "receiver failed"}, {Code: -1, Err: os.ErrNotExist}, {Code: -9, Timeout: true}} {
		t.Run(fmt.Sprintf("%d_%v", result.Code, result.Timeout), func(t *testing.T) {
			e := newTestEnv(t)
			src := e.make(t, "transfer", 30*day, nil, nil)
			hashes, err := e.A.FileHashes(src)
			must(t, err)
			e.A.RunInput = func([]string, float64, string, []string, io.Reader) Result { return result }
			ok, detail := e.A.remoteCopyVerified(src, filepath.Join(e.Root, "received"), "fixture", []string{"unused"}, hashes)
			check(t, !ok && exists(src) && strings.HasPrefix(detail, "remote transfer failed:"), "failed transfer accepted: %v %s", ok, detail)
		})
	}
}
func TestRemoteAttributeInspectionFailsClosed(t *testing.T) {
	for _, names := range []string{"", "com.apple.provenance\x00", "user.fixture\x00", "com.apple.ResourceFork\x00"} {
		query := func(b []byte) (int, error) {
			if b != nil {
				copy(b, names)
			}
			return len(names), nil
		}
		err := refuseRemoteAttributeList(query)
		check(t, (err == nil) == (names == "" || names == "com.apple.provenance\x00"), "attribute decision for %q: %v", names, err)
	}
	check(t, refuseRemoteAttributeList(func([]byte) (int, error) { return 0, os.ErrPermission }) != nil, "failed inspection allowed")
}

func TestRemoteReceiverRejectsTraversalAndLinkParent(t *testing.T) {
	for _, kind := range []string{"parent", "absolute", "symlink-child", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			e := newTestEnv(t)
			outside := filepath.Join(e.Root, "outside")
			removalWrite(t, filepath.Join(outside, "precious"), "outside bytes")
			var data bytes.Buffer
			tw := tar.NewWriter(&data)
			switch kind {
			case "parent":
				must(t, tw.WriteHeader(&tar.Header{Name: "../outside/precious", Typeflag: tar.TypeReg, Mode: 0600, Size: 7}))
				_, err := tw.Write([]byte("changed"))
				must(t, err)
			case "absolute":
				must(t, tw.WriteHeader(&tar.Header{Name: filepath.Join(outside, "precious"), Typeflag: tar.TypeReg, Mode: 0600, Size: 7}))
				_, err := tw.Write([]byte("changed"))
				must(t, err)
			case "symlink-child":
				must(t, tw.WriteHeader(&tar.Header{Name: "redirect", Typeflag: tar.TypeSymlink, Mode: 0777, Linkname: outside}))
				must(t, tw.WriteHeader(&tar.Header{Name: "redirect/precious", Typeflag: tar.TypeReg, Mode: 0600, Size: 7}))
				_, err := tw.Write([]byte("changed"))
				must(t, err)
			case "hardlink":
				must(t, tw.WriteHeader(&tar.Header{Name: "hard", Typeflag: tar.TypeLink, Mode: 0600, Linkname: filepath.Join(outside, "precious")}))
			}
			must(t, tw.Close())
			result := e.A.RunInput([]string{"sh", "-c", remoteArchiveScript("receive", filepath.Join(e.Root, "received"))}, 5, "", nil, bytes.NewReader(data.Bytes()))
			check(t, result.Code != 0 || result.Err != nil, "unsafe archive accepted")
			b, err := os.ReadFile(filepath.Join(outside, "precious"))
			must(t, err)
			check(t, string(b) == "outside bytes", "archive mutated outside bytes")
		})
	}
}

func TestRemoteHashInventoryPreservesNewlines(t *testing.T) {
	e := newTestEnv(t)
	stage := filepath.Join(e.Root, "newline-stage")
	removalWrite(t, filepath.Join(stage, "a\nb"), "payload")
	must(t, os.Symlink("a\nb", filepath.Join(stage, "link\nname")))
	want, err := e.A.FileHashes(stage)
	must(t, err)
	got, err := e.A.remoteHashes("fixture", stage, []string{"sh", "-c", "{script}"})
	must(t, err)
	check(t, reflect.DeepEqual(got, want), "remote manifest altered newlines: %v vs %v", got, want)
}
func TestRemoteHashRefusesSymlinkRoot(t *testing.T) {
	e := newTestEnv(t)
	outside := filepath.Join(e.Root, "outside")
	removalWrite(t, filepath.Join(outside, "sentinel"), "keep")
	alias := filepath.Join(e.Root, "alias")
	must(t, os.Symlink(outside, alias))
	_, err := e.A.remoteHashes("fixture", alias, []string{"sh", "-c", "{script}"})
	check(t, err != nil, "remote hash followed symlink root")
}
func TestRemoteReceiverPinsNestedDirectoryAcrossMembers(t *testing.T) {
	e := newTestEnv(t)
	dest := filepath.Join(e.Root, "destination")
	outside := filepath.Join(e.Root, "outside")
	removalWrite(t, filepath.Join(outside, "sentinel"), "keep")
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	must(t, tw.WriteHeader(&tar.Header{Name: "child", Typeflag: tar.TypeDir, Mode: 0700}))
	must(t, tw.WriteHeader(&tar.Header{Name: "child/payload", Typeflag: tar.TypeReg, Mode: 0600, Size: 3}))
	_, err := tw.Write([]byte("new"))
	must(t, err)
	must(t, tw.Close())
	destJSON, _ := json.Marshal(dest)
	outsideJSON, _ := json.Marshal(outside)
	patch := fmt.Sprintf(`
destination = %s
outside = %s
original_stat = os.stat
observations = []
swapped = []
def patched_stat(path, *args, **kwargs):
    if path == "child" and kwargs.get("dir_fd") is not None:
        observations.append(True)
        if len(observations) == 4:
            os.rename(destination + "/child", destination + "/original-child")
            os.rename(outside, destination + "/child")
            swapped.append(True)
    return original_stat(path, *args, **kwargs)
os.stat = patched_stat
try:
    _remote_archive("receive", destination)
except OSError:
    pass
else:
    raise AssertionError("replaced nested directory accepted")
assert swapped
`, destJSON, outsideJSON)
	// The exported receiver imports these modules inside its function; the local
	// monkeypatch driver also needs them in its own global namespace.
	program := "import os\n" + remoteArchiveProgram + patch
	result := e.A.RunInput([]string{"python3", "-c", program}, 10, "", nil, bytes.NewReader(archive.Bytes()))
	check(t, result.Err == nil && !result.Timeout && result.Code == 0, "receiver pin test failed: %+v", result)
	b, err := os.ReadFile(filepath.Join(dest, "child/sentinel"))
	must(t, err)
	check(t, string(b) == "keep" && !exists(filepath.Join(dest, "child/payload")), "outside directory was written")
}
func TestRemoteTransferPreservesMarkerAge(t *testing.T) {
	e := newTestEnv(t)
	stage := filepath.Join(e.Root, "age-stage")
	marker := filepath.Join(stage, markerName)
	removalWrite(t, marker, "marker")
	// An exactly representable fractional second matches the Python float-time fixture.
	at := time.Unix(time.Now().Unix()-30*86400, 125000000)
	must(t, os.Chtimes(marker, at, at))
	before, err := os.Stat(marker)
	must(t, err)
	hashes, err := e.A.FileHashes(stage)
	must(t, err)
	dest := filepath.Join(e.Root, "destination")
	ok, detail := e.A.remoteCopyVerified(stage, dest, "fixture", []string{"sh", "-c", "{script}"}, hashes)
	check(t, ok, "transfer failed: %s", detail)
	after, err := os.Stat(filepath.Join(dest, markerName))
	must(t, err)
	// Python stat().st_mtime exposes float seconds, including its rounding.
	check(t, float64(after.ModTime().UnixNano())/1e9 == float64(before.ModTime().UnixNano())/1e9, "marker age changed: %v vs %v", after.ModTime(), before.ModTime())
}

func TestRemoteMoveRoundTripUsesLocalFixtureTransport(t *testing.T) {
	e := newTestEnv(t)
	root := e.make(t, "source", 30*day, map[string][]byte{"a\nb": []byte("payload")}, nil)
	archive := "fixture:" + filepath.Join(e.Root, "archive")
	ok, detail := e.A.moveAndVerify(root, archive, []string{"sh", "-c", "{script}"}, nil)
	check(t, ok, "remote move verification failed: %s", detail)
	check(t, exists(root), "verification removed source")
	_, dest := e.A.moveDestination(archive, root)
	content, err := os.ReadFile(filepath.Join(dest, "a\nb"))
	must(t, err)
	check(t, string(content) == "payload", "remote round trip altered newline-named file")
}
