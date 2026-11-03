package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
)

func (a *App) fileHashes(root string) (map[string]string, error) {
	dir, err := openPathDir(root)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	return a.HashDir(dir, root)
}
func (a *App) fileHashesAt(rootDir *os.File, root string) (map[string]string, error) {
	out := map[string]string{}
	err := a.walkPayload(rootDir, func(parent, file *os.File, name, relative string, st os.FileInfo) error {
		switch {
		case st.Mode()&os.ModeSymlink != 0:
			link, err := readlinkAt(parent, name)
			if err != nil {
				return err
			}
			out[relative] = "link:" + link
		case st.Mode().IsRegular():
			h := sha256.New()
			if _, err := io.Copy(h, file); err != nil {
				return err
			}
			out[relative] = fmt.Sprintf("%x", h.Sum(nil))
		}
		return nil
	})
	return out, err
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_@%+=:,./-", r))
	}) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}
func (a *App) remoteRun(remote []string, host, script string) Result {
	if len(remote) == 0 {
		remote = defaultRemoteCommand
	}
	cmd := make([]string, len(remote))
	for i, arg := range remote {
		cmd[i] = strings.ReplaceAll(strings.ReplaceAll(arg, "{host}", host), "{script}", script)
	}
	return a.Run(cmd, 300, "", nil)
}
func (a *App) remoteHashes(host, path string, remote []string) (map[string]string, error) {
	res := a.remoteRun(remote, host, remoteArchiveScript("hash", path))
	if res.Err != nil || res.Timeout || res.Code != 0 {
		return nil, fmt.Errorf("remote hash failed")
	}
	dec := json.NewDecoder(strings.NewReader(res.Stdout))
	token, err := dec.Token()
	if err != nil || token != json.Delim('{') {
		return nil, fmt.Errorf("invalid remote manifest")
	}
	out := map[string]string{}
	for dec.More() {
		token, err = dec.Token()
		if err != nil {
			return nil, err
		}
		rel, ok := token.(string)
		if !ok {
			return nil, fmt.Errorf("invalid manifest path")
		}
		if _, ok := out[rel]; ok {
			return nil, fmt.Errorf("duplicate manifest path")
		}
		if rel == "" || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, "../") || strings.ContainsRune(rel, 0) {
			return nil, fmt.Errorf("invalid manifest path")
		}
		var digest string
		if err = dec.Decode(&digest); err != nil {
			return nil, err
		}
		if !strings.HasPrefix(digest, "link:") {
			if len(digest) != 64 {
				return nil, fmt.Errorf("invalid remote checksum")
			}
			for _, c := range digest {
				if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
					return nil, fmt.Errorf("invalid remote checksum")
				}
			}
		}
		out[rel] = digest
	}
	if _, err = dec.Token(); err != nil {
		return nil, err
	}
	var extra any
	if err = dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("trailing remote manifest data")
	}
	return out, nil
}

func (a *App) moveDestination(destRoot, folder string) (host, dest string) {
	host, root, found := strings.Cut(destRoot, ":")
	if !found || strings.Contains(host, "/") {
		host = ""
		root = destRoot
	}
	rel := a.Hostname() + folder
	if host == "" {
		return "", filepath.Join(a.expand(root), rel)
	}
	return host, strings.TrimRight(root, "/") + "/" + rel
}
func withoutMarker(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		if k != markerName {
			out[k] = v
		}
	}
	return out
}
func pyStrings(values []string) string {
	quoted := make([]string, len(values))
	for i, v := range values {
		quoted[i] = "'" + strings.ReplaceAll(strings.ReplaceAll(v, "\\", "\\\\"), "'", "\\'") + "'"
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}
func (a *App) moveAndVerify(folder, destRoot string, remote []string, src map[string]string) (bool, string) {
	host, dest := a.moveDestination(destRoot, folder)
	var err error
	if src == nil {
		src, err = a.FileHashes(folder)
		if err != nil {
			return false, "source hash failed: " + err.Error()
		}
	}
	src = withoutMarker(src)
	var got map[string]string
	if host != "" {
		ok, detail := a.remoteCopyVerified(folder, dest, host, remote, src)
		if !ok {
			return false, detail
		}
		got, err = a.remoteHashes(host, dest, remote)
		if err != nil {
			return false, "remote hash failed"
		}
	} else {
		if _, err = os.Lstat(dest); err == nil {
			return false, "destination exists: " + dest
		} else if !os.IsNotExist(err) {
			return false, "destination unreadable: " + err.Error()
		}
		target, copyErr := a.copyTreePinned(folder, dest)
		if copyErr != nil {
			return false, "copy failed: " + copyErr.Error()
		}
		defer target.Close()
		got, err = a.HashDir(target, dest)
		if err != nil {
			return false, "destination hash failed: " + err.Error()
		}
	}
	got = withoutMarker(got)
	prefix := ""
	if host != "" {
		prefix = host + ":"
	}
	if !reflect.DeepEqual(got, src) {
		missing, changed := []string{}, []string{}
		for k, v := range src {
			if seen, ok := got[k]; !ok {
				missing = append(missing, k)
			} else if seen != v {
				changed = append(changed, k)
			}
		}
		sort.Strings(missing)
		sort.Strings(changed)
		if len(missing) > 3 {
			missing = missing[:3]
		}
		if len(changed) > 3 {
			changed = changed[:3]
		}
		return false, fmt.Sprintf("hash mismatch at %s%s (missing %s, changed %s)", prefix, dest, pyStrings(missing), pyStrings(changed))
	}
	current, hashErr := a.FileHashes(folder)
	if hashErr != nil {
		return false, "source hash failed: " + hashErr.Error()
	}
	if !reflect.DeepEqual(withoutMarker(current), src) {
		return false, "source changed while it was being copied"
	}
	return true, prefix + dest
}
func (a *App) rmtreeSameDev(path string) ([]string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	parent, err := openPathDir(filepath.Dir(absolute))
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	name := filepath.Base(absolute)
	st, err := a.StatAt(parent, name, false)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("refusing to remove %s: not a real directory", path)
	}
	return a.clearDirectoryAt(parent, name, path, st)
}
func (a *App) clearDirectoryAt(parent *os.File, name, logical string, want os.FileInfo) ([]string, error) {
	dev := device(want)
	left := []string{}
	var clear func(*os.File, string, string, os.FileInfo) bool
	clear = func(parent *os.File, name, path string, want os.FileInfo) bool {

		dir, err := openAt(parent, name, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			left = append(left, path)
			return false
		}
		defer dir.Close()
		opened, err := dir.Stat()
		if err != nil || device(opened) != dev {
			left = append(left, path)
			return false
		}

		entries, err := dir.ReadDir(-1)
		if err != nil {
			left = append(left, path)
			return false
		}
		ok := true
		for _, entry := range entries {
			leaf := entry.Name()
			childPath := filepath.Join(path, leaf)
			st, err := a.StatAt(dir, leaf, false)
			if err != nil {
				left = append(left, childPath)
				ok = false
				continue
			}
			if device(st) != dev {
				left = append(left, childPath)
				ok = false
				continue
			}
			if st.IsDir() {
				if !clear(dir, leaf, childPath, st) {
					ok = false
				}
				continue
			}

			if err := unlinkAt(dir, leaf, false); err != nil {
				left = append(left, childPath)
				ok = false
			}
		}
		if !ok {
			return false
		}

		if err := unlinkAt(parent, name, true); err != nil {
			left = append(left, path)
			return false
		}
		return true
	}
	clear(parent, name, logical, want)
	return left, nil
}

func (a *App) removeFolder(v *Verdict, armed bool, cfg *Config, reg map[string]any, floorPressure ...bool) (bool, string) {
	if !armed {
		return false, "dry-run"
	}
	if v.Marker == nil {
		return false, "marker unavailable"
	}
	if isMount(v.Folder) {
		return false, "folder is a mount point"
	}
	pressure := len(floorPressure) > 0 && floorPressure[0]
	check := func() (*Verdict, string) {
		fresh := a.evaluateChecked(v.Folder, cfg, reg, true, true)
		if fresh.Marker == nil {
			return fresh, "marker changed: " + fresh.Reason
		}
		if fresh.Marker.Mtime != v.Marker.Mtime || len(fresh.Marker.Holds) > 0 {
			return fresh, "marker touched or held since evaluation"
		}
		if !fresh.Safe {
			return fresh, fresh.Reason
		}
		if !pressure && !fresh.Expired {
			return fresh, "no longer expired (clock restarted " + humanAge(a.Now()-fresh.ClockStart) + " ago, ttl " + humanAge(fresh.TTLS) + ")"
		}
		return fresh, ""
	}
	destDetail := ""
	var src map[string]string
	if v.Action == "move" {
		unlock, err := a.HoldLock()
		if err != nil {
			return false, "hold lock failed: " + err.Error()
		}
		_, problem := check()
		unlock()
		if problem != "" {
			return false, problem
		}
		var errHash error
		src, errHash = a.FileHashes(v.Folder)
		if errHash != nil {
			return false, "kept source: source hash failed: " + errHash.Error()
		}
		src = withoutMarker(src)
		ok, detail := a.MoveAndVerify(v.Folder, v.Dest, cfg.RemoteCommand, src)
		if !ok {
			return false, "kept source: " + detail
		}
		destDetail = " -> " + detail
	}
	unlock, err := a.HoldLock()
	if err != nil {
		return false, "hold lock failed: " + err.Error()
	}
	defer unlock()
	fresh, problem := check()
	if problem != "" {
		if v.Action == "move" {
			return false, "kept source" + destDetail + ": " + problem
		}
		return false, problem
	}
	if src != nil {
		current, err := a.FileHashes(v.Folder)
		if err != nil {
			return false, "source hash failed: " + err.Error()
		}
		if !reflect.DeepEqual(withoutMarker(current), src) {
			return false, "source changed while it was being copied"
		}
	}
	common := ""
	if fresh.Repo == "git-linked" {
		res := a.Run([]string{"git", "-C", v.Folder, "rev-parse", "--git-common-dir"}, 30, "", nil)
		if !unavailable(res) && res.Code == 0 {
			common = strings.TrimSpace(res.Stdout)
			if !filepath.IsAbs(common) {
				common = filepath.Join(v.Folder, common)
			}
			if real, err := filepath.EvalSymlinks(common); err == nil {
				common = real
			}
		}
	}
	if fresh.Repo == "jj-secondary" {
		res := a.Run([]string{"jj", "-R", v.Folder, "--ignore-working-copy", "workspace", "forget"}, 60, "", nil)
		if unavailable(res) || res.Code != 0 {
			return false, "jj workspace forget failed: " + shortText(strings.TrimSpace(res.Stderr), 100)
		}
	}
	left, err := a.rmtreeSameDev(v.Folder)
	if err != nil {
		return false, "removal failed: " + err.Error()
	}
	if len(left) > 0 {
		return false, fmt.Sprintf("removal incomplete: %d entries kept", len(left))
	}
	if common != "" {
		a.Run([]string{"git", "--git-dir", common, "worktree", "prune"}, 60, "", nil)
	}
	delete(mapEntry(reg, "markers"), v.Folder)
	return true, destDetail
}
