package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

func (a *App) fileHashes(root string) (map[string]string, error) {
	out := map[string]string{}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return nil, err
	}
	if !rootInfo.IsDir() {
		return nil, fmt.Errorf("not a real directory: %s", root)
	}
	err = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == root {
			return nil
		}
		if d.Name() == ".DS_Store" && !d.IsDir() {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			link, err := os.Readlink(p)
			if err != nil {
				return err
			}
			out[rel] = "link:" + link
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("cannot hash special file %s", p)
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		h := sha256.New()
		_, err = io.Copy(h, f)
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		out[rel] = fmt.Sprintf("%x", h.Sum(nil))
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
	return a.Run(cmd, -1, "", nil)
}
func (a *App) remoteHashes(host, path string, remote []string) (map[string]string, error) {
	// Each phase must succeed; a failed cd/find/checksum must never produce a
	// partial manifest that could authorize deleting the source.
	script := "cd " + shellQuote(path) + " && find . -type f ! -name .DS_Store -exec shasum -a 256 {} + && find . -type l -exec sh -c 'for l do target=$(readlink \"$l\") || exit; printf '\"'\"'link:%s  %s\\n'\"'\"' \"$target\" \"$l\"; done' sh {} +"
	res := a.remoteRun(remote, host, script)
	if res.Err != nil || res.Timeout || res.Code != 0 {
		return nil, fmt.Errorf("remote hash failed")
	}
	out := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(res.Stdout, "\n"), "\n") {
		if line == "" {
			continue
		}
		digest, rel, ok := strings.Cut(line, "  ")
		if !ok {
			return nil, fmt.Errorf("invalid remote manifest")
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
		rel = strings.TrimPrefix(rel, "./")
		if _, exists := out[rel]; exists {
			return nil, fmt.Errorf("duplicate remote manifest path")
		}
		out[rel] = digest
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
		mk := a.remoteRun(remote, host, "mkdir -p "+shellQuote(dest))
		if mk.Err != nil || mk.Timeout || mk.Code != 0 {
			return false, "mkdir on " + host + " failed"
		}
		r := a.Run([]string{"rsync", "-a", "--exclude", ".DS_Store", folder + "/", host + ":" + dest + "/"}, -1, "", nil)
		if r.Err != nil || r.Timeout || r.Code != 0 {
			detail := strings.TrimSpace(r.Stderr)
			if len(detail) > 120 {
				detail = detail[:120]
			}
			return false, "rsync failed: " + detail
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
		if err = os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
			return false, "copy failed: " + err.Error()
		}
		if err = a.copyTree(folder, dest); err != nil {
			return false, "copy failed: " + err.Error()
		}
		got, err = a.FileHashes(dest)
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
	return true, prefix + dest
}
func (a *App) copyTree(src, dest string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("not a real directory: %s", src)
	}
	if err = os.Mkdir(dest, 0700); err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() == ".DS_Store" {
			continue
		}
		from, to := filepath.Join(src, entry.Name()), filepath.Join(dest, entry.Name())
		st, err := os.Lstat(from)
		if err != nil {
			return err
		}
		switch {
		case st.Mode()&os.ModeSymlink != 0:
			// Native cp can set symlink timestamps and flags without following
			// the target, which the Go 1.22 os API cannot express.
			fromAbs, err := filepath.Abs(from)
			if err != nil {
				return err
			}
			toAbs, err := filepath.Abs(to)
			if err != nil {
				return err
			}
			res := a.Run(symlinkCopyArgs(fromAbs, toAbs), 60, "", nil)
			if res.Err != nil || res.Timeout || res.Code != 0 {
				return fmt.Errorf("symlink metadata copy failed: %s", strings.TrimSpace(res.Stderr))
			}
		case st.IsDir():
			if err = a.copyTree(from, to); err != nil {
				return err
			}
		case st.Mode().IsRegular():
			f, err := os.Open(from)
			if err != nil {
				return err
			}
			out, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				f.Close()
				return err
			}
			_, err = io.Copy(out, f)
			closeOut := out.Close()
			closeIn := f.Close()
			if err != nil {
				return err
			}
			if closeOut != nil {
				return closeOut
			}
			if closeIn != nil {
				return closeIn
			}
			if err = copyMetadata(from, to, st); err != nil {
				return err
			}
		default:
			return fmt.Errorf("cannot copy special file %s", from)
		}
	}
	return copyMetadata(src, dest, info)
}
func (a *App) rmtreeSameDev(path string) ([]string, error) {
	st, err := a.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("refusing to remove %s: not a real directory", path)
	}
	dev := device(st)
	left := []string{}
	sameDir := func(p string, want os.FileInfo) bool {
		got, err := a.Lstat(p)
		return err == nil && got.IsDir() && device(got) == dev && inode(got) == inode(want)
	}
	var clear func(string, os.FileInfo) bool
	clear = func(d string, want os.FileInfo) bool {
		if !sameDir(d, want) {
			left = append(left, d)
			return false
		}
		// Refuse a final-component symlink atomically when opening for enumeration,
		// then verify the opened directory still has the expected identity.
		f, err := os.OpenFile(d, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			left = append(left, d)
			return false
		}
		opened, err := f.Stat()
		if err != nil || !opened.IsDir() || device(opened) != dev || inode(opened) != inode(want) {
			f.Close()
			left = append(left, d)
			return false
		}
		entries, err := f.ReadDir(-1)
		closeErr := f.Close()
		if err != nil || closeErr != nil {
			left = append(left, d)
			return false
		}
		ok := true
		for _, e := range entries {
			if !sameDir(d, want) {
				left = append(left, d)
				return false
			}
			p := filepath.Join(d, e.Name())
			child, err := a.Lstat(p)
			if err != nil {
				left = append(left, p)
				ok = false
				continue
			}
			if child.IsDir() {
				if device(child) != dev {
					left = append(left, p)
					ok = false
					continue
				}
				if !clear(p, child) {
					ok = false
					continue
				}
				if !sameDir(p, child) {
					left = append(left, p)
					ok = false
					continue
				}
			}
			if !sameDir(d, want) {
				left = append(left, d)
				return false
			}
			if err = os.Remove(p); err != nil {
				left = append(left, p)
				ok = false
			}
		}
		if !sameDir(d, want) {
			left = append(left, d)
			return false
		}
		return ok
	}
	if clear(path, st) {
		if !sameDir(path, st) {
			left = append(left, path)
		} else if err = os.Remove(path); err != nil {
			return left, err
		}
	}
	return left, nil
}
func (a *App) removeFolder(v *Verdict, armed bool, cfg *Config, reg map[string]any) (bool, string) {
	if !armed {
		return false, "dry-run"
	}
	if v.Marker == nil {
		return false, "marker unavailable"
	}
	if isMount(v.Folder) {
		return false, "folder is a mount point"
	}
	ident, err := a.Lstat(v.Folder)
	if err != nil {
		return false, "folder unreadable: " + err.Error()
	}
	recheck := func(src map[string]string) string {
		fresh, err := a.readMarker(v.Folder)
		if err != nil {
			return "marker changed: " + err.Error()
		}
		if fresh.Mtime != v.Marker.Mtime || len(fresh.Holds) > 0 {
			return "marker touched or held since evaluation"
		}
		if a.denyReason(v.Folder, cfg) != "" {
			return "refused by deny-list"
		}
		st, err := a.Lstat(v.Folder)
		if err != nil {
			return "folder unreadable: " + err.Error()
		}
		if device(st) != device(ident) || inode(st) != inode(ident) {
			return "folder replaced since evaluation"
		}
		if hold := a.holderHold(fresh, cfg); hold != "" {
			return "held: " + hold
		}
		if busy := a.OpenFiles(v.Folder); busy != "" {
			return busy
		}
		var closedAt *float64
		if fresh.Job != "" {
			closed, at, detail := a.jobClosedFresh(fresh.Job, cfg, reg)
			closedAt = at
			if closed == nil || !*closed {
				if closed == nil {
					detail = "state unknown: " + detail
				}
				return "job " + fresh.Job + " " + detail
			}
		}
		if reason := a.sessionProblem(fresh, cfg, markerEntry(reg, v.Folder, a.Now()), closedAt); reason != "" {
			return reason
		}
		start := fresh.Mtime
		if closedAt != nil {
			start = max(start, *closedAt)
		}
		if fresh.Session != "" {
			start = max(start, number(markerEntry(reg, v.Folder, a.Now())["session_exit_seen"]))
		}
		if v.Expired && a.Now()-start < v.TTLS {
			return "job/session clock changed since evaluation; TTL not expired"
		}
		w := a.walk(v.Folder, cfg, true, 300)
		reason, repo := a.treeProblem(v.Folder, fresh, cfg, w)
		if reason != "" {
			return reason
		}
		if repo != v.Repo {
			return "repository type changed since evaluation"
		}
		if src != nil {
			current, err := a.FileHashes(v.Folder)
			if err != nil {
				return "source hash failed: " + err.Error()
			}
			if !reflect.DeepEqual(withoutMarker(current), src) {
				return "source changed while it was being copied"
			}
		}
		return ""
	}
	unlock, err := a.HoldLock()
	if err != nil {
		return false, "hold lock failed: " + err.Error()
	}
	problem := recheck(nil)
	unlock()
	if problem != "" {
		return false, problem
	}
	destDetail := ""
	var src map[string]string
	if v.Action == "move" {
		src, err = a.FileHashes(v.Folder)
		if err != nil {
			return false, "kept source: source hash failed: " + err.Error()
		}
		src = withoutMarker(src)
		ok, detail := a.MoveAndVerify(v.Folder, v.Dest, cfg.RemoteCommand, src)
		if !ok {
			return false, "kept source: " + detail
		}
		destDetail = " -> " + detail
	}
	unlock, err = a.HoldLock()
	if err != nil {
		return false, "hold lock failed: " + err.Error()
	}
	var common, trash string
	ok, detail := func() (bool, string) {
		defer unlock()
		if problem := recheck(src); problem != "" {
			return false, "kept source" + destDetail + ": " + problem
		}
		if v.Repo == "git-linked" {
			res := a.Run([]string{"git", "-C", v.Folder, "rev-parse", "--git-common-dir"}, 30, "", nil)
			if res.Err == nil && !res.Timeout && res.Code == 0 {
				common = strings.TrimSpace(res.Stdout)
				if !filepath.IsAbs(common) {
					common = filepath.Join(v.Folder, common)
				}
				if real, err := filepath.EvalSymlinks(common); err == nil {
					common = real
				}
			}
		}
		if v.Repo == "jj-secondary" {
			res := a.Run([]string{"jj", "-R", v.Folder, "--ignore-working-copy", "workspace", "forget"}, 60, "", nil)
			if res.Err != nil || res.Timeout || res.Code != 0 {
				detail := strings.TrimSpace(res.Stderr)
				if len(detail) > 100 {
					detail = detail[:100]
				}
				return false, "jj workspace forget failed: " + detail
			}
		}
		trash = filepath.Join(filepath.Dir(v.Folder), "."+filepath.Base(v.Folder)+".reclaimable-trash-"+strconv.FormatInt(int64(a.Now()), 10))
		if err := a.Rename(v.Folder, trash); err != nil {
			return false, "rename failed: " + err.Error()
		}
		st, err := a.Lstat(trash)
		if err != nil || !st.IsDir() {
			if err := a.Rename(trash, v.Folder); err != nil {
				return false, "folder became a symlink; restore failed: " + err.Error()
			}
			return false, "folder became a symlink; restored, nothing deleted"
		}
		if device(st) != device(ident) || inode(st) != inode(ident) {
			if err := a.Rename(trash, v.Folder); err != nil {
				return false, "folder replaced before rename; restore failed: " + err.Error()
			}
			return false, "folder replaced before rename; restored, nothing deleted"
		}
		return true, ""
	}()
	if !ok {
		return false, detail
	}
	left, err := a.rmtreeSameDev(trash)
	if err != nil {
		return false, "removal failed: " + err.Error()
	}
	if common != "" {
		a.Run([]string{"git", "--git-dir", common, "worktree", "prune"}, 60, "", nil)
	}
	delete(mapEntry(reg, "markers"), v.Folder)
	if len(left) > 0 {
		destDetail += fmt.Sprintf(" (left %s holding %d other-filesystem dirs)", trash, len(left))
	}
	return true, destDetail
}
