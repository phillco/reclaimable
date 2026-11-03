package main

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"unicode/utf8"
)

// exportArchive reads only verified descriptors and compares exactly the bytes
// being archived with the manifest that authorized the move. A failed export
// never sends a partial archive to the remote command.
func (a *App) exportArchive(root string, w io.Writer, expected map[string]string) error {
	source, err := openPathDir(root)
	if err != nil {
		return err
	}
	defer source.Close()
	manifest := map[string]string{}
	tw := tar.NewWriter(w)
	err = a.walkPayload(source, func(parent, file *os.File, name, relative string, st os.FileInfo) error {
		link := ""
		if st.Mode()&os.ModeSymlink != 0 {
			var err error
			link, err = readlinkAt(parent, name)
			if err != nil {
				return err
			}
			manifest[filepath.ToSlash(relative)] = "link:" + link
		}
		header, err := tar.FileInfoHeader(st, link)
		if err != nil {
			return err
		}
		header.Name = filepath.ToSlash(relative)
		if st.IsDir() {
			header.Name += "/"
		}
		header.AccessTime = accessTime(st)
		header.Format = tar.FormatPAX
		if err = tw.WriteHeader(header); err != nil {
			return err
		}
		if st.Mode().IsRegular() {
			hash := sha256.New()
			if _, err = io.CopyN(tw, io.TeeReader(file, hash), st.Size()); err != nil {
				return err
			}
			manifest[filepath.ToSlash(relative)] = fmt.Sprintf("%x", hash.Sum(nil))
		}
		return nil
	})
	if err != nil {
		return err
	}
	if err = tw.Close(); err != nil {
		return err
	}
	if !reflect.DeepEqual(withoutMarker(manifest), withoutMarker(expected)) {
		return fmt.Errorf("source changed during archive export")
	}
	return nil
}

func remoteArchiveScript(mode, path string) string {
	modeJSON, _ := json.Marshal(mode)
	pathJSON, _ := json.Marshal(path)
	source := remoteArchiveProgram + "\n_remote_archive(" + string(modeJSON) + ", " + string(pathJSON) + ")\n"
	return "python3 -c " + shellQuote(source)
}

func (a *App) remoteCopyVerified(sourceRoot, dest, host string, remote []string, src map[string]string) (bool, string) {
	if !utf8.ValidString(dest) {
		return false, "remote transfer failed: destination is not valid UTF-8"
	}
	if src == nil {
		var err error
		src, err = a.FileHashes(sourceRoot)
		if err != nil {
			return false, "remote transfer failed: " + err.Error()
		}
	}
	stream, err := os.CreateTemp("", "reclaimable-transfer-")
	if err != nil {
		return false, "remote transfer failed: " + err.Error()
	}
	defer stream.Close()
	// The open file is the only reference while unverified source bytes are
	// spooled. Nothing can redirect a later path-based archive reopen.
	if err = os.Remove(stream.Name()); err != nil {
		return false, "remote transfer failed: " + err.Error()
	}
	if err = a.exportArchive(sourceRoot, stream, src); err != nil {
		return false, "remote transfer failed: " + err.Error()
	}
	if _, err = stream.Seek(0, io.SeekStart); err != nil {
		return false, "remote transfer failed: " + err.Error()
	}
	if len(remote) == 0 {
		remote = defaultRemoteCommand
	}
	command := make([]string, len(remote))
	script := remoteArchiveScript("receive", dest)
	for i, arg := range remote {
		command[i] = strings.ReplaceAll(strings.ReplaceAll(arg, "{host}", host), "{script}", script)
	}
	result := a.RunInput(command, 300, "", nil, stream)
	if result.Err != nil {
		return false, "remote transfer failed: " + result.Err.Error()
	}
	if result.Timeout {
		return false, "remote transfer failed: timed out"
	}
	if result.Code != 0 {
		return false, "remote transfer failed: " + shortText(strings.TrimSpace(result.Stderr), 160)
	}
	return true, dest
}

const remoteArchiveProgram = `def _remote_archive(mode, destination):
    """Self-contained remote receiver/hash program; never follows path symlinks."""
    import contextlib
    import hashlib
    import json
    import os
    import stat
    import sys
    import tarfile
    from pathlib import Path

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW

    def same(a, b):
        return (a.st_dev, a.st_ino, stat.S_IFMT(a.st_mode)) == (
            b.st_dev,
            b.st_ino,
            stat.S_IFMT(b.st_mode),
        )

    def require(parent, name, expected):
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if not same(current, expected):
            raise OSError(f"entry replaced: {name}")

    @contextlib.contextmanager
    def directory_at(parent, name, expected=None, create=False):
        if create:
            try:
                os.mkdir(name, 0o700, dir_fd=parent)
            except FileExistsError:
                pass
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISDIR(before.st_mode) or (
            expected is not None and not same(before, expected)
        ):
            raise OSError(f"not the expected directory: {name}")
        fd = os.open(name, flags, dir_fd=parent)
        try:
            if not same(os.fstat(fd), before):
                raise OSError(f"directory replaced: {name}")
            require(parent, name, before)
            yield fd
            require(parent, name, before)
        finally:
            os.close(fd)

    @contextlib.contextmanager
    def directory(path, create=False, exclusive=False):
        path = Path(os.path.abspath(Path(path).expanduser()))
        with contextlib.ExitStack() as stack:
            fd = os.open("/", flags)
            stack.callback(os.close, fd)
            for index, name in enumerate(path.parts[1:]):
                last = index == len(path.parts) - 2
                if exclusive and last:
                    os.mkdir(name, 0o700, dir_fd=fd)
                fd = stack.enter_context(directory_at(fd, name, create=create))
            if exclusive and path == Path("/"):
                raise OSError("destination already exists")
            yield fd

    def inventory(fd, prefix, dev, out):
        for entry in list(os.scandir(fd)):
            if entry.name == ".DS_Store":
                continue
            expected = entry.stat(follow_symlinks=False)
            relative = prefix + entry.name
            if stat.S_ISDIR(expected.st_mode):
                if expected.st_dev != dev:
                    raise OSError(f"filesystem boundary: {relative}")
                with directory_at(fd, entry.name, expected) as child:
                    inventory(child, relative + "/", dev, out)
            elif stat.S_ISLNK(expected.st_mode):
                out[relative] = "link:" + os.readlink(entry.name, dir_fd=fd)
                require(fd, entry.name, expected)
            elif stat.S_ISREG(expected.st_mode):
                opened = os.open(
                    entry.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd
                )
                with os.fdopen(opened, "rb") as source:
                    before = os.fstat(source.fileno())
                    if not same(before, expected):
                        raise OSError(f"file replaced: {relative}")
                    digest = hashlib.sha256()
                    for chunk in iter(lambda: source.read(1 << 20), b""):
                        digest.update(chunk)
                    after = os.fstat(source.fileno())
                    if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                        after.st_size,
                        after.st_mtime_ns,
                        after.st_ctime_ns,
                    ):
                        raise OSError(f"file changed: {relative}")
                require(fd, entry.name, expected)
                out[relative] = digest.hexdigest()
            else:
                raise OSError(f"unsupported file type: {relative}")

    if mode == "hash":
        hashes = {}
        with directory(destination) as fd:
            inventory(fd, "", os.fstat(fd).st_dev, hashes)
        print(json.dumps(hashes), flush=True)
        return
    if mode != "receive":
        raise ValueError("invalid transfer operation")
    destination_ids = {}

    @contextlib.contextmanager
    def extraction_directory(parent, name, relative):
        expected = destination_ids.get(relative)
        with directory_at(
            parent, name, expected=expected, create=expected is None
        ) as fd:
            if expected is None:
                destination_ids[relative] = os.fstat(fd)
            yield fd

    with directory(destination, create=True, exclusive=True) as root:
        with tarfile.open(fileobj=sys.stdin.buffer, mode="r|") as archive:
            for member in archive:
                parts = member.name.rstrip("/").split("/")
                if not parts or any(p in ("", ".", "..") for p in parts):
                    raise ValueError("unsafe archive member")
                if not (member.isdir() or member.isfile() or member.issym()):
                    raise ValueError("unsupported archive member")
                with contextlib.ExitStack() as stack:
                    parent = root
                    for index, name in enumerate(parts[:-1]):
                        parent = stack.enter_context(
                            extraction_directory(
                                parent, name, tuple(parts[: index + 1])
                            )
                        )
                    name = parts[-1]
                    if member.isdir():
                        with extraction_directory(parent, name, tuple(parts)):
                            pass
                    elif member.issym():
                        os.symlink(member.linkname, name, dir_fd=parent)
                    else:
                        fd = os.open(
                            name,
                            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                            0o600,
                            dir_fd=parent,
                        )
                        with os.fdopen(fd, "wb") as target:
                            original = os.fstat(target.fileno())
                            source = archive.extractfile(member)
                            if source is None:
                                raise ValueError("missing archive file data")
                            remaining = member.size
                            with source:
                                while remaining:
                                    chunk = source.read(min(1 << 20, remaining))
                                    if not chunk:
                                        raise ValueError("truncated archive file")
                                    target.write(chunk)
                                    remaining -= len(chunk)
                            target.flush()
                            os.fchmod(target.fileno(), member.mode & 0o777)
                            os.utime(target.fileno(), (member.mtime, member.mtime))
                        require(parent, name, original)
`

func refuseRemoteAttributeList(query func([]byte) (int, error)) error {
	n, err := query(nil)
	if err != nil {
		return err
	}
	if n < 0 || n > 1<<20 {
		return fmt.Errorf("cannot inspect extended attributes")
	}
	b := make([]byte, n)
	count, err := query(b)
	if err != nil {
		return err
	}
	if count < 0 || count > n {
		return fmt.Errorf("cannot inspect extended attributes")
	}
	for _, name := range strings.Split(string(b[:count]), "\x00") {
		if name != "" && name != "com.apple.provenance" {
			return fmt.Errorf("extended data cannot be preserved and verified; source kept")
		}
	}
	return nil
}
