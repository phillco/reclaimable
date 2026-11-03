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
// keeps the source, even if the receiver has created a partial destination.
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
	if len(remote) == 0 {
		remote = defaultRemoteCommand
	}
	command := make([]string, len(remote))
	script := remoteArchiveScript("receive", dest)
	for i, arg := range remote {
		command[i] = strings.ReplaceAll(strings.ReplaceAll(arg, "{host}", host), "{script}", script)
	}
	reader, writer := io.Pipe()
	exported := make(chan error, 1)
	go func() {
		err := a.exportArchive(sourceRoot, writer, src)
		writer.CloseWithError(err)
		exported <- err
	}()
	result := a.RunInput(command, 300, "", nil, reader)
	reader.Close() // Unblock export if the receiver exits without reading it all.
	exportErr := <-exported
	if result.Err != nil {
		return false, "remote transfer failed: " + result.Err.Error()
	}
	if result.Timeout {
		return false, "remote transfer failed: timed out"
	}
	if result.Code != 0 {
		return false, "remote transfer failed: " + shortText(strings.TrimSpace(result.Stderr), 160)
	}
	if exportErr != nil {
		return false, "remote transfer failed: " + exportErr.Error()
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

    @contextlib.contextmanager
    def directory_at(parent, name, create=False):
        if create:
            try:
                os.mkdir(name, 0o700, dir_fd=parent)
            except FileExistsError:
                pass
        fd = os.open(name, flags, dir_fd=parent)
        try:
            yield fd
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
                with directory_at(fd, entry.name) as child:
                    inventory(child, relative + "/", dev, out)
            elif stat.S_ISLNK(expected.st_mode):
                out[relative] = "link:" + os.readlink(entry.name, dir_fd=fd)
            elif stat.S_ISREG(expected.st_mode):
                opened = os.open(
                    entry.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd
                )
                with os.fdopen(opened, "rb") as source:
                    digest = hashlib.sha256()
                    for chunk in iter(lambda: source.read(1 << 20), b""):
                        digest.update(chunk)
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
                    for name in parts[:-1]:
                        parent = stack.enter_context(directory_at(parent, name, create=True))
                    name = parts[-1]
                    if member.isdir():
                        with directory_at(parent, name, create=True):
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
