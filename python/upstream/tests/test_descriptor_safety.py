"""Deterministic filesystem races; every target and sentinel is disposable."""

import hashlib
import os
import subprocess
from pathlib import Path

import pytest

from test_reclaimable import env as env, make, rc


def swap_at_scandir(monkeypatch, child, outside):
    original = rc.os.scandir
    expected = child.stat()
    swapped = []

    def scandir(path):
        is_child = (
            isinstance(path, int) and os.fstat(path).st_ino == expected.st_ino
        ) or (not isinstance(path, int) and Path(os.fspath(path)) == child)
        if is_child and not swapped:
            child.rename(child.with_name("parked"))
            child.symlink_to(outside, target_is_directory=True)
            swapped.append(True)
        return original(path)

    monkeypatch.setattr(rc.os, "scandir", scandir)
    return swapped


def test_removal_child_swap_never_follows_symlink(env, monkeypatch):
    root = env.root / "remove"
    child = root / "child"
    child.mkdir(parents=True)
    outside = env.root / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel"
    sentinel.write_bytes(b"keep")
    swapped = swap_at_scandir(monkeypatch, child, outside)
    left = rc.rmtree_same_dev(root)
    assert swapped and sentinel.read_bytes() == b"keep"
    assert left and child.is_symlink()


def test_hasher_child_swap_never_reads_symlink_target(env, monkeypatch):
    root = env.root / "hash"
    child = root / "child"
    child.mkdir(parents=True)
    outside = env.root / "outside"
    outside.mkdir()
    (outside / "sentinel").write_bytes(b"private")
    swapped = swap_at_scandir(monkeypatch, child, outside)
    try:
        inventory = rc.file_hashes(root)
    except OSError:
        inventory = {}
    assert swapped
    assert "child/sentinel" not in inventory


def test_copy_child_swap_never_copies_symlink_target(env, monkeypatch):
    root = make(env, "source", files={"child/inside": b"inside"})
    outside = env.root / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel"
    sentinel.write_bytes(b"private")
    source_hashes = rc.file_hashes(root)
    swapped = swap_at_scandir(monkeypatch, root / "child", outside)
    ok, _ = rc.move_and_verify(root, str(env.root / "archive"), src=source_hashes)
    assert swapped and not ok
    assert sentinel.read_bytes() == b"private"
    assert not list((env.root / "archive").rglob("sentinel"))


def test_hasher_file_swap_never_reads_symlink_target(env, monkeypatch):
    root = make(env, "source", files={"payload": b"inside"})
    outside = env.root / "sentinel"
    outside.write_bytes(b"private")
    original_open = rc.os.open
    original_path_open = Path.open
    swapped = []

    def swap():
        if not swapped:
            (root / "payload").unlink()
            (root / "payload").symlink_to(outside)
            swapped.append(True)

    def fd_open(path, flags, *args, **kwargs):
        if path == "payload" and kwargs.get("dir_fd") is not None:
            swap()
        return original_open(path, flags, *args, **kwargs)

    def path_open(path, *args, **kwargs):
        if path == root / "payload":
            swap()
        return original_path_open(path, *args, **kwargs)

    monkeypatch.setattr(rc.os, "open", fd_open)
    monkeypatch.setattr(Path, "open", path_open)
    try:
        inventory = rc.file_hashes(root)
    except OSError:
        inventory = {}
    assert swapped
    assert hashlib.sha256(b"private").hexdigest() not in inventory.values()


def test_hasher_refuses_special_files(env):
    root = make(env, "source")
    os.mkfifo(root / "pipe")
    # The walker must reject the FIFO before any blocking read.
    with pytest.raises(OSError):
        rc.file_hashes(root)


def test_marker_swap_never_bypasses_nested_hold(env, monkeypatch):
    root = make(env, "outer", age_s=30 * 86400)
    child = make(env, "outer/child", age_s=30 * 86400, holds=[{"job": "reader"}])
    outside = make(env, "outside", age_s=30 * 86400)
    expected = child.stat()
    original = rc.os.open
    swapped = []

    def open_marker(path, flags, *args, **kwargs):
        fd = kwargs.get("dir_fd")
        if (
            path == rc.MARKER
            and fd is not None
            and os.fstat(fd).st_ino == expected.st_ino
        ):
            if not swapped:
                (child / rc.MARKER).rename(child / "held-marker")
                (child / rc.MARKER).symlink_to(outside / rc.MARKER)
                swapped.append(True)
        return original(path, flags, *args, **kwargs)

    monkeypatch.setattr(rc.os, "open", open_marker)
    v = rc.evaluate(root, env.cfg, env.reg)
    assert swapped and not v.safe


def test_copy_pins_destination_identity(env, monkeypatch):
    root = make(env, "source", files={"payload": b"new"})
    archive = env.root / "archive"
    _, dest_name = rc.move_destination(str(archive), root)
    dest = Path(dest_name)
    original = rc.os.open
    swapped = []

    def replace_destination(path, flags, *args, **kwargs):
        fd = kwargs.get("dir_fd")
        if (
            path == "payload"
            and fd is not None
            and flags & os.O_CREAT
            and dest.exists()
        ):
            if os.fstat(fd).st_ino == dest.stat().st_ino and not swapped:
                dest.rename(dest.with_name("parked"))
                dest.mkdir()
                (dest / "sentinel").write_bytes(b"keep")
                swapped.append(True)
        return original(path, flags, *args, **kwargs)

    monkeypatch.setattr(rc.os, "open", replace_destination)
    ok, _ = rc.move_and_verify(root, str(archive))
    assert swapped and not ok and root.exists()
    assert (dest / "sentinel").read_bytes() == b"keep"
    assert not (dest / "payload").exists()


def test_copy_refuses_symlink_destination_ancestor(env):
    root = make(env, "source")
    outside = env.root / "outside"
    outside.mkdir()
    archive = env.root / "archive"
    archive.symlink_to(outside, target_is_directory=True)
    ok, _ = rc.move_and_verify(root, str(archive))
    assert not ok and root.exists() and not list(outside.iterdir())


def test_file_modified_during_hash_fails_closed(env, monkeypatch):
    root = make(env, "source", files={"payload": b"before"})
    target = (root / "payload").stat()
    original = rc.os.read
    changed = []

    def read(fd, size):
        if os.fstat(fd).st_ino == target.st_ino and not changed:
            (root / "payload").write_bytes(b"after")
            changed.append(True)
        return original(fd, size)

    monkeypatch.setattr(rc.os, "read", read)
    with pytest.raises(OSError, match="changed"):
        rc.file_hashes(root)


def test_copy_preserves_marker_age_and_executable_mode(env):
    root = make(env, "source", age_s=30 * 86400, files={"tool": b"executable"})
    (root / "tool").chmod(0o755)
    archive = env.root / "archive"
    ok, detail = rc.move_and_verify(root, str(archive))
    assert ok, detail
    _, dest = rc.move_destination(str(archive), root)
    assert (Path(dest) / "tool").stat().st_mode & 0o777 == 0o755
    assert (Path(dest) / rc.MARKER).stat().st_mtime == (
        root / rc.MARKER
    ).stat().st_mtime


def test_final_rename_does_not_follow_replaced_parent(env, monkeypatch):
    root = make(env, "parent/source", age_s=30 * 86400)
    v = rc.evaluate(root, env.cfg, env.reg)
    outside = env.root / "outside"
    (outside / "source").mkdir(parents=True)
    sentinel = outside / "source/sentinel"
    sentinel.write_bytes(b"keep")
    original = rc.os.rename
    swapped = []

    def rename(src, dst, **kwargs):
        if src == root.name and not swapped:
            original(root.parent, root.parent.with_name("parked-parent"))
            root.parent.symlink_to(outside, target_is_directory=True)
            swapped.append(True)
        return original(src, dst, **kwargs)

    monkeypatch.setattr(rc.os, "rename", rename)
    ok, _ = rc.remove_folder(v, True, env.cfg, env.reg)
    assert swapped and not ok and sentinel.read_bytes() == b"keep"


def test_discovery_never_follows_swapped_child(env, monkeypatch):
    root = env.root / "discover"
    child = root / "child"
    child.mkdir(parents=True)
    outside = make(env, "outside")
    swapped = swap_at_scandir(monkeypatch, child, outside)
    found, complete = rc.scan([root], env.cfg)
    assert swapped and not complete and not found


def test_remote_move_round_trip_uses_local_fixture_transport(env):
    root = make(env, "source", age_s=30 * 86400, files={"a\nb": b"payload"})
    archive = env.root / "archive"
    ok, detail = rc.move_and_verify(
        root, "fixture:" + str(archive), remote_cmd=["sh", "-c", "{script}"]
    )
    assert ok, detail
    assert root.exists()
    _, dest = rc.move_destination("fixture:" + str(archive), root)
    assert (Path(dest) / "a\nb").read_bytes() == b"payload"


def test_replaced_folder_after_evaluation_is_kept(env):
    root = make(env, "source", age_s=30 * 86400)
    v = rc.evaluate(root, env.cfg, env.reg)
    marker = (root / rc.MARKER).read_bytes()
    marker_stat = (root / rc.MARKER).stat()
    root.rename(root.with_name("parked-source"))
    root.mkdir()
    (root / rc.MARKER).write_bytes(marker)
    os.utime(root / rc.MARKER, ns=(marker_stat.st_atime_ns, marker_stat.st_mtime_ns))
    sentinel = root / "replacement"
    sentinel.write_bytes(b"keep")
    ok, detail = rc.remove_folder(v, True, env.cfg, env.reg)
    assert not ok and "replaced" in detail
    assert sentinel.read_bytes() == b"keep"


@pytest.mark.skipif(rc.sys.platform != "darwin", reason="resource forks are macOS data")
@pytest.mark.parametrize("target_name", ["payload", ".", "link"])
def test_resource_fork_keeps_source_during_move(env, target_name):
    root = make(env, "source", files={"payload": b"data"})
    (root / "link").symlink_to("payload")
    subprocess.run(
        [
            "/usr/bin/xattr",
            "-s",
            "-w",
            "com.apple.ResourceFork" if target_name == "payload" else "user.fixture",
            "keep-fork",
            str(root / target_name),
        ],
        check=True,
        capture_output=True,
    )
    ok, detail = rc.move_and_verify(root, str(env.root / "archive"))
    assert not ok and "extended data" in detail
    assert (root / "payload").read_bytes() == b"data"
