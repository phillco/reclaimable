"""Exercise the remote protocol locally on disposable fixtures only."""

import io
import os
import subprocess
import tarfile
import time
from types import SimpleNamespace

import pytest

from test_reclaimable import rc


LOCAL_REMOTE = ["sh", "-c", "{script}"]


def test_remote_transfer_preserves_files_and_links(tmp_path):
    stage = tmp_path / "stage"
    (stage / "nested").mkdir(parents=True)
    (stage / "nested/a\nb").write_bytes(b"payload")
    (stage / "link").symlink_to("nested/a\nb")
    dest = tmp_path / "archive/result"
    ok, detail = rc.remote_copy(stage, str(dest), "fixture", LOCAL_REMOTE)
    assert ok, detail
    assert (dest / "nested/a\nb").read_bytes() == b"payload"
    assert os.readlink(dest / "link") == "nested/a\nb"
    hashes = rc.remote_hashes("fixture", str(dest), LOCAL_REMOTE)
    assert hashes == rc.file_hashes(stage)


def test_remote_hash_inventory_preserves_newlines(tmp_path):
    (tmp_path / "a\nb").write_bytes(b"payload")
    (tmp_path / "link\nname").symlink_to("a\nb")
    assert rc.remote_hashes("fixture", str(tmp_path), LOCAL_REMOTE) == rc.file_hashes(
        tmp_path
    )


def test_remote_transfer_refuses_existing_destination(tmp_path):
    stage = tmp_path / "stage"
    stage.mkdir()
    (stage / "sentinel").write_bytes(b"new")
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "sentinel").write_bytes(b"keep")
    ok, _ = rc.remote_copy(stage, str(dest), "fixture", LOCAL_REMOTE)
    assert not ok
    assert (dest / "sentinel").read_bytes() == b"keep"


def test_remote_transfer_refuses_symlink_destination_parent(tmp_path):
    stage = tmp_path / "stage"
    stage.mkdir()
    (stage / "payload").write_bytes(b"new")
    outside = tmp_path / "outside"
    outside.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(outside, target_is_directory=True)
    ok, _ = rc.remote_copy(stage, str(alias / "dest"), "fixture", LOCAL_REMOTE)
    assert not ok
    assert not list(outside.iterdir())


def test_remote_receiver_rejects_traversal_and_link_parent(tmp_path):
    for name in ("../sentinel", "/sentinel", "link/payload"):
        dest = tmp_path / ("dest-" + str(len(list(tmp_path.iterdir()))))
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w") as tar:
            if name == "link/payload":
                link = tarfile.TarInfo("link")
                link.type = tarfile.SYMTYPE
                link.linkname = str(tmp_path)
                tar.addfile(link)
            info = tarfile.TarInfo(name)
            info.size = 3
            tar.addfile(info, io.BytesIO(b"bad"))
        archive.seek(0)
        script = rc._remote_script("receive", str(dest))
        result = subprocess.run(
            ["sh", "-c", script], input=archive.getvalue(), capture_output=True
        )
        assert result.returncode != 0
        assert not (tmp_path / "sentinel").exists()
        assert not (tmp_path / "payload").exists()


def test_remote_hash_refuses_symlink_root(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "sentinel").write_bytes(b"keep")
    alias = tmp_path / "alias"
    alias.symlink_to(outside, target_is_directory=True)
    assert rc.remote_hashes("fixture", str(alias), LOCAL_REMOTE) is None


def test_remote_receiver_pins_nested_directory_across_members(tmp_path, monkeypatch):
    destination = tmp_path / "destination"
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel"
    sentinel.write_bytes(b"keep")
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w") as tar:
        child = tarfile.TarInfo("child")
        child.type = tarfile.DIRTYPE
        tar.addfile(child)
        payload = tarfile.TarInfo("child/payload")
        payload.size = 3
        tar.addfile(payload, io.BytesIO(b"new"))
    archive.seek(0)
    monkeypatch.setattr(rc.sys, "stdin", SimpleNamespace(buffer=archive))
    original = rc.os.stat
    observations = []
    swapped = []

    def stat(path, *args, **kwargs):
        if path == "child" and kwargs.get("dir_fd") is not None:
            observations.append(True)
            # The first member opened, checked and closed this directory. Replace
            # it before the next member establishes a fresh parent identity.
            if len(observations) == 4:
                (destination / "child").rename(destination / "original-child")
                outside.rename(destination / "child")
                swapped.append(True)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(rc.os, "stat", stat)
    with pytest.raises(OSError):
        rc._remote_archive("receive", str(destination))
    assert swapped
    assert (destination / "child/sentinel").read_bytes() == b"keep"
    assert not (destination / "child/payload").exists()


def test_remote_transfer_preserves_marker_age(tmp_path):
    stage = tmp_path / "stage"
    stage.mkdir()
    marker = stage / ".reclaimable"
    marker.write_bytes(b"marker")
    old = time.time() - 30 * 86400
    os.utime(marker, (old, old))
    destination = tmp_path / "destination"
    ok, detail = rc.remote_copy(stage, str(destination), "fixture", LOCAL_REMOTE)
    assert ok, detail
    assert (destination / ".reclaimable").stat().st_mtime == marker.stat().st_mtime
