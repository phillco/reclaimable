"""reclaimable: markers, TTL/eligibility, deny-list, holders, job gating, worktrees, move-verify, floor/LRU.

Temp dirs only; pgrep/lsof are mocked, holders and job_done are real tiny scripts.
"""

import importlib.machinery
import importlib.util
import json
import os
import stat
import subprocess
import sys
import time
import unicodedata
from pathlib import Path
from types import SimpleNamespace

import pytest

_loader = importlib.machinery.SourceFileLoader(
    "reclaimable_cli", str(Path(__file__).parents[1] / "reclaimable")
)
_spec = importlib.util.spec_from_loader(_loader.name, _loader)
rc = importlib.util.module_from_spec(_spec)
sys.modules[_loader.name] = rc
_loader.exec_module(rc)

DAY = 86400


@pytest.fixture
def env(tmp_path, monkeypatch):
    tmp_path = tmp_path.resolve()
    state = tmp_path / "state"
    for name, value in {
        "STATE_DIR": state,
        "CONFIG_DIR": tmp_path / "config",
        "CONFIG_FILE": tmp_path / "config/config.toml",
        "ARMED_FILE": tmp_path / "config/armed",
        "LOG_FILE": tmp_path / "log/reclaimable.log",
        "REGISTRY": state / "registry.json",
        "LAST_SWEEP": state / "last-sweep.json",
    }.items():
        monkeypatch.setattr(rc, name, value)
    monkeypatch.setattr(rc, "open_files", lambda folder: None)
    monkeypatch.setattr(rc, "process_cwd", lambda pid: None)
    jobs = tmp_path / "jobs"
    jobs.mkdir()
    script = tmp_path / "jobdone"
    script.write_text(
        '#!/bin/sh\nf="$(dirname "$0")/jobs/$1"\n[ -f "$f" ] || exit 2\n'
        'read -r state when < "$f"\n[ "$state" = closed ] && { echo "$when"; exit 0; }\n'
        '[ "$state" = open ] && exit 1\nexit 2\n'
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    cfg = rc.Config(
        roots=[tmp_path / "data"],
        floor=0,
        target=0,
        move_root=None,
        deny_paths=list(rc.DENY_PATHS),
        deny_names=list(rc.DENY_NAMES),
        deny_exact=list(rc.BROAD),
        holders=[
            {
                "lease_dir": str(tmp_path / "leases"),
                "claim_dir": str(tmp_path / "claims"),
            }
        ],
        job_done={"command": [str(script), "{job}"]},
    )
    monkeypatch.setattr(rc, "load_config", lambda path=None: cfg)
    return SimpleNamespace(root=tmp_path, cfg=cfg, reg={"markers": {}}, jobs=jobs)


def set_job(env, job, text):
    (env.jobs / job).write_text(text)


def make(env, rel, age_s=0, files=None, **marker):
    folder = env.root / "data" / rel
    folder.mkdir(parents=True, exist_ok=True)
    for name, content in (files or {"blob.bin": b"x" * 5000}).items():
        p = folder / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content)
    data = {"owner": "test", "regenerate": "rerun", "holds": []}
    data.update(marker)
    (folder / ".reclaimable").write_text(json.dumps(data))
    t = time.time() - age_s
    os.utime(folder / ".reclaimable", (t, t))
    return folder


def sweep_args(**kw):
    base = dict(
        dry_run=False, armed=False, floor=None, target=None, scan=True, verbose=False
    )
    return SimpleNamespace(**{**base, **kw})


# --- marker parsing -------------------------------------------------------------


def test_marker_parsing_and_defaults(env):
    f = make(env, "c", ttl="3d", kind="cache", custom=1)
    m = rc.read_marker(f)
    assert m.owner == "test" and m.ttl_seconds == 3 * DAY and m.extra == {"custom": 1}
    assert rc.read_marker(make(env, "s", kind="staged")).ttl_seconds == 2 * DAY
    h = rc.read_marker(make(env, "plain"))
    assert h.effective_kind == "cache" and h.ttl_seconds == DAY


@pytest.mark.parametrize(
    "bad", [{"owner": ""}, {"kind": "nope"}, {"ttl": "soon"}, {"holds": "x"}]
)
def test_bad_markers_are_kept(env, bad):
    f = make(env, "bad", age_s=99 * DAY, **bad)
    v = rc.evaluate(f, env.cfg, env.reg)
    assert not v.safe and v.reason.startswith("bad marker")


def test_ttl_and_size_parsing():
    assert rc.parse_ttl("24h") == DAY and rc.parse_ttl("1.5d") == 1.5 * DAY
    with pytest.raises(ValueError):
        rc.parse_ttl("3 days")
    assert rc.parse_size("50GiB") == 50 * 2**30 and rc.parse_size("30") == 30 * 10**9


def test_mark_touch_cli_round_trip(env):
    folder = env.root / "data/new-cache"
    args = ["mark", str(folder), "-o", "tool", "-t", "24h", "-r", "tool rebuilds it"]
    assert rc.main(args) == 0
    m = rc.read_marker(folder)
    assert m.owner == "tool" and m.regenerate == "tool rebuilds it"
    assert str(folder) in json.loads(rc.REGISTRY.read_text())["markers"]
    old = time.time() - 5 * DAY
    os.utime(m.path, (old, old))
    assert rc.main(["touch", str(folder)]) == 0
    assert time.time() - m.path.stat().st_mtime < 60


# --- TTL / eligibility ----------------------------------------------------------


def test_fresh_vs_expired(env):
    fresh = rc.evaluate(make(env, "fresh", age_s=3600, ttl="24h"), env.cfg, env.reg)
    old = rc.evaluate(make(env, "old", age_s=2 * DAY, ttl="24h"), env.cfg, env.reg)
    assert fresh.safe and not fresh.expired
    assert old.safe and old.expired and old.action == "delete" and old.size > 0


def test_sweep_dry_run_by_default_and_armed_after_grace(env):
    f = make(env, "old", age_s=2 * DAY, ttl="24h")
    rc.sweep(sweep_args(), env.cfg)
    assert f.exists() and "would delete" in rc.LOG_FILE.read_text()
    rc.write_json(rc.ARMED_FILE, {"armed_at": time.time() - 3600})
    rc.sweep(sweep_args(), env.cfg)
    assert f.exists(), "first 24h after arming stay dry-run"
    rc.write_json(rc.ARMED_FILE, {"armed_at": time.time() - 2 * DAY})
    rc.sweep(sweep_args(), env.cfg)
    assert not f.exists()


def test_sweep_summary_counts_every_kept_folder(env, capsys):
    make(env, "fresh", age_s=60, ttl="24h")  # safe but not expired: kept
    make(env, "held", age_s=9 * DAY, ttl="1d", holds=[{"job": "j"}])  # unsafe: kept
    make(env, "old", age_s=9 * DAY, ttl="1d")  # acted on
    rc.sweep(sweep_args(verbose=True), env.cfg)
    out = capsys.readouterr().out
    assert "2 kept" in out and "keep " in out
    last = json.loads(rc.LAST_SWEEP.read_text())
    assert len(last["kept"]) == 2 and len(last["blocked"]) == 1


# --- deny-list ------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        "~/src/foo/.git",
        "~/src/foo/.jj/repo",
        "~",
        "/",
        "~/Documents",
        "~/.ssh/x",
        "/Volumes/Data",
        "~/Pictures/Photos.photoslibrary/x",
    ],
)
def test_builtin_deny_list(env, raw):
    assert rc.deny_reason(rc.expand(raw), env.cfg)


def test_deny_allows_ordinary_caches(env):
    assert rc.deny_reason(rc.expand("~/src/proj/cache/frames"), env.cfg) is None


def test_config_only_adds_to_deny(env, tmp_path):
    cfg_file = tmp_path / "c.toml"
    cfg_file.write_text(
        'deny = ["/tmp/extra-deny"]\ndeny_names = ["golden-*"]\n'
        'deny_exact = ["~/mine"]\ndeny_sequences = [["a", "b"]]\nfloor = "40GB"\n'
    )
    cfg = _fresh().load_config(cfg_file)
    assert (
        set(rc.DENY_PATHS) <= set(cfg.deny_paths)
        and "/tmp/extra-deny" in cfg.deny_paths
    )
    assert "*.photoslibrary" in cfg.deny_names and "golden-*" in cfg.deny_names
    assert cfg.floor == 40 * 10**9 and cfg.target == 60 * 10**9
    assert rc.deny_reason(rc.expand("~/mine"), cfg)
    assert rc.deny_reason(rc.expand("~/x/a/b/c"), cfg) == "deny-listed name a/b"
    assert rc.deny_reason(rc.expand("/tmp/extra-deny/x"), cfg)
    assert rc.deny_reason(rc.expand("~/x/golden-1"), cfg)


def _fresh():
    loader = importlib.machinery.SourceFileLoader("reclaimable_fresh", _loader.path)
    mod = importlib.util.module_from_spec(
        importlib.util.spec_from_loader(loader.name, loader)
    )
    sys.modules[loader.name] = mod
    loader.exec_module(mod)
    return mod


def test_mark_refuses_denied(env):
    assert rc.main(["mark", str(rc.expand("~/.ssh/keys")), "-o", "t", "-r", "r"]) == 2


def test_denied_descendants_block(env):
    env.cfg.deny_names.append("models")
    f = make(env, "cachey", age_s=9 * DAY, files={"x/models/w.pth": b"1"})
    v = rc.evaluate(f, env.cfg, env.reg)
    assert not v.safe and "deny-listed" in v.reason


# --- config ---------------------------------------------------------------------


def test_config_floors_hosts_ttls_and_validation(env, tmp_path, monkeypatch):
    mod = _fresh()
    monkeypatch.setattr(mod, "hostname", lambda: "box-1")
    p = tmp_path / "c.toml"
    p.write_text(
        'floor_gb = 10\n[default_ttls]\ncache = "6h"\n'
        '[hosts.box-1]\nfloor = "50GiB"\ndeny = ["/x"]\n'
        '[hosts.other]\nfloor = "1GB"\n'
        '[[holder]]\ncommand = ["true"]\n[job_done]\ncommand = ["true", "{job}"]\n'
    )
    cfg = mod.load_config(p)
    assert cfg.floor == 50 * 2**30 and "/x" in cfg.deny_paths
    assert mod.DEFAULT_TTL["cache"] == "6h" and cfg.job_done and len(cfg.holders) == 1
    monkeypatch.setattr(mod, "hostname", lambda: "elsewhere")
    assert mod.load_config(p).floor == 10 * 10**9
    assert mod.load_config(tmp_path / "missing.toml").floor == 30 * 10**9
    bad = tmp_path / "bad.toml"
    bad.write_text("[[holder]]\nname = 'x'\n")
    with pytest.raises(SystemExit):
        mod.load_config(bad)


def test_exclude_list_export(env, tmp_path):
    f = make(env, "c")
    env.cfg.export_list = tmp_path / "out/list.txt"
    env.cfg.export_format = "path {path}"
    rc.write_export_list({"markers": {str(f): {}}}, env.cfg)
    assert f"path {f}" in env.cfg.export_list.read_text()


# --- holds, leases, command holders ---------------------------------------------


def test_holds_block_and_release(env):
    f = make(env, "held", age_s=9 * DAY)
    assert rc.main(["hold", str(f), "job42"]) == 0
    old = time.time() - 9 * DAY
    os.utime(f / ".reclaimable", (old, old))
    v = rc.evaluate(f, env.cfg, env.reg)
    assert not v.safe and "held by job42" in v.reason
    assert rc.main(["release", str(f), "job42"]) == 0
    os.utime(f / ".reclaimable", (old, old))
    assert rc.evaluate(f, env.cfg, env.reg).safe


def test_live_lease_referencing_folder_holds(env):
    f = make(env, "leased", age_s=9 * DAY)
    leases = env.root / "leases"
    leases.mkdir()
    (leases / "1.json").write_text(
        json.dumps({"job": "x", "pid": os.getpid(), "log": str(f / "run.log")})
    )
    v = rc.evaluate(f, env.cfg, env.reg)
    assert not v.safe and "lease" in v.reason
    (leases / "1.json").write_text(
        json.dumps({"job": "x", "pid": 999999, "log": str(f / "run.log")})
    )
    assert rc.evaluate(f, env.cfg, env.reg).safe


def test_lease_for_same_job_holds(env):
    f = make(env, "leased", age_s=9 * DAY, job="7", kind="scratch")
    set_job(env, "7", "closed 2020-01-01T00:00:00Z")
    (env.root / "leases").mkdir()
    (env.root / "leases/1.json").write_text(
        json.dumps({"job": "7", "pid": os.getpid()})
    )
    assert "is this job" in rc.evaluate(f, env.cfg, env.reg).reason


def test_lease_dir_glob(env):
    f = make(env, "g", age_s=9 * DAY)
    d = env.root / "u1/leases"
    d.mkdir(parents=True)
    (d / "1.json").write_text(json.dumps({"pid": os.getpid(), "what": str(f)}))
    env.cfg.holders = [{"lease_dir": str(env.root / "u*/leases")}]
    assert "lease" in rc.evaluate(f, env.cfg, env.reg).reason


def test_malformed_lease_fails_closed(env):
    f = make(env, "x", age_s=9 * DAY)
    (env.root / "leases").mkdir()
    (env.root / "leases/2.json").write_text("{nope")
    v = rc.evaluate(f, env.cfg, env.reg)
    assert not v.safe and "unreadable lease" in v.reason


def test_running_claim_record_holds(env):
    f = make(env, "claimed", age_s=9 * DAY)
    (env.root / "claims").mkdir()
    (env.root / "claims/abc.json").write_text(
        json.dumps({"state": "starting", "cwd": str(f)})
    )
    assert "claim abc" in rc.evaluate(f, env.cfg, env.reg).reason


@pytest.mark.parametrize("code,safe", [(0, False), (1, True), (2, False), (127, False)])
def test_command_holder_exit_codes(env, code, safe):
    f = make(env, "h", age_s=9 * DAY)
    env.cfg.holders = [
        {
            "command": ["sh", "-c", f"echo busy; exit {code}", "x", "{path}"],
            "name": "chk",
        }
    ]
    v = rc.evaluate(f, env.cfg, env.reg)
    assert v.safe is safe
    if code == 0:
        assert "chk: busy" in v.reason


def test_command_holder_gets_marker_fields(env):
    f = make(env, "h", age_s=9 * DAY, job="9", kind="scratch")
    set_job(env, "9", "closed 2020-01-01T00:00:00Z")
    out = env.root / "seen"
    env.cfg.holders = [
        {
            "command": [
                "sh",
                "-c",
                'echo "$1 $2 $3 $4 $RECLAIMABLE_PATH $RECLAIMABLE_JOB" > "$5"; exit 1',
                "x",
                "{path}",
                "{owner}",
                "{kind}",
                "{job}",
                str(out),
            ]
        }
    ]
    assert rc.evaluate(f, env.cfg, env.reg).safe
    assert out.read_text().split() == [str(f), "test", "scratch", "9", str(f), "9"]


def test_command_holder_timeout_and_missing_fail_closed(env):
    f = make(env, "h", age_s=9 * DAY)
    env.cfg.holders = [{"command": ["sleep", "5"], "timeout": 0.2}]
    assert "timed out" in rc.evaluate(f, env.cfg, env.reg).reason
    env.cfg.holders = [{"command": ["/nonexistent/holder"]}]
    assert not rc.evaluate(f, env.cfg, env.reg).safe


def test_config_dir_placeholder(env):
    f = make(env, "h", age_s=9 * DAY)
    (env.root / "config").mkdir(exist_ok=True)
    rc.CONFIG_FILE.write_text("")
    helper = rc.CONFIG_FILE.parent / "veto"
    helper.write_text("#!/bin/sh\nexit 0\n")
    helper.chmod(0o755)
    env.cfg.holders = [{"command": ["{config_dir}/veto"]}]
    assert not rc.evaluate(f, env.cfg, env.reg).safe


def test_open_files_block(env, monkeypatch):
    f = make(env, "busy", age_s=9 * DAY)
    monkeypatch.setattr(rc, "open_files", lambda folder: "open files: python[1]")
    assert not rc.evaluate(f, env.cfg, env.reg).safe


# --- job-close gating -----------------------------------------------------------


def fake_pgrep(monkeypatch, rc_code):
    real = rc.run

    def run(cmd, timeout=60, cwd=None):
        if cmd[0] == "pgrep":
            return subprocess.CompletedProcess(
                cmd, rc_code, "4242\n" if rc_code == 0 else "", ""
            )
        return real(cmd, timeout=timeout, cwd=cwd)

    monkeypatch.setattr(rc, "run", run)
    monkeypatch.setattr(rc.shutil, "which", lambda name: "/bin/" + name)


def test_job_open_blocks(env):
    set_job(env, "123", "open")
    v = rc.evaluate(
        make(env, "j", age_s=30 * DAY, job="123", kind="scratch"), env.cfg, env.reg
    )
    assert not v.safe and "job 123 open" in v.reason


def test_job_unknown_or_unconfigured_not_eligible(env):
    f = make(env, "j", age_s=30 * DAY, job="nope")
    assert "unknown" in rc.evaluate(f, env.cfg, env.reg).reason
    env.cfg.job_done = None
    assert not rc.evaluate(
        make(env, "k", age_s=30 * DAY, job="1"), env.cfg, env.reg
    ).safe


def test_job_closed_but_session_running_blocks(env, monkeypatch):
    set_job(env, "5", "closed 2020-01-01T00:00:00Z")
    fake_pgrep(monkeypatch, 0)
    v = rc.evaluate(
        make(env, "j", age_s=30 * DAY, job="5", session="sess-x"), env.cfg, env.reg
    )
    assert not v.safe and "still running" in v.reason


def test_pgrep_miss_is_unknown_not_exited(env, monkeypatch):
    set_job(env, "5", "closed 2020-01-01T00:00:00Z")
    fake_pgrep(monkeypatch, 1)
    v = rc.evaluate(
        make(env, "j", age_s=30 * DAY, job="5", session="sess-x"), env.cfg, env.reg
    )
    assert not v.safe and "unknown" in v.reason
    # A numeric session is a pid and is checked exactly.
    w = rc.evaluate(
        make(env, "k", age_s=30 * DAY, job="5", session="999999"), env.cfg, env.reg
    )
    assert w.safe


def test_ttl_counts_from_job_close_and_session_exit(env):
    recent = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - DAY))
    set_job(env, "5", f"closed {recent}")
    f = make(env, "j", age_s=30 * DAY, job="5", session="999999", kind="scratch")
    v = rc.evaluate(f, env.cfg, env.reg)
    assert v.safe and not v.expired, "scratch TTL is 7d from close (closed 1d ago)"
    env.reg["jobs"] = {}
    env.reg["markers"][str(f)]["session_exit_seen"] = time.time() - 8 * DAY
    set_job(env, "5", "closed 2020-01-01T00:00:00Z")
    assert rc.evaluate(f, env.cfg, env.reg).expired


@pytest.mark.parametrize("rel", ["x/models/w.bin", "a/closed-receipt.json"])
def test_mirror_descendant_deny_names_apply(env, rel):
    env.cfg.deny_names += ["models", "*receipt*"]
    f = make(env, "mir", age_s=30 * DAY, kind="mirror", files={rel: b"1"})
    v = rc.evaluate(f, env.cfg, env.reg)
    assert not v.safe and "deny-listed" in v.reason


# --- worktrees ------------------------------------------------------------------


def git(*args, cwd):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


def make_repo_with_remote(env):
    origin = env.root / "origin.git"
    git("init", "--bare", "-q", str(origin), cwd=env.root)
    main = env.root / "main"
    git("init", "-q", str(main), cwd=env.root)
    for k, v in (("user.email", "t@t"), ("user.name", "t")):
        git("config", k, v, cwd=main)
    (main / "a").write_text("1")
    git("add", "a", cwd=main)
    git("commit", "-qm", "a", cwd=main)
    git("remote", "add", "origin", str(origin), cwd=main)
    git("push", "-q", "origin", "HEAD:refs/heads/main", cwd=main)
    return main


def test_dirty_and_unpushed_worktrees_refused(env):
    main = make_repo_with_remote(env)
    wt = env.root / "data/wt"
    git("worktree", "add", "-q", "--detach", str(wt), cwd=main)
    (wt / ".reclaimable").write_text(
        json.dumps({"owner": "t", "regenerate": "git worktree add", "kind": "worktree"})
    )
    old = time.time() - 30 * DAY
    os.utime(wt / ".reclaimable", (old, old))
    v = rc.evaluate(wt, env.cfg, env.reg)
    assert v.safe and v.repo == "git-linked", v.reason
    (wt / "b").write_text("2")
    assert "dirty" in rc.evaluate(wt, env.cfg, env.reg).reason
    git("add", "b", cwd=wt)
    git("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "b", cwd=wt)
    assert "unpushed" in rc.evaluate(wt, env.cfg, env.reg).reason
    (main / ".reclaimable").write_text(
        json.dumps({"owner": "t", "regenerate": "clone"})
    )
    os.utime(main / ".reclaimable", (old, old))
    assert "git-primary" in rc.evaluate(main, env.cfg, env.reg).reason


def test_mirror_still_checks_nested_repos(env):
    main = make_repo_with_remote(env)
    f = make(env, "mir", age_s=30 * DAY, kind="mirror")
    git("clone", "-q", str(main), str(f / "inner"), cwd=env.root)
    (f / "inner/dirty").write_text("x")
    v = rc.evaluate(f, env.cfg, env.reg)
    assert not v.safe and "nested repo inner" in v.reason


# --- move, verify, delete -------------------------------------------------------


def make_movable(env, rel="scratch1", **kw):
    f = make(env, rel, age_s=30 * DAY, files={"a.txt": b"hello", "d/b.txt": b"bye"})
    dest = env.root / "archive"
    rc.write_json(
        f / ".reclaimable",
        {
            "owner": "t",
            "regenerate": "r",
            "kind": "scratch",
            "move_to": str(dest),
            "holds": [],
            **kw,
        },
    )
    old = time.time() - 30 * DAY
    os.utime(f / ".reclaimable", (old, old))
    return f, dest


def test_move_verifies_then_deletes(env):
    f, dest = make_movable(env)
    v = rc.evaluate(f, env.cfg, env.reg)
    assert v.action == "move"
    ok, detail = rc.remove_folder(v, True, env.cfg, env.reg)
    assert ok and not f.exists()
    assert (
        dest / rc.hostname() / str(f).lstrip("/") / "d/b.txt"
    ).read_bytes() == b"bye"


def test_hash_mismatch_keeps_source(env, monkeypatch):
    f = make(env, "scratch2", age_s=30 * DAY, files={"a.txt": b"hello"})
    real = rc.file_hashes
    calls = []

    def corrupt(root):
        out = real(root)
        calls.append(root)
        if len(calls) == 2:
            out["a.txt"] = "0" * 64
        return out

    monkeypatch.setattr(rc, "file_hashes", corrupt)
    ok, detail = rc.move_and_verify(f, str(env.root / "archive"))
    assert not ok and "hash mismatch" in detail and (f / "a.txt").exists()


def test_marker_touched_after_evaluation_is_kept(env):
    f = make(env, "race", age_s=30 * DAY)
    v = rc.evaluate(f, env.cfg, env.reg)
    os.utime(f / ".reclaimable")
    ok, detail = rc.remove_folder(v, True, env.cfg, env.reg)
    assert not ok and f.exists() and "touched" in detail


def test_hold_added_during_move_keeps_source(env, monkeypatch):
    f, dest = make_movable(env)
    v = rc.evaluate(f, env.cfg, env.reg)
    real = rc.move_and_verify

    def slow(*a, **kw):
        out = real(*a, **kw)
        assert rc.main(["hold", str(f), "late-reader"]) == 0
        return out

    monkeypatch.setattr(rc, "move_and_verify", slow)
    ok, detail = rc.remove_folder(v, True, env.cfg, env.reg)
    assert not ok and f.exists() and "held" in detail


def test_lease_appearing_during_move_keeps_source(env, monkeypatch):
    f, dest = make_movable(env)
    v = rc.evaluate(f, env.cfg, env.reg)
    real = rc.move_and_verify

    def slow(*a, **kw):
        out = real(*a, **kw)
        (env.root / "leases").mkdir(exist_ok=True)
        (env.root / "leases/9.json").write_text(
            json.dumps({"pid": os.getpid(), "what": str(f)})
        )
        return out

    monkeypatch.setattr(rc, "move_and_verify", slow)
    ok, detail = rc.remove_folder(v, True, env.cfg, env.reg)
    assert not ok and f.exists() and "lease" in detail


def test_source_modified_during_move_keeps_source(env, monkeypatch):
    f, dest = make_movable(env)
    v = rc.evaluate(f, env.cfg, env.reg)
    real = rc.move_and_verify

    def slow(*a, **kw):
        out = real(*a, **kw)
        (f / "a.txt").write_bytes(b"changed after copy")
        return out

    monkeypatch.setattr(rc, "move_and_verify", slow)
    ok, detail = rc.remove_folder(v, True, env.cfg, env.reg)
    assert not ok and (f / "a.txt").exists() and "changed" in detail


def test_hold_and_removal_share_one_lock(env, monkeypatch):
    f = make(env, "locked", age_s=30 * DAY)
    v = rc.evaluate(f, env.cfg, env.reg)
    seen = []
    real = rc.hold_lock

    class Spy:
        def __enter__(self):
            seen.append("enter")
            return real().__enter__()

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(rc, "hold_lock", lambda: Spy())
    ok, _ = rc.remove_folder(v, True, env.cfg, env.reg)
    assert ok and seen, "removal re-checks under the same lock `hold` takes"


def test_rmtree_does_not_cross_filesystems(env, monkeypatch, tmp_path):
    d = tmp_path / "t"
    (d / "sub").mkdir(parents=True)
    (d / "sub/f").write_text("x")
    (d / "mnt").mkdir()
    (d / "mnt/keep").write_text("other fs")
    real = os.scandir

    class E:
        def __init__(self, e):
            self.e, self.name, self.path = e, e.name, e.path

        def is_dir(self, follow_symlinks=True):
            return self.e.is_dir(follow_symlinks=follow_symlinks)

        def stat(self, follow_symlinks=True):
            st = self.e.stat(follow_symlinks=follow_symlinks)
            if self.name == "mnt":
                return os.stat_result((st.st_mode, st.st_ino, st.st_dev + 1, *st[3:]))
            return st

    monkeypatch.setattr(rc.os, "scandir", lambda p: [E(e) for e in real(p)])
    left = rc.rmtree_same_dev(d)
    assert (
        left == [d / "mnt"] and (d / "mnt/keep").exists() and not (d / "sub").exists()
    )


# --- floor / LRU ----------------------------------------------------------------


def test_floor_takes_lru_safe_before_ttl(env, monkeypatch):
    a = make(env, "a", age_s=10 * 3600, ttl="3d", files={"x": b"x" * 4096})
    b = make(env, "b", age_s=1 * 3600, ttl="3d", files={"x": b"x" * 4096})
    c = make(env, "c", age_s=20 * 3600, ttl="3d", files={"x": b"x" * 4096})
    rc.main(["hold", str(c), "reader"])
    os.utime(c / ".reclaimable", (time.time() - 20 * 3600,) * 2)
    vs = [rc.evaluate(f, env.cfg, env.reg) for f in (a, b, c)]
    assert not any(v.expired for v in vs)
    env.cfg.floor, env.cfg.target = 10**18, 10**18
    monkeypatch.setattr(rc, "HOME", env.root)
    chosen = [v.folder.name for v, why in rc.plan(vs, env.cfg)]
    assert chosen == ["a", "b"], "LRU order; the held folder is never chosen"
    env.cfg.floor, env.cfg.target = 1, 1
    assert rc.plan(vs, env.cfg) == []


def test_scan_does_not_descend_into_marked_or_denied(env):
    outer = make(env, "outer")
    make(env, "outer/inner")
    (env.root / "data/secret").mkdir(parents=True)
    env.cfg.deny_paths.append(str(env.root / "data/secret"))
    make(env, "secret/hidden")
    found, complete = rc.scan([env.root / "data"], env.cfg)
    assert found == {str(outer)}


# --- symlinks, glob deny on descendants, nested primary repos -------------------


def test_symlink_root_and_ancestor_refused_everywhere(env):
    real = make(env, "real", age_s=30 * DAY, files={"keep.txt": b"precious"})
    (real / ".reclaimable").unlink()
    link = env.root / "data/link"
    link.symlink_to(real, target_is_directory=True)
    (real / ".reclaimable").write_text(
        json.dumps({"owner": "t", "regenerate": "r", "holds": []})
    )
    old = time.time() - 30 * DAY
    os.utime(real / ".reclaimable", (old, old))
    # mark refuses a symlink root and a symlinked ancestor
    assert rc.main(["mark", str(link), "-o", "t", "-r", "r"]) == 2
    assert rc.main(["mark", str(link / "sub"), "-o", "t", "-r", "r"]) == 2
    # evaluation refuses it even though a marker is reachable through the link
    v = rc.evaluate(link, env.cfg, env.reg)
    assert not v.safe and "symlink" in v.reason
    assert not rc.evaluate(link, env.cfg, env.reg).safe
    # final removal refuses it too, and never traverses it
    v.safe, v.action = True, "delete"
    ok, detail = rc.remove_folder(v, True, env.cfg, env.reg)
    assert (
        not ok and (real / "keep.txt").read_bytes() == b"precious" and link.is_symlink()
    )
    with pytest.raises(OSError):
        rc.rmtree_same_dev(link)
    assert (real / "keep.txt").exists()


def test_folder_swapped_for_symlink_before_rename_is_restored(env, monkeypatch):
    f = make(env, "swap", age_s=30 * DAY)
    victim = make(env, "victim", age_s=0, files={"keep.txt": b"precious"})
    v = rc.evaluate(f, env.cfg, env.reg)
    real_rename = os.rename
    state = {"n": 0}

    def rename(a, b):
        if state["n"] == 0 and Path(a) == f:
            # Simulate a race: the folder was replaced by a symlink just before the rename.
            state["n"] += 1
            moved = f.with_name("swapped-away")
            real_rename(f, moved)
            f.symlink_to(victim, target_is_directory=True)
        return real_rename(a, b)

    monkeypatch.setattr(rc.os, "rename", rename)
    ok, detail = rc.remove_folder(v, True, env.cfg, env.reg)
    assert not ok and (victim / "keep.txt").exists() and f.is_symlink()


def test_glob_deny_paths_apply_to_descendants(env):
    env.cfg.deny_paths.append(str(env.root / "data/*/models"))
    f = make(env, "bucket", age_s=30 * DAY, files={"ok.bin": b"1"})
    assert rc.evaluate(f, env.cfg, env.reg).safe
    (f / "models").mkdir()
    (f / "models/w.bin").write_bytes(b"w")
    g = rc.evaluate(f, env.cfg, env.reg)
    assert not g.safe and "deny-listed" in g.reason
    # the denied folder itself is refused too
    assert rc.deny_reason(f / "models", env.cfg)
    # exact (non-glob) deny paths inside a marked folder count as well
    h = make(env, "b2", age_s=30 * DAY, files={"inner/secret/x": b"1"})
    env.cfg.deny_paths.append(str(h / "inner/secret"))
    assert not rc.evaluate(h, env.cfg, env.reg).safe


def test_nested_primary_repo_in_mirror_refused(env):
    main = make_repo_with_remote(env)
    f = make(env, "mir2", age_s=30 * DAY, kind="mirror")
    git("clone", "-q", str(main), str(f / "inner"), cwd=env.root)
    v = rc.evaluate(f, env.cfg, env.reg)
    assert not v.safe and "nested git-primary" in v.reason
    # a nested linked worktree is still fine
    g = make(env, "mir3", age_s=30 * DAY, kind="mirror")
    git("worktree", "add", "-q", "--detach", str(g / "wt"), cwd=main)
    assert rc.evaluate(g, env.cfg, env.reg).safe


# --- session_grace ----------------------------------------------------------------


def iso_ago(s):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - s))


def test_session_grace_unset_keeps_unobservable_session(env, monkeypatch):
    set_job(env, "5", f"closed {iso_ago(30 * DAY)}")
    fake_pgrep(monkeypatch, 1)
    v = rc.evaluate(
        make(env, "j", age_s=30 * DAY, job="5", session="sess-x"), env.cfg, env.reg
    )
    assert not v.safe and "unknown" in v.reason


def test_session_grace_not_elapsed_keeps(env, monkeypatch):
    env.cfg.session_grace = 72 * 3600
    set_job(env, "5", f"closed {iso_ago(DAY)}")
    fake_pgrep(monkeypatch, 1)
    v = rc.evaluate(
        make(env, "j", age_s=30 * DAY, job="5", session="sess-x"), env.cfg, env.reg
    )
    assert not v.safe and "within grace" in v.reason


def test_session_grace_elapsed_counts_as_gone(env, monkeypatch):
    env.cfg.session_grace = 3 * DAY
    set_job(env, "5", f"closed {iso_ago(10 * DAY)}")
    fake_pgrep(monkeypatch, 1)
    f = make(env, "j", age_s=30 * DAY, job="5", session="sess-x")
    v = rc.evaluate(f, env.cfg, env.reg)
    assert v.safe and v.expired, v.reason
    # the TTL clock starts when the grace ended (7d ago), not at mark time
    assert 6.9 * DAY < time.time() - v.clock_start < 7.1 * DAY


def test_missing_close_time_counts_from_first_observation(env, monkeypatch):
    env.cfg.session_grace = 72 * 3600
    set_job(env, "5", "closed")  # closed, no timestamp
    fake_pgrep(monkeypatch, 1)
    f = make(env, "j", age_s=30 * DAY, job="5", session="sess-x")
    v = rc.evaluate(f, env.cfg, env.reg)
    # old marker mtime must not make it expire the moment the close is first seen
    assert not v.safe and "within grace" in v.reason
    first = env.reg["jobs"]["5"]["first_closed_seen"]
    # later sweeps keep the first-observed time (even after the 1h cache expires)
    env.reg["jobs"]["5"]["checked"] -= 7200
    rc.evaluate(f, env.cfg, env.reg)
    assert env.reg["jobs"]["5"]["first_closed_seen"] == first
    # once the grace has passed since first observation, it is eligible
    env.reg["jobs"]["5"].update(
        first_closed_seen=first - 4 * DAY, closed_at=first - 4 * DAY
    )
    assert rc.evaluate(f, env.cfg, env.reg).safe
    # garbled timestamps behave the same
    set_job(env, "6", "closed garbage")
    g = rc.evaluate(
        make(env, "k", age_s=30 * DAY, job="6", session="sess-x"), env.cfg, env.reg
    )
    assert not g.safe and "within grace" in g.reason


def test_missing_close_time_ttl_counts_from_first_observation(env):
    set_job(env, "7", "closed")
    f = make(env, "t", age_s=30 * DAY, job="7", kind="scratch")
    v = rc.evaluate(f, env.cfg, env.reg)
    assert v.safe and not v.expired, (
        "old scratch must not expire the moment a close is seen"
    )


def test_session_grace_requires_successful_nomatch_probe(env, monkeypatch):
    env.cfg.session_grace = 3600
    set_job(env, "5", f"closed {iso_ago(30 * DAY)}")
    f = make(env, "j", age_s=30 * DAY, job="5", session="sess-x")
    # pgrep unavailable
    monkeypatch.setattr(rc.shutil, "which", lambda name: None)
    assert not rc.evaluate(f, env.cfg, env.reg).safe
    # pgrep fails (exit 2)
    fake_pgrep(monkeypatch, 2)
    v = rc.evaluate(f, env.cfg, env.reg)
    assert not v.safe and "unknown" in v.reason

    # pgrep times out
    def boom(cmd, timeout=60, cwd=None):
        raise subprocess.TimeoutExpired(cmd, timeout)

    monkeypatch.setattr(rc, "run", boom)
    assert not rc.evaluate(f, env.cfg, env.reg).safe
    # a clean no-match probe is what lets the grace apply
    fake_pgrep(monkeypatch, 1)
    assert rc.evaluate(f, env.cfg, env.reg).safe


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores modes")
def test_unreadable_lease_and_claim_dirs_fail_closed(env):
    f = make(env, "x", age_s=9 * DAY)
    leases = env.root / "leases"
    leases.mkdir()
    (leases / "1.json").write_text(json.dumps({"pid": os.getpid(), "what": str(f)}))
    leases.chmod(0)
    try:
        v = rc.evaluate(f, env.cfg, env.reg)
        assert not v.safe and "unreadable" in v.reason
    finally:
        leases.chmod(0o755)
    claims = env.root / "claims"
    claims.mkdir()
    (claims / "a.json").write_text(
        json.dumps({"state": "running", "pid": os.getpid(), "cwd": str(f)})
    )
    claims.chmod(0)
    try:
        v = rc.evaluate(f, env.cfg, env.reg)
        assert not v.safe and "unreadable" in v.reason
    finally:
        claims.chmod(0o755)
    # a claim_id whose record sits in an unreadable dir
    (leases / "1.json").write_text(json.dumps({"pid": os.getpid(), "claim_id": "a"}))
    claims.chmod(0)
    try:
        assert not rc.evaluate(f, env.cfg, env.reg).safe
    finally:
        claims.chmod(0o755)


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores modes")
def test_unreadable_dir_inside_lease_glob_fails_closed(env):
    f = make(env, "x", age_s=9 * DAY)
    base = env.root / "homes"
    (base / "u1/leases").mkdir(parents=True)
    (base / "u2").mkdir()
    env.cfg.holders = [{"lease_dir": str(base / "*/leases")}]
    assert rc.evaluate(f, env.cfg, env.reg).safe  # u2 has no lease dir: fine
    (base / "u2").chmod(0)  # can't tell whether u2/leases exists
    try:
        assert not rc.evaluate(f, env.cfg, env.reg).safe
    finally:
        (base / "u2").chmod(0o755)
    base.chmod(0)
    try:
        assert not rc.evaluate(f, env.cfg, env.reg).safe
    finally:
        base.chmod(0o755)


def test_session_grace_needs_closed_job_and_ignores_pids_and_live_hits(
    env, monkeypatch
):
    env.cfg.session_grace = 3600
    set_job(env, "5", "open")
    fake_pgrep(monkeypatch, 1)
    assert not rc.evaluate(
        make(env, "o", age_s=30 * DAY, job="5", session="sess-x"), env.cfg, env.reg
    ).safe
    set_job(env, "6", f"closed {iso_ago(30 * DAY)}")
    # a live pgrep hit still blocks
    fake_pgrep(monkeypatch, 0)
    v = rc.evaluate(
        make(env, "h", age_s=30 * DAY, job="6", session="sess-x"), env.cfg, env.reg
    )
    assert not v.safe and "still running" in v.reason
    # numeric pids stay exact: a live pid blocks regardless of grace, a dead one is gone
    live = rc.evaluate(
        make(env, "p", age_s=30 * DAY, job="6", session=str(os.getpid())),
        env.cfg,
        env.reg,
    )
    assert not live.safe and "still running" in live.reason
    dead = rc.evaluate(
        make(env, "d", age_s=30 * DAY, job="6", session="999999"), env.cfg, env.reg
    )
    assert dead.safe


def test_session_grace_config_parsing(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text('session_grace = "72h"\n')
    assert _fresh().load_config(p).session_grace == 72 * 3600
    assert _fresh().load_config(tmp_path / "none.toml").session_grace is None
    p.write_text('session_grace = "soon"\n')
    with pytest.raises(ValueError):
        _fresh().load_config(p)


# --- repo state is re-checked right before removal ------------------------------


def linked_worktree(env, rel="wt2"):
    main = make_repo_with_remote(env)
    wt = env.root / "data" / rel
    git("worktree", "add", "-q", "--detach", str(wt), cwd=main)
    (wt / ".reclaimable").write_text(
        json.dumps({"owner": "t", "regenerate": "git worktree add", "kind": "worktree"})
    )
    old = time.time() - 30 * DAY
    os.utime(wt / ".reclaimable", (old, old))
    return main, wt


def test_dirty_file_added_after_evaluation_blocks_removal(env):
    main, wt = linked_worktree(env)
    v = rc.evaluate(wt, env.cfg, env.reg)
    assert v.safe and v.repo == "git-linked", v.reason
    (wt / "uncommitted.txt").write_text("precious")
    ok, detail = rc.remove_folder(v, True, env.cfg, env.reg)
    assert not ok and "dirty" in detail
    assert (wt / "uncommitted.txt").read_text() == "precious"


def test_unpushed_commit_after_evaluation_blocks_removal(env):
    main, wt = linked_worktree(env, "wt3")
    v = rc.evaluate(wt, env.cfg, env.reg)
    assert v.safe, v.reason
    (wt / "c").write_text("1")
    git("add", "c", cwd=wt)
    git("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "c", cwd=wt)
    ok, detail = rc.remove_folder(v, True, env.cfg, env.reg)
    assert not ok and "unpushed" in detail and wt.exists()


def test_nested_repo_dirtied_after_evaluation_blocks_removal(env):
    main = make_repo_with_remote(env)
    f = make(env, "mir4", age_s=30 * DAY, kind="mirror")
    git("worktree", "add", "-q", "--detach", str(f / "wt"), cwd=main)
    v = rc.evaluate(f, env.cfg, env.reg)
    assert v.safe, v.reason
    (f / "wt/new.txt").write_text("x")
    ok, detail = rc.remove_folder(v, True, env.cfg, env.reg)
    assert not ok and "nested repo wt" in detail and (f / "wt/new.txt").exists()


def test_dirty_file_added_during_move_keeps_source(env, monkeypatch):
    main, wt = linked_worktree(env, "wt5")
    rc.write_json(
        wt / ".reclaimable",
        {
            "owner": "t",
            "regenerate": "r",
            "kind": "worktree",
            "move_to": str(env.root / "arch"),
        },
    )
    old = time.time() - 30 * DAY
    os.utime(wt / ".reclaimable", (old, old))
    v = rc.evaluate(wt, env.cfg, env.reg)
    assert v.safe and v.action == "move", v.reason
    real = rc.move_and_verify

    def slow(*a, **kw):
        out = real(*a, **kw)
        # tracked-file edit leaves the copy matching hashes only if made before; here a new file
        (wt / "late.txt").write_text("late")
        return out

    monkeypatch.setattr(rc, "move_and_verify", slow)
    ok, detail = rc.remove_folder(v, True, env.cfg, env.reg)
    assert not ok and (wt / "late.txt").exists()


# --- job state is re-asked right before removal ---------------------------------


@pytest.mark.parametrize("later", ["open", "garbage", None])
def test_job_state_change_after_evaluation_blocks_removal(env, later):
    set_job(env, "9", "closed 2020-01-01T00:00:00Z")
    f = make(env, "jj1", age_s=30 * DAY, job="9", kind="scratch")
    v = rc.evaluate(f, env.cfg, env.reg)
    assert v.safe and v.expired, v.reason  # positive answer is now cached
    if later is None:
        (
            env.jobs / "9"
        ).unlink()  # helper now exits 2 (unknown), as with a keep/hold label
    else:
        set_job(env, "9", later)
    ok, detail = rc.remove_folder(v, True, env.cfg, env.reg)
    assert not ok and f.exists() and "job 9" in detail
    assert "9" not in env.reg.get("jobs", {}) or not env.reg["jobs"]["9"].get("closed")


def test_job_still_closed_removes(env):
    set_job(env, "9", "closed 2020-01-01T00:00:00Z")
    f = make(env, "jj2", age_s=30 * DAY, job="9", kind="scratch")
    v = rc.evaluate(f, env.cfg, env.reg)
    ok, _ = rc.remove_folder(v, True, env.cfg, env.reg)
    assert ok and not f.exists()


def test_job_label_added_during_move_keeps_source(env, monkeypatch):
    set_job(env, "9", "closed 2020-01-01T00:00:00Z")
    f, dest = make_movable(env, "jj3", job="9")
    v = rc.evaluate(f, env.cfg, env.reg)
    assert v.safe and v.action == "move", v.reason
    real = rc.move_and_verify

    def slow(*a, **kw):
        out = real(*a, **kw)
        (env.jobs / "9").unlink()
        return out

    monkeypatch.setattr(rc, "move_and_verify", slow)
    ok, detail = rc.remove_folder(v, True, env.cfg, env.reg)
    assert not ok and f.exists() and "job 9" in detail


# --- session state is re-decided right before removal ---------------------------


def test_numeric_session_alive_after_evaluation_blocks_removal(env):
    import subprocess as sp

    p = sp.Popen(["sleep", "30"])
    p.kill()
    p.wait()  # a pid that is now dead
    f = make(env, "ss1", age_s=30 * DAY, session=str(p.pid))
    v = rc.evaluate(f, env.cfg, env.reg)
    assert v.safe, v.reason
    live = sp.Popen(["sleep", "30"])
    try:
        # the marker is edited to name a live pid
        m = json.loads((f / ".reclaimable").read_text())
        m["session"] = str(live.pid)
        (f / ".reclaimable").write_text(json.dumps(m))
        old = v.marker.mtime
        os.utime(f / ".reclaimable", (old, old))
        ok, detail = rc.remove_folder(v, True, env.cfg, env.reg)
        assert not ok and f.exists() and "still running" in detail
    finally:
        live.kill()
        live.wait()


def test_session_appearing_alive_between_evaluate_and_removal_is_kept(env, monkeypatch):
    env.cfg.session_grace = 3600
    set_job(env, "5", f"closed {iso_ago(30 * DAY)}")
    fake_pgrep(monkeypatch, 1)
    f = make(env, "ss2", age_s=30 * DAY, job="5", session="sess-x")
    v = rc.evaluate(f, env.cfg, env.reg)
    assert v.safe, v.reason
    fake_pgrep(monkeypatch, 0)  # the session shows up again
    ok, detail = rc.remove_folder(v, True, env.cfg, env.reg)
    assert not ok and f.exists() and "still running" in detail


@pytest.mark.parametrize("code", [2, None])
def test_session_probe_failing_at_removal_is_kept(env, monkeypatch, code):
    env.cfg.session_grace = 3600
    set_job(env, "5", f"closed {iso_ago(30 * DAY)}")
    fake_pgrep(monkeypatch, 1)
    f = make(env, "ss3", age_s=30 * DAY, job="5", session="sess-x")
    v = rc.evaluate(f, env.cfg, env.reg)
    assert v.safe, v.reason
    if code is None:
        monkeypatch.setattr(rc.shutil, "which", lambda name: None)
    else:
        fake_pgrep(monkeypatch, code)
    ok, detail = rc.remove_folder(v, True, env.cfg, env.reg)
    assert not ok and f.exists() and "unknown" in detail


def test_session_alive_during_move_keeps_source(env, monkeypatch):
    env.cfg.session_grace = 3600
    set_job(env, "5", f"closed {iso_ago(30 * DAY)}")
    fake_pgrep(monkeypatch, 1)
    f, dest = make_movable(env, "ss4", job="5", session="sess-x")
    v = rc.evaluate(f, env.cfg, env.reg)
    assert v.safe and v.action == "move", v.reason
    real = rc.move_and_verify

    def slow(*a, **kw):
        out = real(*a, **kw)
        fake_pgrep(monkeypatch, 0)
        return out

    monkeypatch.setattr(rc, "move_and_verify", slow)
    ok, detail = rc.remove_folder(v, True, env.cfg, env.reg)
    assert not ok and f.exists() and "still running" in detail


def test_session_still_gone_at_removal_removes(env, monkeypatch):
    env.cfg.session_grace = 3600
    set_job(env, "5", f"closed {iso_ago(30 * DAY)}")
    fake_pgrep(monkeypatch, 1)
    f = make(env, "ss5", age_s=30 * DAY, job="5", session="sess-x")
    v = rc.evaluate(f, env.cfg, env.reg)
    ok, _ = rc.remove_folder(v, True, env.cfg, env.reg)
    assert ok and not f.exists()


# --- relative paths are normalised to absolute lexical paths ---------------------


def test_relative_mark_and_evaluate_apply_absolute_glob_deny(env, monkeypatch):
    data = env.root / "data"
    data.mkdir(exist_ok=True)
    env.cfg.deny_paths.append(str(data / "*/models"))
    monkeypatch.chdir(data)
    make(env, "bucket", age_s=30 * DAY)
    (data / "bucket/models").mkdir()
    (data / "bucket/models/w.bin").write_bytes(b"w")
    absolute = rc.evaluate(data / "bucket", env.cfg, env.reg)
    relative = rc.evaluate(Path("bucket"), env.cfg, env.reg)
    assert not absolute.safe and not relative.safe
    assert "deny-listed" in relative.reason and relative.folder == data / "bucket"
    # `mark` by relative path registers the absolute path
    (data / "other").mkdir()
    assert rc.main(["mark", "other", "-o", "t", "-r", "r"]) == 0
    markers = json.loads(rc.REGISTRY.read_text())["markers"]
    assert str(data / "other") in markers and "other" not in markers
    assert rc.main(["mark", "../data/./other2", "-o", "t", "-r", "r"]) == 0
    assert str(data / "other2") in json.loads(rc.REGISTRY.read_text())["markers"]


def test_relative_registry_entries_are_ignored_not_deleted(env, monkeypatch):
    data = env.root / "data"
    f = make(env, "bucket", age_s=30 * DAY)
    monkeypatch.chdir(data)
    reg = {"markers": {"bucket": {"registered": 1}, str(f) + "/": {"registered": 2}}}
    folders = rc.discover(env.cfg, reg)
    assert folders == [f]
    assert "bucket" in reg["markers"], "relative entry stays, untouched"
    assert str(f) in reg["markers"] and str(f) + "/" not in reg["markers"]
    assert "ignoring relative registry path" in rc.LOG_FILE.read_text()
    assert f.exists()


# --- TTL clock is recomputed at removal; volume_floors paths are absolute --------


def test_job_reclosed_recently_keeps_ttl_candidate(env):
    set_job(env, "9", f"closed {iso_ago(30 * DAY)}")
    f = make(env, "rc1", age_s=30 * DAY, job="9", kind="scratch")
    v = rc.evaluate(f, env.cfg, env.reg)
    assert v.safe and v.expired, v.reason
    set_job(env, "9", f"closed {iso_ago(60)}")  # reopened and re-closed a minute ago
    ok, detail = rc.remove_folder(v, True, env.cfg, env.reg)
    assert not ok and f.exists() and "no longer expired" in detail


def test_floor_pressure_candidate_ignores_recomputed_clock(env):
    set_job(env, "9", f"closed {iso_ago(30 * DAY)}")
    f = make(env, "rc2", age_s=30 * DAY, job="9", kind="scratch")
    v = rc.evaluate(f, env.cfg, env.reg)
    set_job(env, "9", f"closed {iso_ago(60)}")
    ok, _ = rc.remove_folder(v, True, env.cfg, env.reg, floor_pressure=True)
    assert ok and not f.exists()


def test_job_reclosed_during_move_keeps_source(env, monkeypatch):
    set_job(env, "9", f"closed {iso_ago(30 * DAY)}")
    f, dest = make_movable(env, "rc3", job="9")
    v = rc.evaluate(f, env.cfg, env.reg)
    assert v.safe and v.expired and v.action == "move", v.reason
    real = rc.move_and_verify

    def slow(*a, **kw):
        out = real(*a, **kw)
        set_job(env, "9", f"closed {iso_ago(30)}")
        return out

    monkeypatch.setattr(rc, "move_and_verify", slow)
    ok, detail = rc.remove_folder(v, True, env.cfg, env.reg)
    assert not ok and f.exists() and "no longer expired" in detail


def test_sweep_ttl_selected_candidate_still_removed(env):
    set_job(env, "9", f"closed {iso_ago(30 * DAY)}")
    f = make(env, "rc4", age_s=30 * DAY, job="9", kind="scratch")
    rc.write_json(rc.ARMED_FILE, {"armed_at": time.time() - 2 * DAY})
    rc.sweep(sweep_args(), env.cfg)
    assert not f.exists()


def test_relative_volume_floors_key_is_absolute(env, monkeypatch, tmp_path):
    mount = env.root
    while not os.path.ismount(mount) and mount != mount.parent:
        mount = mount.parent
    monkeypatch.chdir(mount)
    cfg_file = tmp_path / "c.toml"
    cfg_file.write_text('volume_floors = { "." = "10GB", "x/../y" = "1GB" }\n')
    cfg = _fresh().load_config(cfg_file)
    assert cfg.volume_floors == {str(mount): 10 * 10**9, str(mount / "y"): 10**9}


def test_plan_matches_volume_floor_by_absolute_mount(env, monkeypatch):
    f = make(env, "vf", age_s=3600, ttl="3d", files={"x": b"x" * 4096})
    v = rc.evaluate(f, env.cfg, env.reg)
    mount = f
    while not os.path.ismount(mount) and mount != mount.parent:
        mount = mount.parent
    other = Path("/")  # pretend home lives on another device when possible
    if other.stat().st_dev == f.stat().st_dev:
        pytest.skip("home and data share a device here")
    monkeypatch.setattr(rc, "HOME", other)
    monkeypatch.chdir(mount)
    env.cfg.volume_floors = {str(rc.expand(".")): 10**18}
    assert [x.folder for x, _ in rc.plan([v], env.cfg)] == [f]


# --- review round: marker validity, capacity, ignored files ----------------------


@pytest.mark.parametrize(
    "bad",
    [{"regenerate": ""}, {"regenerate": "  "}, {"regenerate": 5}, {"regenerate": None}],
)
def test_marker_without_regenerate_is_invalid_and_kept(env, bad):
    f = make(env, "noregen", age_s=99 * DAY, **bad)
    v = rc.evaluate(f, env.cfg, env.reg)
    assert not v.safe and "regenerate" in v.reason
    g = make(env, "noregen2", age_s=99 * DAY)
    data = json.loads((g / ".reclaimable").read_text())
    del data["regenerate"]
    (g / ".reclaimable").write_text(json.dumps(data))
    assert "regenerate" in rc.evaluate(g, env.cfg, env.reg).reason


def test_hardlinks_are_counted_once(env):
    f = make(env, "hl", age_s=30 * DAY, files={"a.bin": b"x" * 200_000})
    os.link(f / "a.bin", f / "b.bin")
    os.link(f / "a.bin", f / "c.bin")
    v = rc.evaluate(f, env.cfg, env.reg)
    solo = make(env, "solo", age_s=30 * DAY, files={"a.bin": b"x" * 200_000})
    one = rc.evaluate(solo, env.cfg, env.reg)
    assert v.size < one.size + 8192, (v.size, one.size)


def test_pressure_sweep_stops_when_real_free_space_reaches_target(env, monkeypatch):
    names = ["pa", "pb", "pc"]
    folders = [
        make(env, n, age_s=(10 - i) * 3600, ttl="3d", files={"x": b"x" * 4096})
        for i, n in enumerate(names)
    ]
    monkeypatch.setattr(rc, "HOME", env.root)
    env.cfg.floor, env.cfg.target = 10**18, 10**18

    def fake_free(path):
        return 5 if all(f.exists() for f in folders) else 10**18 + 1

    monkeypatch.setattr(rc, "free_bytes", fake_free)
    rc.write_json(rc.ARMED_FILE, {"armed_at": time.time() - 2 * DAY})
    rc.sweep(sweep_args(floor=10**18, target=10**18), env.cfg)
    assert sum(f.exists() for f in folders) == 2, (
        "only the oldest is removed; the plan overshoots"
    )


def ignore_in_main(main, pattern):
    exclude = main / ".git/info/exclude"
    exclude.parent.mkdir(exist_ok=True)
    exclude.write_text(pattern + "\n")


def test_worktree_with_ignored_files_needs_ignored_ok(env):
    main, wt = linked_worktree(env, "ig1")
    ignore_in_main(main, "data/")
    assert rc.evaluate(wt, env.cfg, env.reg).safe
    (wt / "data").mkdir()
    (wt / "data/copy.bin").write_bytes(b"irreplaceable")
    v = rc.evaluate(wt, env.cfg, env.reg)
    assert not v.safe and "contains ignored files; marker lacks ignored_ok" in v.reason
    data = json.loads((wt / ".reclaimable").read_text())
    data["ignored_ok"] = True
    (wt / ".reclaimable").write_text(json.dumps(data))
    old = time.time() - 30 * DAY
    os.utime(wt / ".reclaimable", (old, old))
    assert rc.evaluate(wt, env.cfg, env.reg).safe


def test_ignored_file_added_before_removal_blocks(env):
    main, wt = linked_worktree(env, "ig2")
    ignore_in_main(main, "data/")
    v = rc.evaluate(wt, env.cfg, env.reg)
    assert v.safe
    (wt / "data").mkdir()
    (wt / "data/x").write_text("1")
    ok, detail = rc.remove_folder(v, True, env.cfg, env.reg)
    assert not ok and "ignored_ok" in detail and wt.exists()


def test_nested_linked_worktree_ignored_files(env):
    main = make_repo_with_remote(env)
    ignore_in_main(main, "data/")
    f = make(env, "ig3", age_s=30 * DAY, kind="mirror")
    git("worktree", "add", "-q", "--detach", str(f / "wt"), cwd=main)
    assert rc.evaluate(f, env.cfg, env.reg).safe
    (f / "wt/data").mkdir()
    (f / "wt/data/x").write_text("1")
    v = rc.evaluate(f, env.cfg, env.reg)
    assert not v.safe and "nested repo wt" in v.reason and "ignored_ok" in v.reason


def test_ignored_ok_must_be_boolean(env):
    f = make(env, "ig4", age_s=30 * DAY, ignored_ok="yes")
    assert "ignored_ok" in rc.evaluate(f, env.cfg, env.reg).reason


@pytest.mark.skipif(not rc.shutil.which("jj"), reason="jj not installed")
def test_jj_secondary_workspace_ignored_files(env):
    main = env.root / "jjmain"
    subprocess.run(["jj", "git", "init", str(main)], check=True, capture_output=True)
    (main / ".gitignore").write_text("data/\n")
    (main / "a").write_text("a")
    subprocess.run(
        ["jj", "commit", "-m", "init"], cwd=main, check=True, capture_output=True
    )
    ws = env.root / "jjws"
    subprocess.run(
        ["jj", "workspace", "add", str(ws)], cwd=main, check=True, capture_output=True
    )
    assert rc.ignored_files(ws, "jj-secondary") is None
    (ws / "data").mkdir()
    (ws / "data/y").write_text("y")
    assert "ignored files" in rc.ignored_files(ws, "jj-secondary")


# --- aliases: Data-volume firmlinks, case, Unicode --------------------------------


def alias(path):
    return Path("/System/Volumes/Data" + str(path))


@pytest.mark.skipif(
    not Path("/System/Volumes/Data").exists(), reason="no APFS Data volume here"
)
def test_data_volume_alias_of_protected_path_is_refused(env):
    protected = env.root / "data/protected"
    protected.mkdir(parents=True)
    env.cfg.deny_paths.append(str(protected))
    assert rc.deny_reason(protected / "x", env.cfg)
    assert rc.deny_reason(alias(protected), env.cfg)
    assert rc.deny_reason(alias(protected / "x"), env.cfg)
    assert rc.main(["mark", str(alias(protected / "x")), "-o", "t", "-r", "r"]) == 2
    # built-ins, broad roots and exact denies share the gap
    assert rc.deny_reason(alias(Path.home() / ".ssh/keys"), env.cfg)
    assert rc.deny_reason(alias(Path.home()), env.cfg)
    assert rc.deny_reason(Path("/System/Volumes/Data"), env.cfg)
    # an evaluated folder reached through the alias is the same folder
    f = make(env, "al", age_s=30 * DAY)
    assert rc.evaluate(alias(f), env.cfg, env.reg).folder == f


def test_case_variants_of_protected_paths(env):
    root = env.root
    (root / "Documents").mkdir()
    (root / "Protected").mkdir()
    env.cfg.deny_exact.append(str(root / "Documents"))
    env.cfg.deny_paths.append(str(root / "Protected"))
    for variant in ("documents", "DOCUMENTS"):
        assert rc.deny_reason(root / variant, env.cfg), variant
    for variant in ("protected", "PROTECTED"):
        assert rc.deny_reason(root / variant / "sub", env.cfg), variant
    assert rc.deny_reason(root / "other", env.cfg) is None


def test_unicode_normalisation_variants(env):
    env.cfg.deny_names.append("café")  # NFC
    nfd = "café"
    assert rc.deny_reason(env.root / nfd, env.cfg)
    env.cfg.deny_paths.append(str(env.root / "café-keep"))
    assert rc.deny_reason(env.root / "café-keep" / "x", env.cfg)
    f = make(env, "uni", age_s=30 * DAY, files={f"{nfd}/x": b"1"})
    v = rc.evaluate(f, env.cfg, env.reg)
    assert not v.safe and "deny-listed" in v.reason


def test_photoslibrary_uppercase(env):
    assert rc.deny_reason(env.root / "Pics.PHOTOSLIBRARY" / "x", env.cfg)
    assert rc.deny_reason(env.root / "Pics.PhotosLibrary", env.cfg)


@pytest.mark.parametrize(
    "rel",
    [
        "x/Models/w.bin",
        "x/MODELS/w.bin",
        "Frozen-X/a",
        "a/Receipt",
        "Experiments/Results/r1",
    ],
)
def test_case_variant_descendant_names_block(env, rel):
    env.cfg.deny_names += ["models", "frozen*", "*receipt*"]
    env.cfg.deny_sequences.append(("experiments", "results"))
    f = make(env, "cv", age_s=30 * DAY, files={rel: b"1"})
    v = rc.evaluate(f, env.cfg, env.reg)
    assert not v.safe and "deny-listed" in v.reason


def test_case_variant_descendant_glob_and_git_dirs(env):
    env.cfg.deny_paths.append(str(env.root / "data/*/Models"))
    f = make(env, "bk", age_s=30 * DAY, files={"models/w": b"1"})
    assert not rc.evaluate(f, env.cfg, env.reg).safe
    assert rc.deny_reason(env.root / "src/foo/.GIT", env.cfg)
    assert rc.deny_reason(env.root / "src/foo/.Jj/repo", env.cfg)


def test_identity_catches_other_spellings_of_a_protected_dir(env):
    protected = env.root / "Keep"
    protected.mkdir()
    env.cfg.deny_paths.append(str(protected))
    other = env.root / "keep"
    if not other.exists():
        pytest.skip("case-sensitive filesystem")
    assert rc.identity(other) == rc.identity(protected)
    assert rc.deny_reason(other, env.cfg)
    assert rc.protected_identities(env.cfg)


@pytest.mark.parametrize(
    "prefix",
    [
        "/system/volumes/data",
        "/sYsTeM/vOlUmEs/dAtA",
        "/ſystem/Volumes/Data",  # folding changes the original component's spelling
        "/Ｓystem/Volumes/Data",  # conservative compatibility normalisation
    ],
)
def test_data_prefix_variants_block_combined_glob_bypass(env, prefix):
    f = make(env, "bucket", age_s=30 * DAY, files={"models/weights": b"keep"})
    env.cfg.deny_paths.append(str(env.root / "data/*/models"))
    v = rc.evaluate(Path(prefix + str(f)), env.cfg, env.reg)
    assert v.folder == f
    assert not v.safe and "deny-list" in v.reason
    assert (f / "models/weights").read_bytes() == b"keep"


def test_decomposed_data_prefix_is_canonical(env, monkeypatch):
    # The real prefix is ASCII (NFD is identical). An accented test prefix proves
    # canonical composition works without creating anything outside this fixture.
    monkeypatch.setattr(rc, "DATA_VOLUME", "/Systém/Volumes/Data")
    f = make(env, "café", files={"models/weights": b"keep"})
    env.cfg.deny_paths.append(str(env.root / "data/*/models"))
    prefix = unicodedata.normalize("NFD", rc.DATA_VOLUME).swapcase()
    v = rc.evaluate(Path(prefix + str(f)), env.cfg, env.reg)
    assert v.folder == f
    assert not v.safe and "deny-list" in v.reason


@pytest.mark.parametrize("pattern", ["*.bin", "[w]*.bin", "?.bin"])
def test_glob_deny_protects_hardlink_identity(env, pattern):
    protected = env.root / "protected"
    protected.mkdir()
    target = protected / "w.bin"
    target.write_bytes(b"keep")
    f = make(env, "bucket")
    os.link(target, f / "innocent")
    env.cfg.deny_paths.append(str(protected / pattern))
    assert rc.identity(target) in rc.protected_identities(env.cfg)
    v = rc.evaluate(f, env.cfg, env.reg)
    assert not v.safe and "deny-list" in v.reason


def test_glob_identity_expansion_folds_literal_components(env):
    protected = env.root / "café-keep"
    protected.mkdir()
    target = protected / "Weights.bin"
    target.write_bytes(b"keep")
    f = make(env, "bucket")
    os.link(target, f / "innocent")
    env.cfg.deny_paths.append(str(env.root / "CAFÉ-KEEP/*.BIN"))
    assert not rc.evaluate(f, env.cfg, env.reg).safe


def test_unreadable_deny_glob_fails_closed(env, monkeypatch):
    f = make(env, "bucket")
    protected = env.root / "protected"
    protected.mkdir()
    env.cfg.deny_paths.append(str(protected / "*/models"))
    original = rc.list_dir

    def unreadable(path):
        if path == protected:
            raise rc.Unreadable("permission denied")
        return original(path)

    monkeypatch.setattr(rc, "list_dir", unreadable)
    v = rc.evaluate(f, env.cfg, env.reg)
    assert not v.safe and "unreadable" in v.reason
    assert rc.deny_reason(f, env.cfg)


@pytest.mark.parametrize("prefix", ["/system/volumes/data", "/sYsTeM/vOlUmEs/dAtA"])
def test_data_prefix_variants_in_deny_patterns_and_walk(env, prefix):
    f = make(env, "bucket", files={"models/weights": b"keep"})
    env.cfg.deny_paths.append(prefix + str(env.root / "data/*/models"))
    assert rc.walk(f, env.cfg, check_names=True).problem
    assert rc.deny_reason(Path(prefix + str(f / "models")), env.cfg)
    assert rc.deny_reason(Path(prefix + "/Users"), env.cfg)


def test_related_paths_fold_normalise_and_strip_prefix(env):
    f = make(env, "café")
    ref = Path("/system/volumes/data" + unicodedata.normalize("NFD", str(f)).upper())
    assert rc.related(ref / "child", f)
    assert rc.related(f, ref / "child")
    assert not rc.related(f, f.with_name(f.name + "-other"))


def test_lease_data_alias_and_case_variant_holds(env):
    f = make(env, "café")
    leases = env.root / "leases"
    leases.mkdir()
    (leases / "1.json").write_text(
        json.dumps(
            {"pid": os.getpid(), "what": "/system/volumes/data" + str(f).upper()}
        )
    )
    v = rc.evaluate(f, env.cfg, env.reg)
    assert not v.safe and "lease" in v.reason


def test_discovery_roots_use_canonical_comparisons(env):
    f = make(env, "café")
    reg = {"markers": {str(f): {}}, "last_scan": rc.now()}
    root = Path("/system/volumes/data" + str(f.parent).upper())
    assert rc.discover(env.cfg, reg, roots=[root]) == [f]


def test_export_broad_roots_use_canonical_comparisons(env, monkeypatch):
    monkeypatch.setattr(rc, "HOME", env.root / "Home")
    assert not rc.export_ok(Path("/system/volumes/data" + str(rc.HOME).upper()))
    assert not rc.export_ok(Path("/system/volumes/data/uSeRs/example"))


def test_double_slash_data_prefix_and_component_boundaries(env):
    assert rc.expand("//sYsTeM/Volumes/Data/Users") == Path("/Users")
    assert rc.deny_reason(Path("//Users"), env.cfg)
    assert rc.expand("/System/Volumes/Database/x") == Path("/System/Volumes/Database/x")


def test_scan_pruning_folds_paths_and_names(env, monkeypatch):
    make(env, "NODE_MODULES/cache")
    make(env, "ordinary/.GIT/cache")
    f = make(env, "café/cache")
    monkeypatch.setattr(rc, "SCAN_PRUNE_PATHS", [str(f.parent).upper()])
    found, complete = rc.scan(env.cfg.roots, env.cfg)
    assert complete and not found


def test_hold_paths_deduplicate_and_release_canonical_alias(env):
    f = make(env, "café")
    child = str(f / "part")
    other = "/sYsTeM/Volumes/Data" + unicodedata.normalize("NFD", child).upper()
    assert rc.main(["hold", str(f), "job42", "-p", child]) == 0
    assert rc.main(["hold", str(f), "job42", "-p", other]) == 0
    assert len(rc.read_marker(f).holds) == 1
    assert rc.main(["release", str(f), "job42", "-p", child]) == 0
    assert not rc.read_marker(f).holds


def test_volume_floor_lookup_uses_canonical_path(env, monkeypatch):
    f = make(env, "bucket")
    monkeypatch.setattr(rc.os.path, "ismount", lambda p: p == f.parent)
    env.cfg.volume_floors = {"/system/volumes/data" + str(f.parent).upper(): 123}
    assert rc.volume_limits(f, env.cfg)[0] == 123


def test_glob_ancestor_identity_protects_other_alias(env, monkeypatch):
    protected = env.root / "keep"
    target = protected / "child"
    target.mkdir(parents=True)
    f = make(env, "bucket")
    env.cfg.deny_paths.append(str(protected / "chi?d"))
    original = rc.identity
    # Simulate a non-symlink directory alias without needing another mount.
    monkeypatch.setattr(
        rc, "identity", lambda p: original(protected) if p == f else original(p)
    )
    assert rc.deny_reason(f, env.cfg)


def test_missing_glob_is_not_a_global_veto(env):
    f = make(env, "bucket")
    env.cfg.deny_paths.append(str(env.root / "absent/*/models"))
    assert rc.evaluate(f, env.cfg, env.reg).safe
