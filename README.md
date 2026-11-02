# reclaimable

Cleanup usually happens only when the tool that made a cache runs, so disk space
isn't freed when something else needs it, and nobody knows what is safe to delete.
`reclaimable` flips that: anything regenerable gets a `.reclaimable` marker in the
folder it governs, and one janitor per host (`reclaimable sweep`, run hourly from
launchd/cron/systemd) removes or moves expired folders and frees space
least-recently-used first when a disk runs low. It only touches folders that pass
every safety check, and it does nothing until you arm the host.

Single-file Python 3.11+, standard library only.

```sh
uv tool install git+https://github.com/OWNER/reclaimable   # or copy ./reclaimable onto PATH
reclaimable mark ~/proj/.cache -o mytool -r "mytool build recreates it" -t 3d
reclaimable ls                  # age, size, TTL, eligibility and why
reclaimable sweep -n            # dry run
reclaimable arm                 # real sweeps begin 24 h later
```

## Marker

`PATH/.reclaimable` is a JSON file:

```json
{"owner": "mytool", "ttl": "3d", "regenerate": "mytool build recreates it",
 "kind": "mirror", "job": "1234", "session": "4242", "move_to": "backup:~/parked",
 "holds": [{"job": "indexer", "path": "sub/dir", "at": 1762000000}]}
```

`owner` and `regenerate` are required. `kind` is `cache` (default), `scratch`,
`worktree`, `mirror` or `staged`. **Last use is the marker's mtime**: owners run
`reclaimable touch PATH` (or `touch PATH/.reclaimable`) whenever they use the
folder. Unknown fields are preserved. Default TTLs (`default_ttls` overrides):
cache 24h, mirror 3d, scratch 7d, staged 2d, worktree 7d. For job-tied data the
TTL counts from the latest of last use, the job's close time and the first sweep
that saw the session gone.

## Commands

```sh
reclaimable mark PATH -o OWNER -r "how it comes back" [-t 24h] [-k KIND] [-j JOB] [-s SESSION] [-m DEST]
reclaimable touch PATH...
reclaimable hold PATH JOB [-p SUBPATH]      # never removed while any hold exists
reclaimable release PATH JOB [-p SUBPATH]
reclaimable ls [ROOTS...] [-j] [-q] [-S]    # -q skips the deep checks
reclaimable sweep [-n | -A] [-f 30GB] [-t 50GB] [-S] [-v]
reclaimable status [-l N]
reclaimable arm [-x]                        # -x disarms
```

Paths are always normalised to absolute lexical paths (symlinks are never resolved,
they are refused) at `mark`, in the registry and at evaluation; a relative path found
in the registry is ignored with a log line, never acted on.

Markers are found by a bounded scan of `roots` (daily, or `-S`) and registered
when created with `mark`. State lives in `~/.local/state/reclaimable/`, the log in
`~/.local/log/reclaimable.log`, the armed flag in `~/.config/reclaimable/armed`.

## Safety model

A folder is removed only if every check passes, and any check that cannot be
completed keeps the folder (fail closed):

1. **Deny-list.** Never removed, even if marked; `mark` refuses them. Built in:
   the root, home, volume roots, `~/Documents` and other broad folders (exact match),
   anything inside a `.git`/`.jj` directory, `~/.ssh`, `~/.gnupg`, `*.photoslibrary`.
   The config can only **add** to the deny-lists.
2. **Holds**: any entry in `holds` keeps the folder.
3. **Live readers**: `lsof +D` (90 s cap) must show nothing open under it.
4. **Holders** (config): external commands and lease directories that can veto a
   folder, see below. Unreadable lease state (an unlistable lease, claim or glob-parent directory,
   or an unparseable file) keeps every folder.
5. **Job-tied data** (`job`): the `job_done` command must report the job closed,
   and the `session` (a pid, or text matched against the process list) must be
   gone. A numeric session is checked exactly; a non-numeric one is only known to
   be alive when found, so a miss keeps the folder as "unknown" unless
   `session_grace` is set (see below), which applies only after a successful
   process-list search found nothing (a failed or missing `pgrep` keeps the folder).
   If `job_done` reports closed without a time, the first time the janitor saw it
   closed (stored in the registry) is used for the grace and the TTL.
6. **Worktrees**: anything with `.git`/`.jj` at its top, and any repo nested inside
   a marked folder (also in `mirror` folders), is refused when dirty or with
   unpushed commits. Primary repositories are never removed, only linked git
   worktrees (then `git worktree prune`) and secondary jj workspaces
   (`jj workspace forget` first).
7. **Symlinks**: a marked folder, or any ancestor of it, that is a symlink is
   refused (at `mark`, at evaluation and at removal); a symlink is never traversed.
   Deny-list paths, including globs, also apply to everything inside a marked folder.
   Nested primary git/jj repositories inside a marked folder keep it too.
8. **Filesystem boundary**: folders containing another mounted filesystem are
   kept, and deletion never crosses a device boundary.

The size walk doubles as the descendant deny check (names, sequences), which
applies to every kind, `mirror` included; a walk that times out or hits an unreadable folder keeps the folder.

Immediately before removal, **under the same lock `hold` takes**, the marker is
re-read (touched or held since evaluation means keep), and the deny-list,
holders, open files, folder identity, a fresh `job_done` answer (the
positive cache is bypassed; open, unknown or error keeps the folder),
the session decision (pid exact; a non-pid session needs a fresh process-list
no-match and an elapsed `session_grace`) and the worktree checks (dirty,
unpushed, primary or nested repos) are re-checked. The TTL clock is recomputed
from the fresh marker mtime, job close time and session state, and a folder
selected for its TTL that is no longer expired (a job reopened and reclosed)
is kept; folders selected because free space is low are exempt. For a **move** the
folder is copied (local, or `rsync` to `host:path`), every file is sha256-verified
against the source, then the checks above run again and the source's content is
re-hashed; a hold, new lease, reader or changed file during the copy keeps the
source. Removal renames the folder aside, then deletes it.

**Dry-run until armed.** Sweeps act only once the host is armed (`reclaimable arm`)
and 24 h have passed. `sweep -n` never acts; `sweep -A` acts immediately but still
requires the armed flag.

**Space floor.** Below the host's floor, safe folders go least-recently-used first,
even before their TTL, until the target. Default floor 30 GB, target floor + 20 GB;
only the home volume has a floor unless `volume_floors` names others.

## Configuration

`~/.config/reclaimable/config.toml` (override the path with `$RECLAIMABLE_CONFIG`).
Everything is optional.

```toml
floor_gb = 30                 # or floor = "30GB" / "50GiB"; default 30 GB
target_gb = 50                # default floor + 20 GB
roots = ["~", "/Volumes/Data"]       # where to scan for markers (default: home + writable volumes)
move_root = "backup:/archive"        # non-cache kinds move here instead of being deleted
volume_floors = { "/Volumes/Data" = "100GB" }

# The deny-list can only grow.
deny = ["~/keep-me", "/Volumes/Archive/*"]    # paths (globs ok): inside, containing, or equal
deny_names = ["golden-*"]                     # component names, on the path or anywhere inside
deny_sequences = [["experiments", "results"]] # consecutive component names
deny_exact = ["~/src"]                        # the folder itself may never be marked

# Non-numeric sessions can't be observed reliably (their id may never appear in a command
# line). Unset (default): a session the process list doesn't show is "unknown" and keeps the
# folder. With a grace, such a session counts as gone only if the job is closed AND now >=
# the job's close time + grace. If job_done prints no close time, the first time the janitor
# saw the job closed is used instead.
# Numeric pids are always checked exactly; a process-list hit always blocks.
session_grace = "72h"

[default_ttls]
cache = "12h"

# Per-host overrides, keyed by the lowercase first label of the hostname.
[hosts.build-box]
floor = "50GiB"
deny = ["~/extra"]            # deny lists extend the top-level ones

# Holders can veto a folder.
[[holder]]
name = "my-scheduler"
command = ["/usr/local/bin/is-in-use", "{path}"]
timeout = 30
# exit 0 = held, 1 = free, anything else (or a timeout / failure to run) = held.
# Placeholders: {path} ({folder}), {owner}, {job}, {session}, {kind};
# the same values are in RECLAIMABLE_PATH, _FOLDER, _OWNER, _JOB, _SESSION, _KIND.
# The first stdout line becomes the reason. {config_dir} is the directory of this file,
# so helper scripts can live beside it. A leading "~/" in an argument is expanded.

[[holder]]
lease_dir = ["~/.local/state/leases", "/home/*/.local/state/leases"]  # paths or globs
claim_dir = "~/.local/state/claims"                                  # optional
# A lease is <lease_dir>/*.json: {"pid": 123, "job": "1234", "log": "/path", "what": ["/path"],
# "claim_id": "abc"}. A lease with a live pid holds the folder if its job (or "issue") equals the
# marker's job, if its log/what mention a path inside or above the folder, or if its process's
# cwd does. claim_id names <claim_dir>/<id>.json ({"state", "cwd", "command", "pid"}); claim
# records in state starting/running hold paths they reference. Unparseable lease or claim files
# keep every folder.

# How to tell that a marker's `job` is finished. Without it, job-tied folders are never removed.
[job_done]
command = ["/usr/local/bin/job-closed", "{job}"]
# exit 0 = closed (first stdout line may be its close time: epoch seconds or 2026-10-01T00:00:00Z),
# 1 = still open, anything else = unknown (kept).

# Optional: write every registered, non-denied marked folder to a file (other tools
# can use it as an exclusion list). Off by default.
exclude_list_path = "~/.local/state/reclaimable/marked-paths.txt"
exclude_list_format = "{path}"       # one line per folder; e.g. "path {path}"

# How remote moves (move_to = "host:path") run commands on the host.
remote_command = ["ssh", "{host}", "{script}"]
```

## Tests

```sh
uv run --no-project --with pytest python -m pytest
```

## License

MIT
