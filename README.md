# reclaimable

Cleanup usually happens only when the tool that made a cache runs, so disk space
isn't freed when something else needs it, and nobody knows what is safe to delete.
`reclaimable` flips that: anything regenerable gets a `.reclaimable` marker in the
folder it governs, and one janitor per host (`reclaimable sweep`, run hourly from
launchd/cron/systemd) removes or moves expired folders and frees space
least-recently-used first when a disk runs low. It only touches folders that pass
every safety check, and folder cleanup does nothing until you arm the host.

Single Go executable for macOS/Linux (amd64/arm64), Go 1.22+. Library dependencies are pinned and vendored:
`github.com/BurntSushi/toml` v1.4.0 and `golang.org/x/text` v0.22.0.

```sh
go build                       # produces ./reclaimable
mkdir -p ~/.local/bin
install -m 755 ./reclaimable ~/.local/bin/reclaimable
reclaimable mark ~/proj/.cache -o mytool -r "mytool build recreates it" -t 3d
reclaimable ls                  # age, size, TTL, eligibility and why
reclaimable sweep -n            # dry run
reclaimable arm                 # real sweeps begin 24 h later
```

## Install

With Go 1.22+:

```sh
go install github.com/phillco/reclaimable@latest
```

Prebuilt archives for macOS and Linux (arm64/amd64) are on the
[Releases page](https://github.com/phillco/reclaimable/releases). Each contains the
executable, README and project/dependency licenses. For example, set the release tag and target below,
download with the [GitHub CLI](https://cli.github.com/), then verify before extracting:

```sh
version=v0.1.0  # replace with the desired release tag
os=darwin      # darwin or linux
arch=arm64     # arm64 or amd64
archive="reclaimable_${version}_${os}_${arch}.tar.gz"
gh release download "$version" --repo phillco/reclaimable \
  --pattern "$archive" --pattern checksums.txt &&
awk -v archive="$archive" '$2 == archive' checksums.txt | shasum -a 256 -c - &&
gh attestation verify "$archive" --repo phillco/reclaimable &&
tar -xzf "$archive" &&
./reclaimable --version
```

The checksum checks download integrity; [attestation verification](https://cli.github.com/manual/gh_attestation_verify)
checks that the archive was built by this repository's GitHub Actions workflow.
Move the verified executable to a directory on your `PATH`.

macOS binaries are not signed or notarized; browser downloads need
`xattr -d com.apple.quarantine reclaimable` after extraction (curl/gh downloads do not).

## Marker

`PATH/.reclaimable` is a JSON file:

```json
{"owner": "mytool", "ttl": "3d", "regenerate": "mytool build recreates it",
 "kind": "mirror", "job": "1234", "session": "4242", "move_to": "backup:~/parked",
 "ignored_ok": true,
 "holds": [{"job": "indexer", "path": "sub/dir", "at": 1762000000}]}
```

`owner` and `regenerate` are required (a marker without a non-empty string for each
is invalid and the folder is kept); `ignored_ok` is optional (see Safety model). `kind` is `cache` (default), `scratch`,
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
reclaimable maintenance [-n] [-o NAME | --only NAME] [-f | --force-due]
reclaimable status [-l N]
reclaimable arm [-x]                        # -x disarms
```

Paths are always normalised to absolute lexical paths (symlinks are never resolved,
they are refused) at `mark`, in the registry and at evaluation; a relative path found
in the registry is ignored with a log line, never acted on.

Markers are found by a depth-limited scan of `roots` (daily, or `-S`) and registered
when created with `mark`. State lives in `~/.local/state/reclaimable/`, the log in
`~/.local/log/reclaimable.log`, the armed flag in `~/.config/reclaimable/armed`.

Without explicit `roots`, discovery scans only the home directory. To scan an
external volume, add its path to `roots`, for example
`roots = ["~", "/Volumes/Work"]`. Volume discovery is never automatic.

The marker walk checks a 120-second budget between filesystem operations and
stops at eight directory levels. That budget cannot interrupt a blocked open,
stat, or directory read, including a privacy prompt deeper inside a selected
root. Configured roots are scanned directly.
For unattended sweeps, set `roots` to responsive directories the binary can
access; avoid unavailable mounts and grant any required privacy permissions.

## Safety model

A folder is removed only if every check passes, and any check that cannot be
completed keeps the folder (fail closed):

1. **Deny-list.** Never removed, even if marked; `mark` refuses them. Built in:
   the root, home, volume roots, `~/Documents` and other broad folders (exact match),
   anything inside a `.git`/`.jj` directory, `~/.ssh`, `~/.gnupg`, `*.photoslibrary`.
   The config can only **add** to the deny-lists.
   Matching is conservative: names and paths are compared case-folded and
   Unicode-normalised (case variants and NFC/NFD spellings are the same), the macOS
   `/System/Volumes/Data` firmlink prefix is removed component by component from
   every path and pattern, including mixed-case and Unicode-equivalent spellings.
   Safety comparisons use the same absolute canonical form; filesystem operations
   and content inventories retain their original names. Protected
   paths and their ancestors are also compared by filesystem identity (device and
   inode), including glob matches and descendants found while walking a marked
   folder. Glob expansion compares every component case-folded and normalised;
   unreadable glob directories keep the folder. This
   over-protects on case-sensitive volumes on purpose.
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
7. **Ignored files.** A checkout (and any nested linked worktree) holding files its
   ignore rules hide is kept ("contains ignored files; marker lacks ignored_ok"),
   because clean/pushed says nothing about them. The owner attests they are
   regenerable with `"ignored_ok": true` in the marker.
   An independently marked nested checkout uses its own attestation; an outer
   marker cannot override it. Unmarked nested checkouts inherit the nearest
   containing marker's explicit attestation.
8. **Symlinks**: a marked folder, or any ancestor of it, that is a symlink is
   refused (at `mark`, at evaluation and at removal); a symlink is never traversed.
   Deny-list paths, including globs, also apply to everything inside a marked folder.
   Nested primary git/jj repositories inside a marked folder keep it too.
9. **Filesystem boundary**: folders containing another mounted filesystem are
   kept, and deletion never crosses a device boundary.
10. **Descriptor-relative operations**: tree walks, marker reads, copying and
    recursive deletion open entries relative to directory descriptors without
    following symlinks. Unsupported file types and incomplete checks keep the
    source. Removal never traverses symlinks or crosses a device boundary.
11. **Nested markers**: a marker at any depth protects its ancestor unless its
    own holds, TTL, deny-list, holders and checkout checks permit removal. Marker
    names are recognised case-folded; malformed, unreadable, symlink or non-file
    markers keep the ancestor. Nested job/session markers and requested moves
    require independent removal. Space pressure never overrides a nested TTL.

The size walk doubles as the descendant deny check (names, sequences), which
applies to every kind, `mirror` included; a walk that times out or hits an unreadable folder keeps the folder.

Immediately before removal, **under the same lock `hold` takes**, the marker is
re-read (touched or held since evaluation means keep), and the deny-list,
holders, open files, a fresh `job_done` answer (the
positive cache is bypassed; open, unknown or error keeps the folder),
the session decision (pid exact; a non-pid session needs a fresh process-list
no-match and an elapsed `session_grace`) and the worktree checks (dirty,
unpushed, primary or nested repos), including every nested marker's independent
protections, are re-checked. The TTL clock is recomputed
from the fresh marker mtime, job close time and session state, and a folder
selected for its TTL that is no longer expired (a job reopened and reclosed)
is kept; folders selected because free space is low are exempt. For a **move** the
folder is read through directory descriptors, copied
locally or streamed to `host:path`, and every file is sha256-verified
against the source, then the checks above run again and the source's content is
re-hashed; a hold, new lease, reader or changed file during the copy keeps the
source. Destinations must be new; creation refuses symlink ancestors and existing
files. Moves refuse extended attributes and resource forks that the byte-copy
protocol cannot preserve and verify (automatically attached system provenance is
excluded). Remote moves require Python 3 on the destination host; the archive receiver
and hash verifier use the same descriptor-relative protections. A failed copy may
leave a partial destination for inspection, while retaining the source.
Removal uses descriptor-relative deletion. The safety model assumes trusted
jobs owned by one user: holds and open-file checks protect active work, while
hostile concurrent renames and entry replacement are outside its scope.

**Dry-run until armed.** Folder sweeps act only once the host is armed (`reclaimable arm`)
and 24 h have passed. `sweep -n` never acts; `sweep -A` acts immediately but still
requires the armed flag. `maintenance_only = true` keeps folder removals dry-run
even with an armed flag or `sweep -A`, while permitting opted-in native hooks.

**Space floor.** Below the host's floor, safe folders go least-recently-used first,
even before their TTL, until the target. Default floor 30 GB, target floor + 20 GB;
only the home volume has a floor unless `volume_floors` names others.
Sizes count each hardlinked file once. The floor plan is an estimate: when armed,
the sweep re-measures real free space before every pressure removal and stops at
the target. An optimistic size estimate cannot stop an armed sweep early; later
safe candidates remain in LRU order until measured free space reaches the target.

## Configuration

`~/.config/reclaimable/config.toml` (override the path with `$RECLAIMABLE_CONFIG`).
Everything is optional.

```toml
floor_gb = 30                 # or floor = "30GB" / "50GiB"; default 30 GB
target_gb = 50                # default floor + 20 GB
roots = ["~", "/Volumes/Data"]       # where to scan for markers (default: home only)
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

## Scheduled native cache maintenance (Go only)

The hourly `sweep` can also run a configured list of native cleanup commands,
after folder removals and under the same sweep lock. No separate scheduler is
needed for each tool. `maintenance` inspects or runs the same hooks without a
marker scan or folder removal:

```sh
reclaimable maintenance -n
reclaimable maintenance --only uv --force-due
```

Hooks require the explicit config opt-in `maintenance_armed = true`. By default,
they also require a valid host armed state past its 24-hour grace. Setting
`maintenance_only = true` allows hooks without arming folder removal or waiting
for that grace; folder removals stay dry-run even if the host is armed or
`sweep -A` is used. Otherwise hooks report a dry run.
`sweep -n` and `maintenance -n` never run cleanup commands. `sweep -A` does not
bypass maintenance's grace period. `--force-due` ignores only cadence; it does not
bypass arming, free-space triggers, busy holders or in-use checks.

The config's argv arrays are the allow-list: commands are never read from markers
or other data files, substituted with marker values, or passed through a shell.
Each hook executable must be a bare name or an absolute path. In executable
names, `{config_dir}` expands to the config file's directory before validation,
so `command = ["{config_dir}/helper"]` works for hooks and busy holders. No other
executable placeholder is expanded during validation; configured relative paths
containing `/` (including `./tool` and `~/bin/tool`) are config errors.
Bare names are resolved through the current PATH once per attempt and pinned to
an absolute path before execution, so the hook's home working directory cannot
change which executable runs. Executables must resolve to regular executable
files, including when symlinks are used; directories and symlinks to directories
are refused. The same resolution and file checks apply to maintenance's `lsof`,
`pgrep` and busy-holder commands; referenced busy holders also reject configured
relative executable paths. Missing or invalid executables are logged and the hook
is skipped. Configure only trusted native commands and arguments.
Native tools own their cleanup policy; marker TTL/deny checks do not govern what
a configured native tool removes.

Add entries like these to `config.toml` (all opt out by default), or adapt
[config.example.toml](config.example.toml):

```toml
maintenance_armed = false  # top-level; true is a separate explicit opt-in
maintenance_only = false   # top-level; true keeps folder removals dry-run
busy_holders = ["scheduler"]  # all maintenance hooks must pass this check

[[maintenance]]
name = "uv"
command = ["uv", "cache", "prune"]
every = "24h"
when_free_below = "80GB"  # optional; free space on the home volume, strictly below
timeout = "20m"          # optional; default 20m, must be a positive duration
# No in_use: uv cache prune takes uv's own cache lock.

[[maintenance]]
name = "npm"
command = ["npm", "cache", "verify"]
every = "24h"
in_use = { lsof = ["~/.npm"], processes = ["npm"] }

[[maintenance]]
name = "pnpm"
command = ["pnpm", "store", "prune"]
every = "24h"
in_use = { processes = ["pnpm"] }

[[maintenance]]
name = "brew"
command = ["brew", "cleanup"]
every = "7d"
# No in_use: brew cleanup uses its own locking.

[[maintenance]]
name = "docker-dangling"
command = ["docker", "image", "prune", "-f", "--filter", "dangling=true"]
every = "24h"
in_use = { processes = ["docker"] }

[[holder]]
name = "scheduler"
command = ["/usr/local/bin/cleanup-busy"]
timeout = 30             # holder timeouts are seconds
# exit 0 = busy, 1 = idle; all other results/errors/timeouts skip cleanup

[hosts.worker]
maintenance_armed = false
maintenance_only = true  # overrides the global value; still requires maintenance_armed
maintenance = []         # replaces the global list; [] disables all hooks here
```

Host sections may override `maintenance_armed`, `maintenance_only` and replace the entire
`maintenance` list, using `[[hosts.worker.maintenance]]` for host entries. Names
must be unique within the effective host list. Cache locations vary by tool and
host; declare checks only where the tool needs them. The Docker example
prunes dangling images only; it does not prune containers, volumes or all unused
images. No example command is executed by installing or building this tool.

`in_use` is optional; omitting it runs no lockfile, lsof or process probes.
Tools with their own cache locking, such as `uv cache prune` and `brew cleanup`,
should omit process-name checks and rely on their native locks. A long-running
`uv` process is common on development machines and does not mean its cache is
unavailable for pruning. For tools that need external checks, for example:

```toml
in_use = { lockfiles = ["~/.cache/mytool/cleanup.lock"], lsof = ["~/.cache/mytool"], processes = ["mytool"] }
```

Any declared lockfile's existence (including a stale file or dangling symlink)
skips cleanup. An error checking a lockfile also skips it. `lsof +D` must return
an unambiguous no-match for each existing declared directory, and `pgrep -x` must
report no process with the exact declared name. Missing probes, unreadable paths,
warnings, failures and timeouts skip the hook. These checks are snapshots; native
tools must still implement their own concurrency protection.
`maintenance_only` changes only arming policy; busy holders, declared in-use
checks, cadence, free-space triggers and timeouts still apply.

`busy_holders` references uniquely named command `[[holder]]` entries. A top-level
list applies to every hook; a hook's own list adds checks. Host sections can
replace the top-level list. Each referenced command is
checked immediately before an eligible attempt; only exit 1 permits cleanup.
For these checks the holder's path/folder is home, owner is the hook name, kind is
`cache`, and job/session are empty. Existing folder-holder behavior is unchanged.

Attempts, including failed/timed-out attempts, consume cadence. Their start times
and outcomes live in `maintenance.json` in the state directory; skipped and dry
runs do not consume cadence. Malformed/unreadable state prevents execution. Each
timeout kills the command's process group, and remaining group members are killed
when the command returns. Hook outcomes go to the existing log and the
`maintenance` array in `last-sweep.json`, including elapsed seconds, exit status,
timeout status, home-volume free bytes before/after and their signed difference
in bytes and decimal GB. Other disk activity can affect that measured difference.
A manual run updates that array while preserving the prior folder-sweep report.
A command failure returns a nonzero exit; skipped hooks return success.

## Build and tests

```sh
go build                       # uses vendor/, no network needed
go test ./...                  # parity requires Python 3.11+
go vet ./...
gofmt -l *.go
(cd python && uv run --no-project --with pytest python -m pytest)
uv run --no-project --with pytest python -m pytest python/upstream/tests
```

Copy `completions/reclaimable.fish` into a Fish completion directory. The binary
name, subcommands and flags remain `reclaimable`.

The original Python reference and 75 cases remain unchanged under `python/`.
The separate `python/upstream/` snapshot includes later reviewed safeguards and
183 cases. `PORT-NOTES.md` maps every Python test function to Go. Tests use temporary
trees/homes/state for destructive scenarios, and local shims for remote protocols.
Parity compares outputs, exits and resulting state; only fixture roots, clocks
and free-space measurements are normalized.

## Differences from the Python version

- Help layout, parser/OS/JSON diagnostics, JSON key order and escaping differ.
  Flags, TOML keys, marker/state schemas and ordinary command exits are compatible.
- Unicode comparison uses x/text's Unicode 15.0.0 NFKC and case-fold data; newer Unicode characters can compare differently from Python.
- Malformed lease/claim objects and holder-directory settings keep data instead
  of raising exceptions. Size overflow is rejected; invalid/nonfinite arming times
  and descendant stat failures keep data. Moves verify copied contents and re-hash
  the source before deletion. Timeouts also bound process groups/pipes.
- Descriptor operations support macOS/Linux on amd64/arm64. Other architectures
  keep data. Linux symlink metadata inspection needs procfs; unavailable inspection
  keeps the source. No native copy utility is required.
- Local copies retain full mode bits/macOS flags beyond the updated Python copy's
  ordinary permission bits. Both refuse unverifiable extended payloads, including
  resource forks, except system provenance.
- Remote export streams verified TAR without staging a full local archive; Python
  first builds a private snapshot tree. Both use descriptor-relative receivers
  and JSON inventories; malformed/duplicate inventories are refused.
- The unreadable-claim test isolates claims from an earlier live lease, fixing a
  masking assertion while preserving its intended scenario.

Local runtime needs no Python. External `lsof`, `pgrep`, `git` and `jj` retain
their existing roles; remote endpoints need Python 3 and the configured remote
command. Building, installing and running tests do not arm the real host.

## License

MIT; vendored dependencies retain their included licenses.
