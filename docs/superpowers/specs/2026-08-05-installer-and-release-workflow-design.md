# Design: One-Command Installer and Release Workflow Improvements

Date: 2026-08-05

## Overview

Add an `install.sh` shell script that lets users get colatrl with a single `curl | sh` command, and fix the GitHub Actions release workflow to decouple the PPA push from the GitHub release, add a source tarball artifact, and attach all three package types (`.deb`, `.rpm`, `.tar.gz`) to every GitHub release.

## Goals

- Users on Debian/Ubuntu and Fedora/RHEL can fetch and install colatrl in two commands: one to download the package, one to install it with explicit `sudo`
- Users on unsupported distros get clear source-build instructions
- GitHub releases consistently publish all three artifact types
- The PPA push and the GitHub release do not block each other

## Non-Goals

- Cross-architecture builds (only `x86_64` is currently supported by the BPF compilation toolchain)
- Automatic privilege escalation inside the installer
- Package managers beyond `.deb` and `.rpm` (no Homebrew, pacman, etc.)

---

## Component 1: `install.sh`

### Location

`install.sh` at the repository root. Referenced in the README as:

```
curl -fsSL https://raw.githubusercontent.com/colatrl/colatrl/main/install.sh | sh
```

### Flow

1. **Architecture check** — `uname -m`. If not `x86_64`, print an error explaining that only x86_64 is supported and exit 1.

2. **OS detection** — source `/etc/os-release`. Check `$ID` and `$ID_LIKE` to classify:
   - `debian` family: Ubuntu, Debian (ID or ID_LIKE contains `debian`)
   - `rpm` family: Fedora, RHEL, CentOS, Rocky, AlmaLinux (ID_LIKE contains `fedora` or `rhel`)
   - anything else: `unsupported`

3. **Fetch latest release tag** — `curl -fsSL https://api.github.com/repos/colatrl/colatrl/releases/latest | grep '"tag_name"'` to extract the version string. No hardcoded version in the script.

4. **Download package to temp dir** — `mktemp -d` with a `trap ... EXIT` to clean up. Download URL is constructed from the release tag:
   - Debian: `https://github.com/colatrl/colatrl/releases/download/TAG/colatrl_TAG_amd64.deb`
   - RPM: `https://github.com/colatrl/colatrl/releases/download/TAG/colatrl-TAG-1.x86_64.rpm`

5. **Print install instructions** — the script does NOT call sudo. It prints the exact commands:

   Debian/Ubuntu:
   ```
   sudo apt-get install -y /path/to/colatrl_VERSION_amd64.deb
   sudo systemctl enable --now colatrl
   ```

   Fedora/RHEL:
   ```
   sudo dnf install -y /path/to/colatrl-VERSION-1.x86_64.rpm
   sudo systemctl enable --now colatrl
   ```

6. **Unsupported distro path** — fetches the source tarball (`colatrl-TAG.tar.gz`) from the release, extracts to the temp dir, and prints build-from-source instructions. Includes a clear warning that source builds on unsupported distros are untested and may require manual dependency resolution.

### Error handling

- Missing `curl`: print message, exit 1
- GitHub API failure (rate limit, network): print message with direct link to releases page, exit 1
- Download failure: print message, exit 1
- Unsupported arch: print message, exit 1

### README update

Add a new top-level install section above the existing sections:

```
## quick install

curl -fsSL https://raw.githubusercontent.com/colatrl/colatrl/main/install.sh | sh
```

Add a note under the source-build section that source builds on distros other than Ubuntu/Debian and Fedora/RHEL are unsupported and may require manual adjustment of build dependencies.

---

## Component 2: Release Workflow Fixes

### Current problems

1. The `release` job (PPA push) depends on `create-github-release`, which itself depends on the build jobs. This creates unnecessary serialization: the PPA push cannot start until the GitHub release is created.
2. No source tarball is produced or attached to releases.
3. The `create-github-release` job dependency list does not include a source tarball job.

### Job dependency graph (new)

```
build-release-deb  ──┐
build-release-rpm  ──┼──> create-github-release
build-release-source ─┘

build-release-deb  ──> release  (PPA push, independent of create-github-release)
```

### New job: `build-release-source`

- Runs on `ubuntu-latest`
- Checks out the repo
- Extracts the version tag from `git describe`
- Runs `git archive --format=tar.gz --prefix=colatrl-VERSION/ HEAD > colatrl-VERSION.tar.gz`
- Uploads as artifact `source-tarball`

### Updated `create-github-release`

- `needs: [build-release-deb, build-release-rpm, build-release-source]`
- Downloads all three artifacts before creating the release
- Passes `*.deb`, `*.rpm`, and `*.tar.gz` to `softprops/action-gh-release`

### Updated `release` job (PPA push)

- `needs: [build-release-deb]` only — no longer waits on `create-github-release`
- Behavior otherwise unchanged

---

## README Usability Notes

Beyond the installer, the following small README improvements are in scope:

- Move "quick install" to the top of the installation section
- Note x86_64-only limitation explicitly
- Note that source builds on non-Debian/Fedora distros are unsupported (fragile)
- Clarify the systemd enable step is required for the service to start on boot

---

---

## Component 3: systemd Service Reliability Fixes

### Issue 1: Missing `Wants=network-online.target`

`After=network-online.target` only sets ordering — it does not pull `network-online.target` into the dependency graph. If nothing else requires that target, colatrl can start before the network is ready.

**Fix:** Add `Wants=network-online.target` alongside the existing `After=`.

### Issue 2: `stop` fails when DNS64 is unavailable (bug)

`process()` in `colatrl` calls `pfx96()` — a live DNS64 lookup via `host ipv4only.arpa` — unconditionally before branching to `cmd_stop`. With `set -e` active, if DNS64 is unreachable at shutdown time (network torn down, interface removed), the script exits before `cmd_stop` runs, leaving BPF tc filters, qdiscs, and IP state loaded in the kernel. This makes `systemctl stop colatrl` unreliable during system shutdown or network reconfiguration.

**Fix:** When `CMD == stop`, skip the `pfx96`/route-lookup block. Instead, write the device name (DEV, DEV4, DEV6) to a state file (e.g. `/run/colatrl/state`) on successful start, and read it back on stop. `cmd_stop` does not need the prefix — it only needs the device names.

### Issue 3: No restart on transient failure

If the BPF programs are detached or the start script fails transiently, systemd marks the unit failed and leaves it down. For a service that provides IPv4 connectivity on an IPv6-only network, this is a hard outage.

**Fix:** Add `Restart=on-failure` and `RestartSec=5s` to the `[Service]` section.

### Issue 4: Partial start state not cleaned up before retry

If `cmd_start` fails after `tc qdisc add dev ... clsact` but before completion, the qdisc and BPF filters remain loaded. A subsequent start attempt fails immediately on `tc qdisc add` (already exists). This makes the service non-recoverable without manual cleanup.

**Fix:** Add `ExecStartPre=-/usr/sbin/colatrl stop` to the service file. The `-` prefix means systemd ignores a non-zero exit (expected when there is nothing to clean up).

### Issue 5: `sysctl forwarding` not restored (documentation)

`sysctl -w net.ipv6.conf.all.forwarding=1` is set on start and never reverted on stop. This is likely intentional but should be documented in the README.

### Updated `colatrl.service`

```ini
[Unit]
Description=colatrl
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=-/usr/sbin/colatrl stop
ExecStart=/usr/sbin/colatrl start
ExecStop=/usr/sbin/colatrl stop
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

### State file for device tracking

On successful start, `colatrl` writes:

```
/run/colatrl/state
```

Contents: three lines — `DEV`, `DEV4`, `DEV6`. The `cmd_stop` path reads this file when invoked without a prior route-lookup context. If the file does not exist, `cmd_stop` falls back to the current route-lookup behavior (best-effort).

---

## Files Changed

| File | Change |
|------|--------|
| `install.sh` | New file |
| `README.md` | Add quick install section, usability notes, forwarding sysctl note |
| `.github/workflows/release.yml` | Fix job deps, add source tarball job, update release artifact list |
| `debian/colatrl.service` | Add `Wants=`, `ExecStartPre`, `Restart=on-failure`, `RestartSec` |
| `colatrl` | Write state file on start; read state file on stop to avoid DNS64 dependency |
