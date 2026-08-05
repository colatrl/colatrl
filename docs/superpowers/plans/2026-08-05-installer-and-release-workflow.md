# Installer, Release Workflow, and systemd Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a one-command shell installer, fix the GitHub Actions release workflow to produce and attach `.deb`, `.rpm`, and source tarballs, and fix four systemd/service reliability bugs.

**Architecture:** Five discrete, independently committable changes: (1) state-file tracking in the `colatrl` shell script so `stop` works without DNS64; (2) hardened `colatrl.service`; (3) new `install.sh` that detects OS and prints install instructions; (4) updated `README.md`; (5) updated `.github/workflows/release.yml` with decoupled jobs and source tarball.

**Tech Stack:** bash, systemd, GitHub Actions, debhelper, rpmbuild, softprops/action-gh-release

## Global Constraints

- No `sudo` called inside `install.sh` — print instructions only
- No AI/Claude attribution in any commit message or file
- `install.sh` must pass `shellcheck` (already enforced by `test.yml` lint job for `colatrl`; add `install.sh` to that check)
- x86_64 only for binary packages; unsupported arch must exit 1 with a clear message
- Minimum kernel version: 5.10 (existing requirement, document in README)
- State file path: `/run/colatrl/state`
- GitHub repo slug used in installer: `colatrl/colatrl`

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `colatrl` | Modify | Write state file on start; read state file on stop |
| `debian/colatrl.service` | Modify | Add `Wants=`, `ExecStartPre`, `Restart`, `RestartSec` |
| `install.sh` | Create | OS detection, package download, print install instructions |
| `README.md` | Modify | Quick install section, usability notes, sysctl note |
| `.github/workflows/release.yml` | Modify | Decouple jobs, add source tarball, attach all artifacts |
| `.github/workflows/test.yml` | Modify | Add `shellcheck install.sh` to lint job |

---

## Task 1: Fix `colatrl stop` DNS64 dependency via state file

**Files:**
- Modify: `colatrl`

**Interfaces:**
- Produces: `/run/colatrl/state` written on successful start; read on stop. Format: three lines — `DEV`, `DEV4`, `DEV6`.

- [ ] **Step 1: Understand the current stop path**

Read `colatrl` lines 196–228. Note that `process()` calls `pfx96()` and `gt()` before branching to `cmd_stop`, and that `set -e` will abort if `pfx96()` fails (DNS64 unavailable at shutdown).

- [ ] **Step 2: Add state file write at end of `cmd_start`**

In `colatrl`, after `ping -c 3 "${TEST4}"` and before `return 0` in `cmd_start`, add:

```bash
mkdir -p /run/colatrl
printf '%s\n%s\n%s\n' "${DEV}" "${DEV4}" "${DEV6}" > /run/colatrl/state
```

- [ ] **Step 3: Add state file read at top of `process()` for stop**

In `process()`, add a branch before the existing `pfx96`/`gt` calls so that when `CMD == stop`, the device names come from the state file instead of a live DNS lookup:

```bash
process() {
    declare -r CMD=$1

    if [[ "$CMD" == "" ]]; then
        echo Need start, stop, or status.
        return 1
    fi

    if [[ "$CMD" == "stop" ]]; then
        if [[ -f /run/colatrl/state ]]; then
            mapfile -t _state < /run/colatrl/state
            cmd_stop "${_state[0]}" "${_state[1]}" "${_state[2]}"
            rm -f /run/colatrl/state
        else
            # Fallback: attempt live route lookup (may fail if network is down)
            declare -r PFX96_STOP=$(pfx96)
            declare -r DEV_STOP=$(gt "${PFX96_STOP}" 2)
            declare -r DEV4_STOP=$(get_ipv4_default_route_device || echo unknown)
            declare -r DEV6_STOP=$(get_ipv6_default_route_device)
            cmd_stop "${DEV_STOP}" "${DEV4_STOP}" "${DEV6_STOP}"
        fi
        return 0
    fi

    declare -r PFX96=$(pfx96)
    declare -r DEV=$(gt "${PFX96}" 2)
    declare -r DEV4=$(get_ipv4_default_route_device || echo unknown)
    declare -r DEV6=$(get_ipv6_default_route_device)

    if [[ "$CMD" == "status" ]]; then
        cmd_status "${DEV}" "${DEV4}" "${DEV6}"
        return 0
    fi

    if [[ "$CMD" != "start" ]]; then
        echo Need start, stop, or status.
        return 1
    fi

    cmd_start "${DEV}" "${DEV4}" "${DEV6}"
    return 0
}
```

- [ ] **Step 4: Verify shellcheck passes**

```bash
shellcheck colatrl
```

Expected: no errors or warnings.

- [ ] **Step 5: Commit**

```bash
git add colatrl
git commit -m "fix: read device from state file on stop to avoid DNS64 dependency"
```

---

## Task 2: Harden `debian/colatrl.service`

**Files:**
- Modify: `debian/colatrl.service`

**Interfaces:**
- Consumes: Task 1's state file (`/run/colatrl/state`) — `ExecStartPre=-/usr/sbin/colatrl stop` triggers Task 1's stop path before each start.

- [ ] **Step 1: Replace the service file contents**

```bash
cat > debian/colatrl.service << 'EOF'
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
EOF
```

- [ ] **Step 2: Verify the file is correct**

```bash
cat debian/colatrl.service
```

Expected output matches the block above exactly.

- [ ] **Step 3: Commit**

```bash
git add debian/colatrl.service
git commit -m "fix: harden systemd service (Wants=network-online, ExecStartPre cleanup, Restart=on-failure)"
```

---

## Task 3: Create `install.sh`

**Files:**
- Create: `install.sh`

**Interfaces:**
- Produces: executable shell script; user runs `curl -fsSL https://raw.githubusercontent.com/colatrl/colatrl/main/install.sh | sh`
- Consumes: GitHub releases API at `https://api.github.com/repos/colatrl/colatrl/releases/latest`

- [ ] **Step 1: Create `install.sh`**

```bash
cat > install.sh << 'SCRIPT'
#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -e

REPO="colatrl/colatrl"
GITHUB_API="https://api.github.com/repos/${REPO}/releases/latest"

die() {
    echo "ERROR: $1" >&2
    echo "Visit https://github.com/${REPO}/releases for manual download." >&2
    exit 1
}

# Architecture check
ARCH=$(uname -m)
if [ "${ARCH}" != "x86_64" ]; then
    die "Only x86_64 is supported. Your architecture: ${ARCH}"
fi

# Dependency check
command -v curl >/dev/null 2>&1 || die "curl is required but not installed."

# Fetch latest release tag (no jq dependency)
echo "Fetching latest release information..."
TAG=$(curl -fsSL "${GITHUB_API}" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)
if [ -z "${TAG}" ]; then
    die "Could not determine latest release tag. GitHub API may be rate-limiting this request."
fi
echo "Latest release: ${TAG}"

# OS detection
OS_ID=""
OS_ID_LIKE=""
if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-}"
    OS_ID_LIKE="${ID_LIKE:-}"
fi

is_debian() {
    echo "${OS_ID} ${OS_ID_LIKE}" | grep -qiE '(^| )debian( |$)'
}

is_rpm() {
    echo "${OS_ID} ${OS_ID_LIKE}" | grep -qiE '(^| )(fedora|rhel|centos|rocky|alma)( |$)'
}

# Create temp dir, clean up on exit
TMPDIR=$(mktemp -d)
trap 'rm -rf "${TMPDIR}"' EXIT

if is_debian; then
    PKG_NAME="colatrl_${TAG}_amd64.deb"
    PKG_URL="https://github.com/${REPO}/releases/download/${TAG}/${PKG_NAME}"
    PKG_PATH="${TMPDIR}/${PKG_NAME}"
    echo "Downloading ${PKG_NAME}..."
    curl -fsSL --output "${PKG_PATH}" "${PKG_URL}" || die "Failed to download ${PKG_URL}"
    echo ""
    echo "Package downloaded to: ${PKG_PATH}"
    echo ""
    echo "Run the following commands to install colatrl:"
    echo ""
    echo "  sudo apt-get install -y ${PKG_PATH}"
    echo "  sudo systemctl enable --now colatrl"
    echo ""
    echo "Note: net.ipv6.conf.all.forwarding will be set to 1 by the service and is not reverted on stop."

elif is_rpm; then
    PKG_NAME="colatrl-${TAG}-1.x86_64.rpm"
    PKG_URL="https://github.com/${REPO}/releases/download/${TAG}/${PKG_NAME}"
    PKG_PATH="${TMPDIR}/${PKG_NAME}"
    echo "Downloading ${PKG_NAME}..."
    curl -fsSL --output "${PKG_PATH}" "${PKG_URL}" || die "Failed to download ${PKG_URL}"
    echo ""
    echo "Package downloaded to: ${PKG_PATH}"
    echo ""
    echo "Run the following commands to install colatrl:"
    echo ""
    echo "  sudo dnf install -y ${PKG_PATH}"
    echo "  sudo systemctl enable --now colatrl"
    echo ""
    echo "Note: net.ipv6.conf.all.forwarding will be set to 1 by the service and is not reverted on stop."

else
    echo ""
    echo "WARNING: Unsupported distribution detected (ID=${OS_ID})."
    echo "Source builds on distributions other than Debian/Ubuntu and Fedora/RHEL are"
    echo "untested and may require manual dependency resolution. Proceed with caution."
    echo ""
    SRC_NAME="colatrl-${TAG}.tar.gz"
    SRC_URL="https://github.com/${REPO}/releases/download/${TAG}/${SRC_NAME}"
    SRC_PATH="${TMPDIR}/${SRC_NAME}"
    echo "Downloading source tarball ${SRC_NAME}..."
    curl -fsSL --output "${SRC_PATH}" "${SRC_URL}" || die "Failed to download ${SRC_URL}"
    tar -xzf "${SRC_PATH}" -C "${TMPDIR}"
    SRC_DIR="${TMPDIR}/colatrl-${TAG}"
    echo ""
    echo "Source extracted to: ${SRC_DIR}"
    echo ""
    echo "To build and install from source, run the following commands:"
    echo ""
    echo "  # Debian/Ubuntu build dependencies:"
    echo "  sudo apt-get install -y clang-19 g++ libc6-dev-i386"
    echo ""
    echo "  # Or Fedora/RHEL build dependencies:"
    echo "  sudo dnf install -y clang gcc-c++ glibc-devel.i686 libgcc.i686 bpftool iproute ndisc6 bind-utils"
    echo ""
    echo "  cd ${SRC_DIR}"
    echo "  make"
    echo "  sudo make install"
    echo "  sudo cp debian/colatrl.service /etc/systemd/system/"
    echo "  sudo systemctl daemon-reload"
    echo "  sudo systemctl enable --now colatrl"
    echo ""
    echo "Note: net.ipv6.conf.all.forwarding will be set to 1 by the service and is not reverted on stop."
    echo "Note: The source directory will be removed when this script exits. Copy it first if needed."
fi
SCRIPT
chmod +x install.sh
```

- [ ] **Step 2: Run shellcheck on `install.sh`**

```bash
shellcheck install.sh
```

Expected: no errors or warnings.

- [ ] **Step 3: Smoke-test OS detection logic locally**

```bash
# Simulate debian detection
(ID=ubuntu ID_LIKE=debian . /dev/stdin <<'EOF'
echo "${ID} ${ID_LIKE}" | grep -qiE '(^| )debian( |$)' && echo "debian: OK" || echo "debian: FAIL"
EOF
)

# Simulate fedora detection
(ID=fedora ID_LIKE="" . /dev/stdin <<'EOF'
echo "${ID} ${ID_LIKE}" | grep -qiE '(^| )(fedora|rhel|centos|rocky|alma)( |$)' && echo "rpm: OK" || echo "rpm: FAIL"
EOF
)
```

Expected: both print `OK`.

- [ ] **Step 4: Commit**

```bash
git add install.sh
git commit -m "add: one-command installer script"
```

---

## Task 4: Update `README.md`

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: `install.sh` from Task 3 (references its curl command)

- [ ] **Step 1: Add quick install section at the top of the installation block**

Open `README.md`. The current `## installation` section starts at line 7. Insert a new subsection `### quick install` immediately after the `## installation` heading (before `### from ppa`):

```markdown
### quick install

```
curl -fsSL https://raw.githubusercontent.com/colatrl/colatrl/main/install.sh | sh
```

Detects your distribution, downloads the appropriate package from the [latest release](https://github.com/colatrl/colatrl/releases/latest), and prints the install command to run with `sudo`. Supported: Debian/Ubuntu (`.deb`), Fedora/RHEL (`.rpm`). Other distributions receive a source-build path — see the note below.

> **x86_64 only.** Binary packages are built for x86_64. Other architectures must build from source.
```

- [ ] **Step 2: Add source-build fragility note**

At the end of the `### local` section (after the systemd service install block), add:

```markdown
> **Note:** Source builds on distributions other than Debian/Ubuntu and Fedora/RHEL are untested and may require manual adjustment of build dependencies and compiler flags.
>
> **Note:** The service sets `net.ipv6.conf.all.forwarding=1` on start. This sysctl is not reverted when the service is stopped.
```

- [ ] **Step 3: Verify README renders correctly**

```bash
# Check for broken markdown (basic)
grep -n '```' README.md | awk -F: '{print $1}' | awk 'NR%2==0{print prev"-"$0} {prev=$0}' | head -20
```

Expected: paired line numbers (open/close fences match up).

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: add quick install section and usability notes"
```

---

## Task 5: Update `.github/workflows/test.yml` to lint `install.sh`

**Files:**
- Modify: `.github/workflows/test.yml`

**Interfaces:**
- Consumes: `install.sh` from Task 3

- [ ] **Step 1: Add `install.sh` to the shellcheck step**

In `.github/workflows/test.yml`, find the `shellcheck` step in the `lint` job (currently line ~21):

```yaml
      - name: shellcheck
        run: shellcheck colatrl
```

Change it to:

```yaml
      - name: shellcheck
        run: shellcheck colatrl install.sh
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/test.yml
git commit -m "ci: add install.sh to shellcheck lint"
```

---

## Task 6: Update `.github/workflows/release.yml`

**Files:**
- Modify: `.github/workflows/release.yml`

**Interfaces:**
- Produces: GitHub release with three artifacts: `colatrl_TAG_amd64.deb`, `colatrl-TAG-1.x86_64.rpm`, `colatrl-TAG.tar.gz`
- Consumes: existing `build-release-deb` and `build-release-rpm` jobs (unchanged)

- [ ] **Step 1: Add `build-release-source` job**

In `release.yml`, after the `build-release-rpm` job block and before `create-github-release`, insert:

```yaml
  build-release-source:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0
      - name: build source tarball
        run: |
          VER=$(git describe --tags $(git rev-list --tags --max-count=1))
          git archive --format=tar.gz --prefix=colatrl-${VER}/ HEAD > colatrl-${VER}.tar.gz
      - name: Upload source artifact
        uses: actions/upload-artifact@v7
        with:
          name: source-tarball
          path: "*.tar.gz"
```

- [ ] **Step 2: Update `create-github-release` needs and artifact downloads**

Find the `create-github-release` job. Change its `needs` line from:

```yaml
    needs: [build-release-deb, build-release-rpm]
```

to:

```yaml
    needs: [build-release-deb, build-release-rpm, build-release-source]
```

Add a download step for the source tarball after the existing two download steps:

```yaml
      - name: Download source artifact
        uses: actions/download-artifact@v8
        with:
          name: source-tarball
```

Update the `files` list in the `softprops/action-gh-release` step to include the tarball:

```yaml
          files: |
            *.deb
            *.rpm
            *.tar.gz
```

- [ ] **Step 3: Fix `release` job (PPA push) dependency**

Find the `release` job at the top of the file. Its current `needs` line is:

```yaml
    needs: [create-github-release]
```

Change it to:

```yaml
    needs: [build-release-deb]
```

This decouples the PPA push from the GitHub release creation so they run in parallel after the deb build completes.

- [ ] **Step 4: Verify job dependency graph is correct**

```bash
# Check needs lines in the updated file
grep -n 'needs:' .github/workflows/release.yml
```

Expected output (line numbers will vary):
```
N:    needs: [build-release-deb]
N:    needs: [build-release-deb, build-release-rpm, build-release-source]
```

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci: decouple PPA push, add source tarball, attach all artifacts to release"
```

---

## Self-Review Checklist

- [x] **Spec coverage:**
  - `install.sh` with OS detection, arch check, package download, print-instructions-only: Task 3 ✓
  - Unsupported distro source-build path: Task 3 ✓
  - `Wants=network-online.target`: Task 2 ✓
  - `ExecStartPre=-/usr/sbin/colatrl stop`: Task 2 ✓
  - `Restart=on-failure` + `RestartSec=5s`: Task 2 ✓
  - State file for stop-without-DNS64: Task 1 ✓
  - Sysctl documentation: Task 4 ✓
  - Source tarball in release: Task 6 ✓
  - Decoupled PPA push: Task 6 ✓
  - All three artifacts attached to GitHub release: Task 6 ✓
  - `shellcheck install.sh` in CI: Task 5 ✓
  - README quick install section: Task 4 ✓
  - x86_64-only note in README: Task 4 ✓

- [x] **No placeholders:** All steps contain concrete code, commands, and expected output.

- [x] **Type/name consistency:** `cmd_stop`, `cmd_start`, `process()`, `/run/colatrl/state` used consistently across Tasks 1 and 2. `source-tarball` artifact name consistent between Task 6 Steps 1 and 2.

- [x] **Task ordering:** Tasks 1 and 2 are independent of each other but both should land before a release. Task 3 (`install.sh`) is independent. Task 5 depends on Task 3 (references `install.sh`). Task 6 is independent of Tasks 1–5 (workflow changes).
