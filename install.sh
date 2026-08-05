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

if is_debian; then
    PKG_NAME="colatrl_${TAG}-1_amd64.deb"
    PKG_URL="https://github.com/${REPO}/releases/download/${TAG}/${PKG_NAME}"
    echo "Downloading ${PKG_NAME}..."
    curl -fsSL --output "${PKG_NAME}" "${PKG_URL}" || die "Failed to download ${PKG_URL}"
    echo ""
    echo "Package downloaded to: ./${PKG_NAME}"
    echo ""
    echo "Run the following commands to install colatrl:"
    echo ""
    echo "  sudo apt-get install -y ./${PKG_NAME}"
    echo "  sudo systemctl enable --now colatrl"
    echo ""
    echo "Note: net.ipv6.conf.all.forwarding will be set to 1 by the service and is not reverted on stop."

elif is_rpm; then
    PKG_NAME="colatrl-${TAG}-1.x86_64.rpm"
    PKG_URL="https://github.com/${REPO}/releases/download/${TAG}/${PKG_NAME}"
    echo "Downloading ${PKG_NAME}..."
    curl -fsSL --output "${PKG_NAME}" "${PKG_URL}" || die "Failed to download ${PKG_URL}"
    echo ""
    echo "Package downloaded to: ./${PKG_NAME}"
    echo ""
    echo "Run the following commands to install colatrl:"
    echo ""
    echo "  sudo dnf install -y ./${PKG_NAME}"
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
    echo "Downloading source tarball ${SRC_NAME}..."
    curl -fsSL --output "${SRC_NAME}" "${SRC_URL}" || die "Failed to download ${SRC_URL}"
    tar -xzf "${SRC_NAME}"
    SRC_DIR="colatrl-${TAG}"
    echo ""
    echo "Source extracted to: ./${SRC_DIR}"
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
fi
