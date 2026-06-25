#!/bin/sh
set -e

REPO="roman-kolpachev/envseal"
INSTALL_DIR="${ENVSEAL_INSTALL_DIR:-/usr/local/bin}"

main() {
    os="$(detect_os)"
    arch="$(detect_arch)"
    version="${ENVSEAL_VERSION:-$(latest_version)}"

    if [ -z "$version" ]; then
        echo "Error: could not determine latest version" >&2
        exit 1
    fi

    # Validate the tag before interpolating it into a URL: it comes from the
    # GitHub API (or user env) and must not contain path separators, whitespace,
    # or shell/terminal metacharacters.
    case "$version" in
        v[0-9]*) ;;
        *)
            echo "Error: unexpected version format: ${version}" >&2
            exit 1
            ;;
    esac
    if printf '%s' "$version" | LC_ALL=C grep -q '[^A-Za-z0-9._-]'; then
        echo "Error: version contains invalid characters" >&2
        exit 1
    fi

    echo "Installing envseal ${version} (${os}/${arch})..."

    ext="tar.gz"
    if [ "$os" = "windows" ]; then
        ext="zip"
    fi

    archive="envseal-${os}-${arch}.${ext}"
    base_url="https://github.com/${REPO}/releases/download/${version}"
    tmpdir="$(mktemp -d)"
    trap 'rm -rf "$tmpdir"' EXIT

    echo "Downloading ${base_url}/${archive}..."
    download "${base_url}/${archive}" "${tmpdir}/${archive}"
    download "${base_url}/checksums.txt" "${tmpdir}/checksums.txt"

    echo "Verifying checksum..."
    verify_checksum "$tmpdir" "$archive"

    cd "$tmpdir"
    if [ "$ext" = "zip" ]; then
        unzip -q "$archive"
    else
        tar xzf "$archive"
    fi

    binary="envseal"
    if [ "$os" = "windows" ]; then
        binary="envseal.exe"
    fi

    if [ ! -f "$binary" ]; then
        echo "Error: binary not found in archive" >&2
        exit 1
    fi

    # Set the executable bit while the binary is still owned by the current
    # user — running chmod after a sudo mv would fail without privileges and
    # abort (set -e) after an otherwise successful install.
    chmod +x "$binary"

    if [ -w "$INSTALL_DIR" ]; then
        mv "$binary" "${INSTALL_DIR}/${binary}"
    else
        echo "Installing to ${INSTALL_DIR} (requires sudo)..."
        sudo mv "$binary" "${INSTALL_DIR}/${binary}"
    fi
    echo "envseal ${version} installed to ${INSTALL_DIR}/${binary}"
}

download() {
    url="$1"
    dest="$2"
    # --proto '=https' / --https-only: refuse plaintext-HTTP even via redirects,
    # so a redirect-downgrade cannot serve an unencrypted (tamperable) binary.
    if command -v curl >/dev/null 2>&1; then
        curl --proto '=https' --tlsv1.2 -fsSL "$url" -o "$dest"
    elif command -v wget >/dev/null 2>&1; then
        wget --https-only -q "$url" -O "$dest"
    else
        echo "Error: curl or wget required" >&2
        exit 1
    fi
}

verify_checksum() {
    dir="$1"
    file="$2"
    cd "$dir"
    # Require an entry for the exact archive we downloaded. Without this,
    # --ignore-missing on a checksums.txt that omits our file could (on some
    # tool versions) verify nothing at all and still exit 0.
    if ! LC_ALL=C grep -q "[ *]${file}\$" checksums.txt; then
        echo "Error: ${file} not found in checksums.txt — refusing to install unverified binary" >&2
        exit 1
    fi
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum --check --ignore-missing checksums.txt
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 --check --ignore-missing checksums.txt
    else
        echo "Error: sha256sum or shasum is required to verify the download but neither was found." >&2
        echo "Install one of them (e.g. 'apt install coreutils' or 'brew install coreutils') and re-run." >&2
        exit 1
    fi
}

detect_os() {
    case "$(uname -s)" in
        Linux*)  echo "linux" ;;
        Darwin*) echo "darwin" ;;
        MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
        *)
            echo "Error: unsupported OS: $(uname -s)" >&2
            exit 1
            ;;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)  echo "amd64" ;;
        arm64|aarch64) echo "arm64" ;;
        *)
            echo "Error: unsupported architecture: $(uname -m)" >&2
            exit 1
            ;;
    esac
}

latest_version() {
    # Same HTTPS-only hardening as download(): refuse plaintext HTTP even
    # via redirects when querying the GitHub API for the latest tag.
    if command -v curl >/dev/null 2>&1; then
        curl --proto '=https' --tlsv1.2 -fsSL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null |
            grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/'
    elif command -v wget >/dev/null 2>&1; then
        wget --https-only -qO- "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null |
            grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/'
    fi
}

main
