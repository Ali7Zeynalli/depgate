#!/bin/sh
# DepGate installer for Linux and macOS.
#
#   curl -fsSL https://raw.githubusercontent.com/Ali7Zeynalli/depgate/main/install.sh | sh
#
# Downloads the release for this system from GitHub, checks its SHA-256 against
# the release's checksums.txt and puts the `depgate` binary in /usr/local/bin
# (when writable) or ~/.local/bin. Nothing else is changed.
#
#   DEPGATE_VERSION=0.21.0   a given version instead of the latest
#   DEPGATE_INSTALL_DIR=DIR  where to put the binary
set -eu

REPO="Ali7Zeynalli/depgate"

say() { printf '%s\n' "$*" >&2; }
die() { say "depgate install: $*"; exit 1; }

if command -v curl >/dev/null 2>&1; then
	get() { curl -fsSL "$1"; }
	save() { curl -fsSL -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
	get() { wget -qO- "$1"; }
	save() { wget -qO "$2" "$1"; }
else
	die "curl or wget is needed"
fi

case "$(uname -s)" in
Linux) os=linux ;;
Darwin) os=darwin ;;
*) die "unsupported system $(uname -s); on Windows use install.ps1" ;;
esac
case "$(uname -m)" in
x86_64 | amd64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
*) die "unsupported CPU $(uname -m)" ;;
esac

version="${DEPGATE_VERSION:-}"
if [ -z "$version" ]; then
	version=$(get "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"v\{0,1\}\([^"]*\)".*/\1/p' | head -n 1)
	[ -n "$version" ] || die "could not find the latest release (GitHub API limit?); set DEPGATE_VERSION"
fi
version="${version#v}"

file="depgate_${version}_${os}_${arch}.tar.gz"
base="https://github.com/$REPO/releases/download/v$version"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

say "Downloading DepGate $version ($os/$arch)…"
save "$base/$file" "$tmp/$file" || die "download failed: $base/$file"
save "$base/checksums.txt" "$tmp/checksums.txt" || die "download failed: checksums.txt"

want=$(grep " $file\$" "$tmp/checksums.txt" | cut -d ' ' -f 1)
[ -n "$want" ] || die "$file is not in checksums.txt"
if command -v sha256sum >/dev/null 2>&1; then
	have=$(sha256sum "$tmp/$file" | cut -d ' ' -f 1)
else
	have=$(shasum -a 256 "$tmp/$file" | cut -d ' ' -f 1)
fi
[ "$want" = "$have" ] || die "checksum mismatch for $file"

tar -xzf "$tmp/$file" -C "$tmp" --no-same-owner depgate

dir="${DEPGATE_INSTALL_DIR:-}"
if [ -z "$dir" ]; then
	if [ -w /usr/local/bin ]; then dir=/usr/local/bin; else dir="$HOME/.local/bin"; fi
fi
mkdir -p "$dir"
mv "$tmp/depgate" "$dir/depgate"
chmod 755 "$dir/depgate"

say "Installed: $dir/depgate"
case ":$PATH:" in
*":$dir:"*) ;;
*) say "Add it to your PATH:  export PATH=\"$dir:\$PATH\"" ;;
esac
say "Start it:  depgate ~/projects"
