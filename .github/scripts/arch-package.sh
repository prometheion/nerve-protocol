#!/usr/bin/env bash
# The Linux desktop app as an Arch Linux package (#230), from the release's
# own program: `arch-package.sh <nerve> <folder>` writes
# nerve-<version>-1-x86_64.pkg.tar.zst into the folder. makepkg packs
# packaging/arch/PKGBUILD with the program as its source, its version the one
# the program says and its checksum the program's. makepkg refuses root, so
# as root (the release's archlinux container) it runs as a user of its own.
set -euo pipefail

bin=$(realpath "$1")
out=$(realpath -m "$2")
said=$("$bin" --version)
version=${said#nerve }
if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "$bin says '$said', not 'nerve x.y.z'" >&2
  exit 1
fi
here=$(dirname "$(realpath "$0")")/../../packaging/arch
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp "$here/PKGBUILD" "$here/nerve.install" "$work/"
cp "$bin" "$work/nerve-x86_64-linux"
sum=$(sha256sum "$bin" | cut -d' ' -f1)
sed -i -e "s/^pkgver=.*/pkgver=$version/" \
  -e "s/^sha256sums=.*/sha256sums=('$sum')/" "$work/PKGBUILD"
if [ "$(id -u)" = 0 ]; then
  id nerve-build > /dev/null 2>&1 || useradd --create-home nerve-build
  chown -R nerve-build "$work"
  (cd "$work" && runuser -u nerve-build -- makepkg --nodeps --noconfirm)
else
  (cd "$work" && makepkg --nodeps --noconfirm)
fi
mkdir -p "$out"
cp "$work/nerve-$version-1-x86_64.pkg.tar.zst" "$out/"
ls -l "$out"
