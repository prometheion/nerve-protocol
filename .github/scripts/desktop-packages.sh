#!/usr/bin/env bash
# The Linux desktop app as a .deb and an .rpm (#212), from the release's own
# program: `desktop-packages.sh <nerve> <folder>` writes
# nerve_<version>_amd64.deb and
# nerve-<version>.x86_64.rpm into the folder. The program puts
# the packages' files in place itself (`__package-root`: the program in
# /usr/bin, its menu entry and icon, the mark of the package's kind), and
# dpkg-deb and rpmbuild pack them; the version is the one the program says.
#
# Once installed, the package's script brings an installed node to the new
# program: the update with the program in place writes the service's files
# and restarts it. A package that `nerve update` installs
# itself leaves that to the update (NERVE_PACKAGE_UPDATE).
set -euo pipefail

bin=$(realpath "$1")
out=$(realpath -m "$2")
said=$("$bin" --version)
version=${said#nerve }
if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "$bin says '$said', not 'nerve x.y.z'" >&2
  exit 1
fi
mkdir -p "$out"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

summary="Nerve, the app for a node or a center"
description="One app for this machine's role in Nerve: a node, which decides
what your centers may do here, or a center, which your agent's harness
reaches; its window, and the node's command line."
homepage="https://github.com/prometheion/nerve-protocol"
after_install='if [ -z "${NERVE_PACKAGE_UPDATE:-}" ] && [ -f /etc/systemd/system/nerve-node.service ]; then
  /usr/bin/nerve update --from=/usr/bin/nerve \
    || echo "nerve: the node still runs the earlier program; the app'"'"'s Update tries again" >&2
fi'

# The .deb: glibc 2.35 or newer and fontconfig, which the program links. It
# takes the place of the package of the pre-releases, nerve-node-desktop.
deb="$work/deb"
"$bin" __package-root "$deb" deb > /dev/null
mkdir -p "$deb/DEBIAN"
size=$(du -sk "$deb" | cut -f1)
cat > "$deb/DEBIAN/control" << CONTROL
Package: nerve
Version: $version
Architecture: amd64
Maintainer: Nerve Protocol <$homepage>
Installed-Size: $size
Depends: libc6 (>= 2.35), libfontconfig1
Replaces: nerve-node-desktop
Conflicts: nerve-node-desktop
Section: admin
Priority: optional
Homepage: $homepage
Description: $summary
$(sed 's/^/ /' <<< "$description")
CONTROL
cat > "$deb/DEBIAN/postinst" << SCRIPT
#!/bin/sh
set -e
if [ "\$1" = configure ]; then
$after_install
fi
exit 0
SCRIPT
chmod 0755 "$deb/DEBIAN/postinst"
dpkg-deb -Zxz --root-owner-group --build "$deb" "$out/nerve_${version}_amd64.deb"

# The .rpm, with the same files and dependencies.
rpmroot="$work/rpmroot"
"$bin" __package-root "$rpmroot" rpm > /dev/null
mkdir -p "$work/rpmbuild/SPECS"
cat > "$work/rpmbuild/SPECS/nerve.spec" << SPEC
Name: nerve
Version: $version
Release: 1
Summary: $summary
License: Apache-2.0 AND LicenseRef-Slint-Royalty-free-2.0
URL: $homepage
Requires: glibc >= 2.35
Requires: fontconfig
Obsoletes: nerve-node-desktop
Conflicts: nerve-node-desktop
AutoReqProv: no
%global debug_package %{nil}
%global __strip /bin/true
%global _build_id_links none
%global source_date_epoch_from_changelog 0

%description
$description

%install
cp -a "$rpmroot"/. %{buildroot}/

%post
$after_install

%files
/usr/bin/nerve
/usr/share/applications/nerve.desktop
/usr/share/icons/hicolor/scalable/apps/nerve.svg
%dir /usr/share/nerve
/usr/share/nerve/package
SPEC
rpmbuild -bb --quiet --target x86_64 --define "_topdir $work/rpmbuild" \
  "$work/rpmbuild/SPECS/nerve.spec"
mv "$work/rpmbuild/RPMS/x86_64/nerve-$version-1.x86_64.rpm" \
  "$out/nerve-$version.x86_64.rpm"
ls -l "$out"
