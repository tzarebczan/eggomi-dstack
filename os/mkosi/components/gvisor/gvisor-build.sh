#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# gVisor's runsc and the sentry sidecars it needs beside it in gvisor-bin/,
# from gVisor's release bundle, at /usr/lib/eggomi/gvisor. Only the pinned
# files are taken, each checked against its SHA-512 after the bundle's own.
# Nothing in the image runs them: Eggomi's measured init script registers
# them with dockerd when they match the SHA-512s its compose pins, and
# fetches the bundle otherwise.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
# shellcheck source=/dev/null
source "$ROOT/os/mkosi/versions.env"
BUILD_DIR=$(realpath -m "${1:?build directory required}")
STAGE=$(realpath -m "${2:?rootfs staging tree required}")
DEST="$STAGE/usr/lib/eggomi/gvisor"

url="https://storage.googleapis.com/gvisor/releases/release/$GVISOR_RELEASE/x86_64/gvisor.tar.bz2"
bundle="$BUILD_DIR/downloads/gvisor-$GVISOR_RELEASE.tar.bz2"
mkdir -p "$BUILD_DIR/downloads"
[[ -f $bundle ]] || { curl -fL --retry 3 -o "$bundle.tmp" "$url"; mv "$bundle.tmp" "$bundle"; }
echo "$GVISOR_BUNDLE_SHA512  $bundle" | sha512sum -c --status || {
  echo "checksum mismatch: $bundle" >&2; exit 1;
}

pins="$BUILD_DIR/SHA512SUMS"
cat > "$pins" <<PINS
$GVISOR_RUNSC_SHA512  runsc
$GVISOR_SENTRY_SHA512  gvisor-bin/gvisor_sentry
$GVISOR_FDPARKING_SHA512  gvisor-bin/runsc-fd-parking
$GVISOR_PREWARMER_SHA512  gvisor-bin/gvisor-sentry-prewarmer
$GVISOR_CKPTGOFER_SHA512  gvisor-bin/checkpointgofer
PINS
unpacked="$BUILD_DIR/unpacked"
rm -rf "$unpacked" "$DEST"
mkdir -p "$unpacked"
# shellcheck disable=SC2046 # the pinned names: fixed, no spaces
tar -xjf "$bundle" -C "$unpacked" --no-same-owner $(awk '{print $2}' "$pins")
(cd "$unpacked" && sha512sum -c --quiet "$pins")
while read -r _ path; do
  install -Dm0755 "$unpacked/$path" "$DEST/$path"
done < "$pins"
rm -rf "$unpacked"

find "$STAGE" -print0 | xargs -0r touch --no-dereference \
  --date="@${SOURCE_DATE_EPOCH:?}"
