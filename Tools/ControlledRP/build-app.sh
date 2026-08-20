#!/bin/sh
set -eu

tool_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
swift build --package-path "$tool_root" -c release
binary=$(swift build --package-path "$tool_root" -c release --show-bin-path)/SiriusSecurityKeyControlledRP
resource_bundle=$(dirname "$binary")/SiriusSecurityKey_SiriusSecurityKey.bundle
app="$tool_root/.build/SiriusSecurityKeyControlledRP.app"
staging=$(mktemp -d "$tool_root/.build/SiriusSecurityKeyControlledRP.app.staging.XXXXXX")
previous="$tool_root/.build/SiriusSecurityKeyControlledRP.app.previous.$$"

cleanup() {
  if [ -n "${staging:-}" ] && [ -e "$staging" ]; then
    rm -rf -- "$staging"
  fi
  if [ -e "$previous" ]; then
    if [ ! -e "$app" ]; then
      mv -- "$previous" "$app"
    else
      rm -rf -- "$previous"
    fi
  fi
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$staging/Contents/MacOS" "$staging/Contents/Resources"
cp "$tool_root/Info.plist" "$staging/Contents/Info.plist"
cp "$binary" "$staging/Contents/MacOS/SiriusSecurityKeyControlledRP"
/usr/bin/ditto "$resource_bundle" "$staging/Contents/Resources/SiriusSecurityKey_SiriusSecurityKey.bundle"

if [ -e "$app" ]; then
  mv -- "$app" "$previous"
fi
mv -- "$staging" "$app"
staging=
rm -rf -- "$previous"
trap - EXIT HUP INT TERM
printf '%s\n' "$app"
