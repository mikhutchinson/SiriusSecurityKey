#!/bin/sh
set -eu

tool_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
swift build --package-path "$tool_root" -c release
binary=$(swift build --package-path "$tool_root" -c release --show-bin-path)/SiriusSecurityKeyControlledRP
resource_bundle=$(dirname "$binary")/SiriusSecurityKey_SiriusSecurityKey.bundle
app="$tool_root/.build/SiriusSecurityKeyControlledRP.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp "$tool_root/Info.plist" "$app/Contents/Info.plist"
cp "$binary" "$app/Contents/MacOS/SiriusSecurityKeyControlledRP"
/usr/bin/ditto "$resource_bundle" "$app/Contents/Resources/SiriusSecurityKey_SiriusSecurityKey.bundle"
printf '%s\n' "$app"
