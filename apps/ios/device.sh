#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
#
# Builds the iPhone app and its watch app, signed by a free Personal Team (an
# Apple ID signed in to Xcode, no developer account), and installs them on a
# connected iPhone and its paired Apple Watch. Such a build runs for 7 days;
# then run this again. CONTRIBUTING.md, "The iPhone app on your own phone".
#
#   apps/ios/device.sh            build, install on the phone and the watch, launch
#   apps/ios/device.sh --all      also the share extension and the widgets
#   apps/ios/device.sh --test     run the app's unit tests on the phone
#
# The environment can set CBB_TEAM (the team's 10-character ID; found in the
# Apple Development certificate when there is one), CBB_DEVICE (the phone's
# identifier, when more than one is connected) and CBB_BUNDLE_ID.
#
# A free team may have three apps on a phone at a time, an extension counting
# as one, and the app group and shared keychain need the developer account, so
# the share extension (which finds the group only through them) and the widgets
# are left out unless --all. The build is Debug: messages show the error
# underneath.
set -eu

all=0
test=0
for a in "$@"; do
	case $a in
	--all) all=1 ;;
	--test) test=1 ;;
	*) echo "usage: $0 [--all] [--test]" >&2; exit 2 ;;
	esac
done

cd "$(dirname "$0")"
root=$(cd ../.. && pwd)

team=${CBB_TEAM:-}
if [ -z "$team" ]; then
	team=$(security find-certificate -a -c "Apple Development" -p 2>/dev/null |
		openssl x509 -noout -subject -nameopt multiline 2>/dev/null |
		sed -n 's/^ *organizationalUnitName *= *//p' | head -n 1)
fi
if [ -z "$team" ]; then
	echo "no team: sign in to Xcode (Settings, Accounts) with your Apple ID, open" >&2
	echo "ClipboardBridge.xcodeproj once and pick your Personal Team under Signing," >&2
	echo "or set CBB_TEAM to its ID" >&2
	exit 1
fi
lower=$(printf %s "$team" | tr '[:upper:]' '[:lower:]')
# Not the release identifier: the developer account will register that one.
bundle=${CBB_BUNDLE_ID:-dev.$lower.clipboardbridge}

# The connected devices from devicectl: "platform udid name" lines.
list=$(mktemp)
trap 'rm -f "$list" device.yml' EXIT
xcrun devicectl list devices --json-output "$list" >/dev/null
devices=$(/usr/bin/python3 -I - "$list" <<'EOF'
import json, sys
for d in json.load(open(sys.argv[1]))["result"]["devices"]:
    hw, cp = d.get("hardwareProperties", {}), d.get("connectionProperties", {})
    if cp.get("pairingState") != "paired":
        continue
    print(hw.get("platform", ""), hw.get("udid", ""), d.get("deviceProperties", {}).get("name", "").replace(" ", "_"))
EOF
)
phone=${CBB_DEVICE:-$(printf '%s\n' "$devices" | awk '$1 == "iOS" { print $2; exit }')}
watch=$(printf '%s\n' "$devices" | awk '$1 == "watchOS" { print $2; exit }')
if [ -z "$phone" ]; then
	echo "no iPhone: connect it by cable, unlock it, trust this Mac and turn on" >&2
	echo "Developer Mode (Settings, Privacy & Security)" >&2
	exit 1
fi

# The tunnel and the Rust core the app links, when not built yet.
[ -d Cbbtun.xcframework ] || "$root/mobile/cbbtun/bind.sh" ios "$PWD/Cbbtun.xcframework"
[ -d CbbCore/iphoneos ] || sh "$root/lite/ffi/bind.sh" ios "$PWD/CbbCore"

if [ "$all" = 1 ]; then
	xcodegen generate --spec project.yml
else
	grep -v -e '- target: ShareExtension$' -e '- target: Widgets$' project.yml >device.yml
	xcodegen generate --spec device.yml
fi

derived=$HOME/Library/Developer/Xcode/DerivedData/cbb-device
set -- -project ClipboardBridge.xcodeproj -scheme ClipboardBridge -configuration Debug \
	-destination "id=$phone" -derivedDataPath "$derived" \
	-allowProvisioningUpdates -allowProvisioningDeviceRegistration \
	DEVELOPMENT_TEAM="$team" CODE_SIGN_STYLE=Automatic CBB_BUNDLE_ID="$bundle"

if [ "$test" = 1 ]; then
	xcodebuild test "$@"
	exit
fi
xcodebuild build "$@"

app=$derived/Build/Products/Debug-iphoneos/ClipboardBridge.app
xcrun devicectl device install app --device "$phone" "$app"
if [ -n "$watch" ] && [ -d "$app/Watch/Watch.app" ]; then
	xcrun devicectl device install app --device "$watch" "$app/Watch/Watch.app" ||
		echo "the watch app was not installed: turn on Developer Mode on the watch, keep it unlocked near the phone" >&2
fi
xcrun devicectl device process launch --device "$phone" "$bundle" ||
	echo "installed; on the first run trust the developer in Settings, General, VPN & Device Management" >&2
echo "installed $bundle (team $team); it runs for 7 days"
