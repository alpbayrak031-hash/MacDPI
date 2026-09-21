#!/bin/bash
# Builds MacDPI.app - a universal menu bar app with the proxy engine inside it.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD="$DIR/build"
APP="$BUILD/MacDPI.app"
VERSION="$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$DIR/macdpi/__init__.py")"
MIN_MACOS="12.0"

SOURCES=(Control.swift System.swift Paths.swift Installer.swift App.swift main.swift)

echo "Building MacDPI $VERSION"
rm -rf "$BUILD"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

# --- universal binary ------------------------------------------------------

cd "$DIR/MenuBar"
for arch in arm64 x86_64; do
  echo "  compiling $arch"
  xcrun swiftc -swift-version 5 -O \
    -target "$arch-apple-macos$MIN_MACOS" \
    "${SOURCES[@]}" -o "$BUILD/MacDPI-$arch"
done
echo "  merging into a universal binary"
lipo -create "$BUILD/MacDPI-arm64" "$BUILD/MacDPI-x86_64" \
     -output "$APP/Contents/MacOS/MacDPI"
rm -f "$BUILD/MacDPI-arm64" "$BUILD/MacDPI-x86_64"
chmod +x "$APP/Contents/MacOS/MacDPI"

# --- the engine travels inside the bundle ----------------------------------

echo "  bundling the engine"
mkdir -p "$APP/Contents/Resources/engine"
cp -R "$DIR/macdpi" "$APP/Contents/Resources/engine/"
cp "$DIR/dpictl" "$APP/Contents/Resources/engine/"
cp "$DIR/README.md" "$APP/Contents/Resources/"
find "$APP/Contents/Resources/engine" -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true

# --- icon ------------------------------------------------------------------

echo "  rendering the icon"
ICONSET="$BUILD/AppIcon.iconset"
mkdir -p "$ICONSET"
cat > "$BUILD/mkicon.swift" <<'ICONEOF'
import Cocoa
// Renders the same shield the menu bar uses, on a rounded macOS-style tile.
let sizes = [16, 32, 64, 128, 256, 512, 1024]
let outputDir = CommandLine.arguments[1]
for size in sizes {
    let side = CGFloat(size)
    let image = NSImage(size: NSSize(width: side, height: side))
    image.lockFocus()
    let rect = NSRect(x: 0, y: 0, width: side, height: side)
    let tile = NSBezierPath(roundedRect: rect.insetBy(dx: side * 0.06, dy: side * 0.06),
                            xRadius: side * 0.22, yRadius: side * 0.22)
    let gradient = NSGradient(colors: [
        NSColor(calibratedRed: 0.22, green: 0.45, blue: 0.95, alpha: 1),
        NSColor(calibratedRed: 0.10, green: 0.24, blue: 0.62, alpha: 1),
    ])
    gradient?.draw(in: tile, angle: -90)
    let config = NSImage.SymbolConfiguration(pointSize: side * 0.52, weight: .semibold)
    if let symbol = NSImage(systemSymbolName: "lock.shield.fill",
                            accessibilityDescription: nil)?
        .withSymbolConfiguration(config) {
        let box = NSRect(x: (side - symbol.size.width) / 2,
                         y: (side - symbol.size.height) / 2,
                         width: symbol.size.width, height: symbol.size.height)
        NSColor.white.set()
        symbol.draw(in: box, from: .zero, operation: .sourceOver, fraction: 0.96)
    }
    image.unlockFocus()
    guard let tiff = image.tiffRepresentation,
          let rep = NSBitmapImageRep(data: tiff),
          let png = rep.representation(using: .png, properties: [:]) else { continue }
    try? png.write(to: URL(fileURLWithPath: "\(outputDir)/icon_\(size).png"))
}
ICONEOF
xcrun swiftc -swift-version 5 -O "$BUILD/mkicon.swift" -o "$BUILD/mkicon" 2>/dev/null
"$BUILD/mkicon" "$ICONSET"
for pair in "16 16x16" "32 16x16@2x" "32 32x32" "64 32x32@2x" \
            "128 128x128" "256 128x128@2x" "256 256x256" "512 256x256@2x" \
            "512 512x512" "1024 512x512@2x"; do
  set -- $pair
  cp "$ICONSET/icon_$1.png" "$ICONSET/icon_$2.png" 2>/dev/null || true
done
rm -f "$ICONSET"/icon_*[0-9].png
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/AppIcon.icns" 2>/dev/null \
  && echo "  icon built" || echo "  icon skipped"
rm -rf "$ICONSET" "$BUILD/mkicon" "$BUILD/mkicon.swift"

# --- Info.plist ------------------------------------------------------------

cat > "$APP/Contents/Info.plist" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>MacDPI</string>
  <key>CFBundleDisplayName</key><string>MacDPI</string>
  <key>CFBundleIdentifier</key><string>com.macdpi.app</string>
  <key>CFBundleExecutable</key><string>MacDPI</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>LSMinimumSystemVersion</key><string>$MIN_MACOS</string>
  <!-- Menu bar only: no Dock icon, no app menu. -->
  <key>LSUIElement</key><true/>
  <key>NSHumanReadableCopyright</key><string>MacDPI $VERSION</string>
</dict>
</plist>
PLISTEOF

# --- sign ------------------------------------------------------------------

# Prefer a real Developer ID if this Mac has one; fall back to an ad-hoc
# signature otherwise. Set MACDPI_SIGN_IDENTITY to force a particular one.
IDENTITY="${MACDPI_SIGN_IDENTITY:-}"
if [ -z "$IDENTITY" ]; then
  IDENTITY="$(security find-identity -v -p codesigning 2>/dev/null \
              | awk -F'"' '/Developer ID Application/{print $2; exit}')"
fi

if [ -n "$IDENTITY" ]; then
  echo "  signing as: $IDENTITY"
  codesign --force --timestamp --options runtime \
           --identifier com.macdpi.app \
           --sign "$IDENTITY" "$APP"
  SIGNED_PROPERLY=1
else
  # An ad-hoc signature is not a trusted one - it names no authority, so
  # Gatekeeper still stops a downloaded copy. It is worth doing anyway: it
  # seals the bundle against tampering and, with an explicit identifier, keeps
  # the app's identity stable across rebuilds so macOS does not treat each
  # build as a brand new application.
  echo "  no Developer ID found - signing ad-hoc"
  codesign --force --identifier com.macdpi.app --sign - "$APP"
  SIGNED_PROPERLY=0
fi

echo "  verifying"
codesign --verify --deep --strict "$APP" && echo "  signature valid"

# --- package ---------------------------------------------------------------

cd "$BUILD"
ZIP="MacDPI-$VERSION.zip"
ditto -c -k --sequesterRsrc --keepParent "MacDPI.app" "$ZIP"

echo
echo "Built:"
echo "  $APP"
echo "  $BUILD/$ZIP  ($(du -h "$BUILD/$ZIP" | cut -f1))"
echo
lipo -archs "$APP/Contents/MacOS/MacDPI" | sed 's/^/  architectures: /'
codesign -dv "$APP" 2>&1 | awk -F= '/^Authority/{print "  authority: " $2}'
if [ "${SIGNED_PROPERLY:-0}" != "1" ]; then
  echo
  echo "  Note: ad-hoc signed, not notarised. On a Mac that downloads this,"
  echo "  the first launch needs right-click -> Open. Signing it properly"
  echo "  needs a paid Apple Developer ID; then re-run and it is picked up"
  echo "  automatically, and 'xcrun notarytool submit' completes the job."
fi
