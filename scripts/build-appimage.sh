#!/bin/bash
# build-appimage.sh - Automated AppImage builder for Ambient Wallet
# See docs/APPIMAGE_BUILD.md for detailed documentation

set -e  # Exit on error

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APPDIR="/tmp/ambient-appimage"
OUTPUT_FILE="${PROJECT_ROOT}/ambient-gui-x86_64.AppImage"
APPIMAGETOOL="/tmp/appimagetool"

echo "🏗️  Building Ambient Wallet AppImage..."
echo "📍 Project root: $PROJECT_ROOT"

# Step 1: Build release binary
echo "📦 Building release binary..."
cd "$PROJECT_ROOT"
cargo build --bin ambient-gui --features gui --release

# Step 2: Create AppDir structure
echo "📁 Creating AppDir structure..."
rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin"
mkdir -p "$APPDIR/usr/share/applications"
mkdir -p "$APPDIR/usr/share/icons/hicolor/256x256/apps"

# Step 3: Copy binary
echo "📋 Copying binary..."
cp target/release/ambient-gui "$APPDIR/usr/bin/"
chmod +x "$APPDIR/usr/bin/ambient-gui"

# Step 4: Create desktop file
echo "🖥️  Creating desktop entry..."
cat > "$APPDIR/ambient-gui.desktop" <<'EOF'
[Desktop Entry]
Name=Ambient Wallet
Comment=Bitcoin wallet with SNICKER support
Exec=ambient-gui
Icon=ambient-gui
Type=Application
Categories=Finance;Utility;
Terminal=false
EOF

cp "$APPDIR/ambient-gui.desktop" "$APPDIR/usr/share/applications/"

# Step 5: Create icon
echo "🎨 Creating icon..."
if command -v convert &> /dev/null; then
    convert -size 256x256 xc:#F7931A \
        -gravity center \
        -pointsize 120 \
        -fill white \
        -annotate +0+0 'A' \
        "$APPDIR/ambient-gui.png"
    echo "✓ Icon created with ImageMagick"
elif [ -f "$PROJECT_ROOT/assets/icon.png" ]; then
    cp "$PROJECT_ROOT/assets/icon.png" "$APPDIR/ambient-gui.png"
    echo "✓ Using icon from assets/"
else
    echo "⚠️  ImageMagick not found and no assets/icon.png"
    echo "    Creating placeholder icon..."
    # Create a minimal 1x1 PNG and scale it
    printf '\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\xcf\xc0\x00\x00\x00\x03\x00\x01\x00\x00\x00\x00IEND\xaeB`\x82' > "$APPDIR/ambient-gui.png"
fi

cp "$APPDIR/ambient-gui.png" "$APPDIR/usr/share/icons/hicolor/256x256/apps/"

# Step 6: Create AppRun
echo "🔗 Creating AppRun..."
cd "$APPDIR"
ln -sf usr/bin/ambient-gui AppRun

# Step 7: Download appimagetool (if needed)
if [ ! -f "$APPIMAGETOOL" ]; then
    echo "⬇️  Downloading appimagetool..."
    wget -q --show-progress \
        https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage \
        -O "$APPIMAGETOOL"
    chmod +x "$APPIMAGETOOL"
fi

# Step 8: Package AppImage
echo "📦 Packaging AppImage..."
rm -f "$OUTPUT_FILE"
"$APPIMAGETOOL" "$APPDIR" "$OUTPUT_FILE" 2>&1 | grep -E "(Success|Error|embedding)"

# Step 9: Verify
echo ""
echo "✅ AppImage created successfully!"
ls -lh "$OUTPUT_FILE"

echo ""
echo "📊 File information:"
file "$OUTPUT_FILE"

if command -v sha256sum &> /dev/null; then
    echo ""
    echo "🔐 SHA256 checksum:"
    sha256sum "$OUTPUT_FILE"
fi

echo ""
echo "🎉 Done! AppImage available at:"
echo "   $OUTPUT_FILE"
echo ""
echo "Run with:"
echo "   ./ambient-gui-x86_64.AppImage"
echo ""
echo "Or install to ~/Applications/:"
echo "   mkdir -p ~/Applications"
echo "   cp ambient-gui-x86_64.AppImage ~/Applications/"
