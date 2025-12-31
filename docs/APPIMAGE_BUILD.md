# AppImage Build Process for Ambient Wallet

**Date Created:** 2025-12-05
**Last Updated:** 2025-12-31
**AppImage Version:** ambient-gui-x86_64.AppImage
**Binary Size:** ~16 MB

---

## Overview

This document describes the exact steps taken to create the Ambient Wallet AppImage for Linux distribution. The process is designed to be reproducible and can be automated for CI/CD pipelines.

---

## Prerequisites

### Required Tools

1. **Rust toolchain** (stable channel)
   ```bash
   rustc --version  # Should be 1.70+
   cargo --version
   ```

2. **appimagetool**
   - Download from: https://github.com/AppImage/AppImageKit/releases
   - Version used: continuous build (x86_64)
   - Location: Downloaded to `/tmp/appimagetool`

3. **ImageMagick** (optional, for icon generation)
   ```bash
   sudo apt install imagemagick  # Debian/Ubuntu
   # or
   sudo dnf install ImageMagick  # Fedora
   ```

4. **Standard Unix tools**
   - `wget` or `curl`
   - `chmod`, `mkdir`, `cp`, `ln`

### Build Environment

- **OS:** Linux (tested on Ubuntu 22.04 / Debian-based)
- **Architecture:** x86_64
- **Cargo features:** `gui` feature must be enabled
- **Dependencies:** All Iced 0.13.1 dependencies (automatically resolved by Cargo)

---

## Step-by-Step Build Process

### 1. Build the Release Binary

```bash
cd /home/waxwing/code/rustsnicker

# Clean build (optional but recommended for reproducibility)
cargo clean

# Build the GUI binary in release mode
cargo build --bin ambient-gui --features gui --release

# Verify binary was created
ls -lh target/release/ambient-gui
# Expected: ~15 MB (includes GTK3 dependencies)
```

**Build flags used:**
- `--release`: Enables optimizations (opt-level = 3)
- `--features gui`: Enables Iced GUI dependencies
- `--bin ambient-gui`: Builds only the GUI binary (not CLI)

**Build time:** Approximately 3-5 minutes on a modern system (clean build)

---

### 2. Create AppImage Directory Structure

The AppImage format requires a specific directory layout compatible with the [AppDir specification](https://docs.appimage.org/reference/appdir.html).

```bash
# Create the base AppDir structure
mkdir -p /tmp/ambient-appimage/usr/bin
mkdir -p /tmp/ambient-appimage/usr/share/applications
mkdir -p /tmp/ambient-appimage/usr/share/icons/hicolor/256x256/apps

# Verify structure
tree /tmp/ambient-appimage
# Expected output:
# /tmp/ambient-appimage/
# └── usr/
#     ├── bin/
#     ├── share/
#         ├── applications/
#         └── icons/
#             └── hicolor/
#                 └── 256x256/
#                     └── apps/
```

---

### 3. Copy the Binary

```bash
# Copy the compiled binary to the AppDir
cp target/release/ambient-gui /tmp/ambient-appimage/usr/bin/

# Make it executable (should already be, but ensure it)
chmod +x /tmp/ambient-appimage/usr/bin/ambient-gui

# Verify
ls -lh /tmp/ambient-appimage/usr/bin/ambient-gui
```

---

### 4. Create the Desktop Entry File

The `.desktop` file provides metadata for Linux desktop environments.

**Location:** `/tmp/ambient-appimage/ambient-gui.desktop` (root of AppDir)

**Contents:**
```ini
[Desktop Entry]
Name=Ambient Wallet
Comment=Bitcoin wallet with SNICKER support
Exec=ambient-gui
Icon=ambient-gui
Type=Application
Categories=Finance;Utility;
Terminal=false
```

**Also copy to standard location:**
```bash
cp /tmp/ambient-appimage/ambient-gui.desktop \
   /tmp/ambient-appimage/usr/share/applications/
```

**Field Explanations:**
- `Name`: Display name in application menus
- `Comment`: Tooltip/description text
- `Exec`: Binary name to execute (relative to AppDir)
- `Icon`: Icon name (without extension)
- `Type`: Always "Application" for apps
- `Categories`: FreeDesktop.org categories (Finance, Utility)
- `Terminal`: Set to `false` for GUI apps

**References:**
- [Desktop Entry Specification](https://specifications.freedesktop.org/desktop-entry-spec/latest/)

---

### 5. Create the Application Icon

#### Method 1: Using ImageMagick (Recommended)

```bash
# Create a simple icon with Bitcoin orange background and white "A"
convert -size 256x256 xc:#F7931A \
    -gravity center \
    -pointsize 120 \
    -fill white \
    -annotate +0+0 'A' \
    /tmp/ambient-appimage/ambient-gui.png

# Verify icon was created
file /tmp/ambient-appimage/ambient-gui.png
# Expected: PNG image data, 256 x 256, 8-bit/color RGB
```

**Color used:** `#F7931A` (Bitcoin orange)

#### Method 2: Manual Icon (for reproducible builds)

For true reproducibility, provide a pre-made PNG icon in the repository:

```bash
# If you have a designed icon:
cp assets/icon.png /tmp/ambient-appimage/ambient-gui.png
```

**Icon specifications:**
- Format: PNG
- Size: 256x256 pixels (required)
- Color depth: 8-bit RGB or RGBA
- Background: Can be transparent

#### Copy Icon to Standard Location

```bash
cp /tmp/ambient-appimage/ambient-gui.png \
   /tmp/ambient-appimage/usr/share/icons/hicolor/256x256/apps/
```

---

### 6. Create the AppRun Entry Point

The `AppRun` file is the executable that gets called when the AppImage runs.

```bash
cd /tmp/ambient-appimage

# Create symlink to the binary
ln -sf usr/bin/ambient-gui AppRun

# Verify
ls -l AppRun
# Expected: AppRun -> usr/bin/ambient-gui
```

**Note:** Using a symlink is the simplest approach. For more complex apps, `AppRun` can be a shell script that sets environment variables or performs initialization.

---

### 7. Verify AppDir Structure

Before packaging, verify the complete structure:

```bash
tree /tmp/ambient-appimage
```

**Expected output:**
```
/tmp/ambient-appimage/
├── ambient-gui.desktop
├── ambient-gui.png
├── AppRun -> usr/bin/ambient-gui
└── usr/
    ├── bin/
    │   └── ambient-gui
    └── share/
        ├── applications/
        │   └── ambient-gui.desktop
        └── icons/
            └── hicolor/
                └── 256x256/
                    └── apps/
                        └── ambient-gui.png
```

**Critical files (must exist):**
1. `AppRun` (symlink or script)
2. `ambient-gui.desktop` (at root)
3. `ambient-gui.png` (at root)
4. `usr/bin/ambient-gui` (actual binary)

---

### 8. Download appimagetool

```bash
# Download the latest continuous build
wget -q https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage \
    -O /tmp/appimagetool

# Make it executable
chmod +x /tmp/appimagetool

# Verify
/tmp/appimagetool --version
```

**Note:** The "continuous" build is the latest version. For reproducibility, you may want to use a specific tagged release:

```bash
# For a specific version (example):
wget https://github.com/AppImage/AppImageKit/releases/download/13/appimagetool-x86_64.AppImage
```

---

### 9. Package the AppImage

```bash
# Run appimagetool to create the AppImage
/tmp/appimagetool /tmp/ambient-appimage /home/waxwing/ambient-gui-x86_64.AppImage

# Expected output:
# Number of fragments 1
# Number of symbolic links  2
# ...
# Embedding ELF...
# Marking the AppImage as executable...
# Embedding MD5 digest
# Success
```

**Command syntax:**
```
appimagetool <source-appdir> <output-file>
```

**Options available (not used but useful):**
- `--no-appstream`: Skip AppStream metadata validation
- `--sign`: Sign the AppImage with GPG key
- `--comp gzip`: Use gzip compression (default is xz)
- `--runtime-file <file>`: Use custom runtime

---

### 10. Verify the AppImage

```bash
# Check file properties
ls -lh ambient-gui-x86_64.AppImage
# Expected: ~16 MB, executable

# Check file type
file /home/waxwing/ambient-gui-x86_64.AppImage
# Expected: ELF 64-bit LSB executable, x86-64

# Test execution (if DISPLAY is available)
./ambient-gui-x86_64.AppImage

# Extract and inspect contents (without running)
./ambient-gui-x86_64.AppImage --appimage-extract
ls squashfs-root/
```

---

## Reproducibility Notes

### Challenges to Reproducible Builds

1. **Rust compilation timestamps:**
   - Rust embeds build timestamps in binaries by default
   - Solution: Use `SOURCE_DATE_EPOCH` environment variable

2. **Dependency versions:**
   - `Cargo.lock` ensures consistent dependencies
   - Commit `Cargo.lock` to repository

3. **System libraries:**
   - Iced GUI requires system libraries (X11, Wayland, etc.)
   - These are dynamically linked and vary by system

4. **appimagetool version:**
   - Different versions may produce different output
   - Pin to a specific release for reproducibility

### Making Builds More Reproducible

#### Use SOURCE_DATE_EPOCH

```bash
# Set a fixed timestamp for reproducible builds
export SOURCE_DATE_EPOCH=1609459200  # 2021-01-01 00:00:00 UTC

# Build with this environment variable
cargo build --bin ambient-gui --features gui --release
```

#### Pin appimagetool Version

Instead of using "continuous", download a specific release:

```bash
APPIMAGETOOL_VERSION=13
wget https://github.com/AppImage/AppImageKit/releases/download/${APPIMAGETOOL_VERSION}/appimagetool-x86_64.AppImage
```

#### Strip Debug Symbols Consistently

```bash
# After building, strip the binary
strip target/release/ambient-gui

# Or add to Cargo.toml:
# [profile.release]
# strip = true
```

---

## Automation Script

Here's a complete script that automates the entire process:

```bash
#!/bin/bash
# build-appimage.sh - Automated AppImage builder for Ambient Wallet

set -e  # Exit on error

PROJECT_ROOT="/home/waxwing/code/rustsnicker"
APPDIR="/tmp/ambient-appimage"
OUTPUT_FILE="${PROJECT_ROOT}/ambient-gui-x86_64.AppImage"
APPIMAGETOOL="/tmp/appimagetool"

echo "🏗️  Building Ambient Wallet AppImage..."

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
cat > "$APPDIR/ambient-gui.desktop" <<EOF
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
else
    echo "⚠️  ImageMagick not found, skipping icon generation"
    touch "$APPDIR/ambient-gui.png"
fi

cp "$APPDIR/ambient-gui.png" "$APPDIR/usr/share/icons/hicolor/256x256/apps/"

# Step 6: Create AppRun
echo "🔗 Creating AppRun..."
cd "$APPDIR"
ln -sf usr/bin/ambient-gui AppRun

# Step 7: Download appimagetool (if needed)
if [ ! -f "$APPIMAGETOOL" ]; then
    echo "⬇️  Downloading appimagetool..."
    wget -q https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage \
        -O "$APPIMAGETOOL"
    chmod +x "$APPIMAGETOOL"
fi

# Step 8: Package AppImage
echo "📦 Packaging AppImage..."
rm -f "$OUTPUT_FILE"
"$APPIMAGETOOL" "$APPDIR" "$OUTPUT_FILE"

# Step 9: Verify
echo "✅ AppImage created successfully!"
ls -lh "$OUTPUT_FILE"
file "$OUTPUT_FILE"

echo ""
echo "🎉 Done! AppImage available at:"
echo "   $OUTPUT_FILE"
echo ""
echo "Run with: ./ambient-gui-x86_64.AppImage"
```

**Save as:** `scripts/build-appimage.sh`

**Usage:**
```bash
chmod +x scripts/build-appimage.sh
./scripts/build-appimage.sh
```

---

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Build AppImage

on:
  push:
    tags:
      - 'v*'
  workflow_dispatch:

jobs:
  build:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Install Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable

      - name: Install system dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y imagemagick wget

      - name: Build AppImage
        run: |
          chmod +x scripts/build-appimage.sh
          ./scripts/build-appimage.sh

      - name: Upload AppImage
        uses: actions/upload-artifact@v3
        with:
          name: ambient-gui-appimage
          path: ambient-gui-x86_64.AppImage
```

---

## Troubleshooting

### Common Issues

#### 1. "appimagetool: command not found"

**Solution:** Download appimagetool as shown in Step 8.

#### 2. "Desktop file validation failed"

**Cause:** Invalid `.desktop` file format.

**Solution:** Validate with:
```bash
desktop-file-validate /tmp/ambient-appimage/ambient-gui.desktop
```

#### 3. AppImage doesn't run: "cannot execute binary file"

**Cause:** AppImage was built for wrong architecture.

**Solution:** Ensure you're building on x86_64 Linux for x86_64 target.

#### 4. Missing libraries when running AppImage

**Cause:** Dynamically linked libraries not available on target system.

**Solution:** Consider using `linuxdeploy` to bundle dependencies:
```bash
# Install linuxdeploy
wget https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage
chmod +x linuxdeploy-x86_64.AppImage

# Use it to bundle dependencies
./linuxdeploy-x86_64.AppImage --appdir=/tmp/ambient-appimage --output appimage
```

#### 5. Icon doesn't appear in desktop environment

**Cause:** Icon not in expected location or wrong format.

**Solution:**
- Ensure PNG format, 256x256 pixels
- Check both root and `usr/share/icons/.../` locations
- Icon filename must match `Icon=` field in desktop file

---

## File Checksums (for this build)

For verification and reproducibility tracking:

```
Binary: target/release/ambient-gui
Size: ~15 MB (includes GTK3 dependencies)

AppImage: ambient-gui-x86_64.AppImage
Size: ~16 MB
SHA256: (run: sha256sum ambient-gui-x86_64.AppImage)
```

---

## References

- [AppImage Documentation](https://docs.appimage.org/)
- [AppDir Specification](https://docs.appimage.org/reference/appdir.html)
- [Desktop Entry Specification](https://specifications.freedesktop.org/desktop-entry-spec/latest/)
- [AppImageKit GitHub](https://github.com/AppImage/AppImageKit)
- [Iced GUI Framework](https://github.com/iced-rs/iced)
- [Rust Reproducible Builds](https://reproducible-builds.org/docs/)

---

## Future Improvements

1. **Bundle icon source:** Include a high-quality SVG icon in `assets/` directory
2. **Automated testing:** Add script to test AppImage on clean Docker container
3. **Signing:** Sign AppImages with GPG for authenticity verification
4. **Multi-arch:** Build for ARM64 in addition to x86_64
5. **AppStream metadata:** Add AppStream XML for better desktop integration
6. **Continuous builds:** Set up GitHub Actions to build on every release tag
7. **Delta updates:** Implement AppImageUpdate for efficient updates

---

## Changelog

**2025-12-31:** Updated size estimates (~16 MB) after switching to GTK3 file dialog backend
**2025-12-05:** Initial documentation of AppImage build process
