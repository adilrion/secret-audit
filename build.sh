#!/usr/bin/env bash
#
# build.sh — build and install the Secret Audit menu bar app.
#
# Usage:
#   ./build.sh          # dev build (default) — app references your .py files
#                        # directly. After this, editing secret_audit.py or
#                        # secret_audit_menubar.py needs NO rebuild — just
#                        # run ./reload.sh (or quit + reopen the app).
#
#   ./build.sh release  # standalone build — freezes a self-contained copy
#                        # into the app bundle. Use this only when you're
#                        # done iterating, want to hand the app to another
#                        # Mac, or are about to move/delete this source folder.
#
set -e

APP_NAME="Secret Audit"
INSTALL_DIR="/Applications"
MODE="${1:-dev}"

echo "==> Quitting existing '$APP_NAME' if it's running..."
osascript -e "tell application \"$APP_NAME\" to quit" >/dev/null 2>&1 || true
pkill -f "secret_audit_menubar" >/dev/null 2>&1 || true
sleep 1

echo "==> Cleaning previous build artifacts..."
rm -rf build dist

if [ "$MODE" = "release" ]; then
    echo "==> Building RELEASE bundle (fully self-contained, slower)..."
    python3 setup.py py2app
else
    echo "==> Building DEV bundle (alias mode — instant future updates)..."
    python3 setup.py py2app -A
fi

echo "==> Installing to $INSTALL_DIR ..."
rm -rf "$INSTALL_DIR/$APP_NAME.app"
cp -R "dist/$APP_NAME.app" "$INSTALL_DIR/"

echo "==> Launching..."
open "$INSTALL_DIR/$APP_NAME.app"

echo ""
echo "Done. Build mode: $MODE"
if [ "$MODE" = "dev" ]; then
    echo ""
    echo "From now on, to ship a code change:"
    echo "  1. Edit secret_audit.py or secret_audit_menubar.py"
    echo "  2. Run ./reload.sh"
    echo "  (No rebuild needed — the app reads these files directly.)"
    echo ""
    echo "NOTE: don't move or delete this source folder — the dev app"
    echo "depends on it staying right here. Run './build.sh release' before"
    echo "archiving/moving this project if you want a standalone copy."
else
    echo ""
    echo "This is a standalone copy — editing the .py files here won't"
    echo "affect it. Run './build.sh' (dev mode) for day-to-day iteration."
fi
