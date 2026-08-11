#!/usr/bin/env bash
#
# reload.sh — quit and relaunch the Secret Audit app after editing code.
# Only works after an initial `./build.sh` (dev mode) — the dev app reads
# secret_audit.py / secret_audit_menubar.py directly, so this is all you
# need after a code change. No rebuild, no py2app, no waiting.
#
set -e

APP_NAME="Secret Audit"
INSTALL_DIR="/Applications"

echo "==> Quitting '$APP_NAME'..."
osascript -e "tell application \"$APP_NAME\" to quit" >/dev/null 2>&1 || true
pkill -f "secret_audit_menubar" >/dev/null 2>&1 || true
sleep 1

echo "==> Relaunching..."
open "$INSTALL_DIR/$APP_NAME.app"

echo "Done — your latest code changes are now running."
