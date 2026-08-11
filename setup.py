"""
setup.py — packages secret_audit_menubar.py into a real macOS .app bundle
(no Python icon, no Dock presence, lives entirely in the menu bar — just
like Stats/iStat Menus).

--------------------------------------------------------------------------
ONE-TIME SETUP
--------------------------------------------------------------------------
1. Make sure these three files are in the same folder:
       secret_audit.py
       secret_audit_menubar.py
       setup.py                (this file)

2. Install the build tool:
       pip3 install py2app

3. Build the app:
       python3 setup.py py2app

   This creates:  dist/Secret Audit.app

4. Move it to your Applications folder:
       mv "dist/Secret Audit.app" /Applications/

5. Double-click it in /Applications (or Spotlight-search "Secret Audit")
   to launch. It will NOT appear in the Dock or Cmd-Tab — only the 🔑 icon
   in your menu bar.

--------------------------------------------------------------------------
LAUNCH AT LOGIN (the proper way, once it's a real .app)
--------------------------------------------------------------------------
System Settings → General → Login Items → click "+" → select
"Secret Audit.app" from /Applications.

(You can remove any old LaunchAgent plist from earlier — it's no longer
needed once this is a real .app.)

--------------------------------------------------------------------------
OPTIONAL: CUSTOM APP ICON
--------------------------------------------------------------------------
Since it's an accessory app it won't show in the Dock anyway, but if you
want a custom icon for Spotlight/Finder:

1. Get/make a 1024x1024 PNG, e.g. icon.png
2. Convert it to .icns:
       mkdir icon.iconset
       sips -z 16 16     icon.png --out icon.iconset/icon_16x16.png
       sips -z 32 32     icon.png --out icon.iconset/icon_16x16@2x.png
       sips -z 32 32     icon.png --out icon.iconset/icon_32x32.png
       sips -z 64 64     icon.png --out icon.iconset/icon_32x32@2x.png
       sips -z 128 128   icon.png --out icon.iconset/icon_128x128.png
       sips -z 256 256   icon.png --out icon.iconset/icon_128x128@2x.png
       sips -z 256 256   icon.png --out icon.iconset/icon_256x256.png
       sips -z 512 512   icon.png --out icon.iconset/icon_256x256@2x.png
       sips -z 512 512   icon.png --out icon.iconset/icon_512x512.png
       cp icon.png icon.iconset/icon_512x512@2x.png
       iconutil -c icns icon.iconset
3. Uncomment the 'iconfile' line in OPTIONS below.
4. Rebuild: python3 setup.py py2app
--------------------------------------------------------------------------
"""

from setuptools import setup
from pathlib import Path

APP = ["secret_audit_menubar.py"]
DATA_FILES = []

VERSION = Path("VERSION").read_text().strip() if Path("VERSION").exists() else "1.0.0"

OPTIONS = {
    "argv_emulation": False,
    "plist": {
        "LSUIElement": True,  # <-- this is what hides it from the Dock/Cmd-Tab
        "CFBundleName": "Secret Audit",
        "CFBundleDisplayName": "Secret Audit",
        "CFBundleIdentifier": "com.local.secretaudit",
        "CFBundleVersion": VERSION,
        "CFBundleShortVersionString": VERSION,
        "NSHumanReadableCopyright": "",
    },
    "packages": ["rumps"],
    # "iconfile": "icon.icns",   # uncomment once you've built icon.icns (see docstring above)
}

setup(
    name="Secret Audit",
    app=APP,
    data_files=DATA_FILES,
    options={"py2app": OPTIONS},
    setup_requires=["py2app"],
)
