#!/usr/bin/env python3
"""
secret_audit_menubar.py

A macOS menu bar app — click the icon in your menu bar to see a live
summary of your secret_audit.py scan (SSH keys, credential files, .env
files, permission warnings), just like clicking the system-info icon
shows CPU/memory/storage.

REQUIRES: secret_audit.py must be in the SAME FOLDER as this file — it's
imported directly rather than duplicated.

--------------------------------------------------------------------------
SETUP
--------------------------------------------------------------------------
1. Put secret_audit.py and secret_audit_menubar.py in the same folder,
   e.g. ~/tools/secret-audit/

2. Install the one dependency:
       pip3 install rumps

3. (Optional) Edit SCAN_DIRS below to point at your project folders,
   e.g. SCAN_DIRS = ["~/code", "~/projects"]

4. Run it:
       python3 secret_audit_menubar.py

   A key icon (🔑) will appear in your menu bar. Click it to see the
   report. Click "Run Audit Now" to refresh.

--------------------------------------------------------------------------
OPTIONAL: LAUNCH AUTOMATICALLY AT LOGIN
--------------------------------------------------------------------------
Create ~/Library/LaunchAgents/com.local.secretaudit.plist with:

    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
      "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
      <key>Label</key><string>com.local.secretaudit</string>
      <key>ProgramArguments</key>
      <array>
        <string>/usr/bin/python3</string>
        <string>/FULL/PATH/TO/secret_audit_menubar.py</string>
      </array>
      <key>RunAtLoad</key><true/>
    </dict>
    </plist>

Then run: launchctl load ~/Library/LaunchAgents/com.local.secretaudit.plist
(Replace /FULL/PATH/TO/ with the real path — `pwd` in that folder to get it.)
--------------------------------------------------------------------------
"""

import contextlib
import io
import subprocess
import webbrowser
from pathlib import Path

import rumps

# Hide from the Dock and Cmd-Tab switcher — without this, running the script
# directly launches Python as a regular foreground app (hence the Python
# rocket/pen icon bouncing in your Dock). This makes it behave like a proper
# menu-bar-only utility, same as apps like Stats/iStat Menus.
try:
    from AppKit import NSApplication, NSApplicationActivationPolicyAccessory
    NSApplication.sharedApplication().setActivationPolicy_(NSApplicationActivationPolicyAccessory)
except ImportError:
    pass  # pyobjc not available yet — app will still work, just shows in the Dock

try:
    import secret_audit  # secret_audit.py must sit next to this file
except ImportError as e:
    try:
        rumps.alert(
            "Secret Audit — Startup Error",
            f"Could not load secret_audit.py:\n{e}\n\n"
            "Make sure secret_audit.py sits in the same folder as this script.",
        )
    except Exception:
        pass
    raise

# Add project folders you want scanned for .env files, e.g.:
# SCAN_DIRS = ["~/code", "~/projects"]
SCAN_DIRS = []


class SecretAuditMenuBarApp(rumps.App):
    def __init__(self):
        super().__init__("🔑", quit_button="Quit")
        self.report = {}
        self.menu = ["Run Audit Now"]
        self.refresh(None)

    @rumps.clicked("Run Audit Now")
    def refresh(self, _):
        self.report = secret_audit.build_report(SCAN_DIRS)
        self._rebuild_menu()

    def _rebuild_menu(self):
        self.menu.clear()
        self.menu.add(rumps.MenuItem("Run Audit Now", callback=self.refresh))
        self.menu.add(rumps.separator)

        self._add_section("SSH Keys", self.report.get("ssh_keys", []), self._ssh_line)
        self._add_section("Credential Files", self.report.get("credential_files", []), self._cred_line)
        self._add_section("Project .env Files", self.report.get("project_secret_files", []), self._proj_line)

        warnings = self._count_warnings()
        self.title = "🔑" if warnings == 0 else f"🔑 {warnings}"

        self.menu.add(rumps.MenuItem(f"⚠ {warnings} warning(s)" if warnings else "✓ No warnings", callback=None))
        self.menu.add(rumps.separator)

        self.menu.add(rumps.MenuItem("Open Dashboard", callback=self.open_dashboard))
        self.menu.add(rumps.MenuItem("Copy Full Report", callback=self.copy_report))
        self.menu.add(self._build_validity_menu())

    def _build_validity_menu(self):
        validity_menu = rumps.MenuItem("Check Validity")
        validity_menu.add(rumps.MenuItem("GitHub Token", callback=lambda _: self.check_validity("github")))
        validity_menu.add(rumps.MenuItem("npm Token", callback=lambda _: self.check_validity("npm")))
        for profile in secret_audit.list_aws_profiles():
            validity_menu.add(rumps.MenuItem(
                f"AWS: {profile}", callback=lambda _, p=profile: self.check_validity("aws", p)
            ))
        for k in self.report.get("ssh_keys", []):
            fname = Path(k["file"]).name
            validity_menu.add(rumps.MenuItem(
                f"SSH → GitHub: {fname}", callback=lambda _, f=k["file"]: self.check_validity("ssh_github", f)
            ))
        return validity_menu

    def open_dashboard(self, _):
        path = secret_audit.generate_html_dashboard(self.report)
        webbrowser.open(f"file://{path}")

    def check_validity(self, kind, arg=None):
        rumps.notification("Secret Audit", "Checking…", "Contacting the official API — one moment")
        if kind == "github":
            r = secret_audit.check_github_token_validity()
            if not r.get("found"):
                msg = r["message"]
            elif r.get("valid") is True:
                msg = f"Valid — authenticated as {r['identity']} (scopes: {r.get('scopes','?')})"
            elif r.get("valid") is False:
                msg = f"Invalid/revoked ({r.get('message','')})"
            else:
                msg = r.get("message", "unknown result")
        elif kind == "npm":
            r = secret_audit.check_npm_token_validity()
            if not r.get("found"):
                msg = r["message"]
            elif r.get("valid") is True:
                msg = f"Valid — authenticated as {r['identity']}"
            elif r.get("valid") is False:
                msg = f"Invalid/revoked ({r.get('message','')})"
            else:
                msg = r.get("message", "unknown result")
        elif kind == "aws":
            r = secret_audit.check_aws_validity(arg or "default")
            if not r.get("found"):
                msg = r["message"]
            elif r.get("valid") is True:
                msg = f"Valid — account {r.get('account')}"
            else:
                msg = f"Invalid ({r.get('message','')})"
        elif kind == "ssh_github":
            r = secret_audit.check_ssh_github_validity(arg)
            if r.get("valid") is True:
                msg = f"Registered with GitHub as {r.get('identity')}"
            elif r.get("valid") is False:
                msg = r.get("message", "Not valid for GitHub")
            else:
                msg = r.get("message", "unknown result")
        else:
            msg = "Unknown check"
        rumps.notification("Secret Audit — Validity Result", kind, msg)

    def _add_section(self, title, items, line_fn):
        self.menu.add(rumps.MenuItem(f"— {title} —", callback=None))
        if not items:
            self.menu.add(rumps.MenuItem("  none found", callback=None))
        else:
            for item in items:
                self.menu.add(rumps.MenuItem(line_fn(item), callback=None))
        self.menu.add(rumps.separator)

    @staticmethod
    def _ssh_line(k):
        flag = " ⚠ perms" if k["insecure_permissions"] else ""
        fp = k.get("fingerprint", "?")
        short_fp = fp if len(fp) <= 24 else fp[:24] + "…"
        return f"  {Path(k['file']).name} — {k.get('key_type', '?')} {short_fp}{flag}"

    @staticmethod
    def _cred_line(c):
        flag = " ⚠ perms" if c["insecure_permissions"] else ""
        return f"  {Path(c['file']).name}{flag}"

    @staticmethod
    def _proj_line(p):
        flag = "" if p["likely_gitignored"] else " ⚠ not gitignored"
        return f"  {Path(p['file']).name}{flag}"

    def _count_warnings(self):
        n = 0
        for k in self.report.get("ssh_keys", []):
            if k["insecure_permissions"]:
                n += 1
        for c in self.report.get("credential_files", []):
            if c["insecure_permissions"]:
                n += 1
        for p in self.report.get("project_secret_files", []):
            if not p["likely_gitignored"]:
                n += 1
        return n

    def copy_report(self, _):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            secret_audit.print_human(self.report)
        subprocess.run(["pbcopy"], input=buf.getvalue(), text=True)
        rumps.notification("Secret Audit", "Report copied", "Full report copied to clipboard")


if __name__ == "__main__":
    try:
        SecretAuditMenuBarApp().run()
    except Exception:
        import traceback
        log_dir = Path.home() / "Library" / "Logs" / "SecretAudit"
        log_dir.mkdir(parents=True, exist_ok=True)
        (log_dir / "crash.log").write_text(traceback.format_exc())
        raise
