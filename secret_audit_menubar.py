#!/usr/bin/env python3
"""
secret_audit_menubar.py

A macOS menu bar app — click the icon in your menu bar to see a live
summary of your secret_audit.py scan (SSH keys, credential files, .env
files, permission warnings, and detected API/service tokens — including
AI providers like OpenAI/Anthropic — with real file:line locations, a
Copy Token action, and a Check Validity call against the provider's own
API). Insecure file permissions can be fixed one-click (or all at once).
Folders to scan for project .env files are managed from the "Scan
Folders" menu (native folder picker) and persisted to
~/Library/Application Support/SecretAudit/config.json — no more editing
this file to change SCAN_DIRS. Works just like clicking the system-info
icon shows CPU/memory/storage.

REQUIRES: secret_audit.py must be in the SAME FOLDER as this file — it's
imported directly rather than duplicated.

--------------------------------------------------------------------------
SETUP
--------------------------------------------------------------------------
1. Put secret_audit.py and secret_audit_menubar.py in the same folder,
   e.g. ~/tools/secret-audit/

2. Install the one dependency:
       pip3 install rumps

3. (Optional) Add project folders to scan for .env files via the app's
   "Scan Folders → Add Folder…" menu once it's running, or pre-seed
   SCAN_DIRS below for the very first run.

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
import threading
from pathlib import Path

import rumps

# Hide from the Dock and Cmd-Tab switcher — without this, running the script
# directly launches Python as a regular foreground app (hence the Python
# rocket/pen icon bouncing in your Dock). This makes it behave like a proper
# menu-bar-only utility, same as apps like Stats/iStat Menus.
try:
    from AppKit import NSApplication, NSApplicationActivationPolicyAccessory, NSOpenPanel
    NSApplication.sharedApplication().setActivationPolicy_(NSApplicationActivationPolicyAccessory)
except ImportError:
    NSOpenPanel = None  # pyobjc not available yet — app still works, just shows in the Dock and
                         # loses the native folder picker (Add Folder to Scan won't be available)

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

# Default project folders to scan for .env files on first run, e.g.:
# SCAN_DIRS = ["~/code", "~/projects"]
# After first run, use the "Scan Folders" menu to add/remove folders — that
# list is persisted to ~/Library/Application Support/SecretAudit/config.json
# and takes over from this constant.
SCAN_DIRS = []

CLIPBOARD_CLEAR_SECONDS = 30


def _clear_clipboard_if_unchanged(expected_value):
    # Only wipe the clipboard if the user hasn't copied something else in
    # the meantime — avoids clobbering an unrelated copy.
    try:
        current = subprocess.run(["pbpaste"], capture_output=True, text=True, timeout=3).stdout
    except Exception:
        return
    if current == expected_value:
        subprocess.run(["pbcopy"], input="", text=True)


class SecretAuditMenuBarApp(rumps.App):
    def __init__(self):
        super().__init__("🔑", quit_button="Quit")
        config = secret_audit.load_config()
        self.scan_dirs = config.get("scan_dirs") or list(SCAN_DIRS)
        self.report = {}
        self.menu = ["Run Audit Now"]
        self.refresh(None)

    @rumps.clicked("Run Audit Now")
    def refresh(self, _):
        self.report = secret_audit.build_report(self.scan_dirs)
        self._rebuild_menu()

    def _save_scan_dirs(self):
        secret_audit.save_config({"scan_dirs": self.scan_dirs})

    def add_scan_folder(self, _):
        if NSOpenPanel is None:
            rumps.alert("Secret Audit", "pyobjc/AppKit not available — can't show the folder picker.")
            return
        panel = NSOpenPanel.openPanel()
        panel.setCanChooseDirectories_(True)
        panel.setCanChooseFiles_(False)
        panel.setAllowsMultipleSelection_(False)
        panel.setPrompt_("Add")
        if panel.runModal() == 1:  # NSModalResponseOK / NSOKButton
            path = panel.URLs()[0].path()
            if path not in self.scan_dirs:
                self.scan_dirs.append(path)
                self._save_scan_dirs()
                self.refresh(None)

    def remove_scan_folder(self, path):
        self.scan_dirs = [d for d in self.scan_dirs if d != path]
        self._save_scan_dirs()
        self.refresh(None)

    def _build_scan_dirs_menu(self):
        m = rumps.MenuItem("Scan Folders")
        m.add(rumps.MenuItem("Add Folder…", callback=self.add_scan_folder))
        if self.scan_dirs:
            m.add(rumps.separator)
            for d in self.scan_dirs:
                entry = rumps.MenuItem(d)
                entry.add(rumps.MenuItem("Remove", callback=lambda _, dd=d: self.remove_scan_folder(dd)))
                m.add(entry)
        return m

    def _rebuild_menu(self):
        self.menu.clear()
        self.menu.add(rumps.MenuItem("Run Audit Now", callback=self.refresh))
        self.menu.add(rumps.separator)

        self._add_actionable_section("SSH Keys", self.report.get("ssh_keys", []), self._build_ssh_item)
        self._add_actionable_section("Credential Files", self.report.get("credential_files", []), self._build_cred_item)
        self._add_section("Project .env Files", self.report.get("project_secret_files", []), self._proj_line)
        self._add_token_section()

        warnings = self._count_warnings()
        self.title = "🔑" if warnings == 0 else f"🔑 {warnings}"

        self.menu.add(rumps.MenuItem(f"⚠ {warnings} warning(s)" if warnings else "✓ No warnings", callback=None))
        if self._count_permission_warnings():
            self.menu.add(rumps.MenuItem("Fix All Insecure Permissions", callback=self.fix_all_permissions))
        self.menu.add(rumps.separator)

        self.menu.add(rumps.MenuItem("Open Dashboard", callback=self.open_dashboard))
        self.menu.add(rumps.MenuItem("Copy Full Report", callback=self.copy_report))
        self.menu.add(self._build_validity_menu())
        self.menu.add(self._build_scan_dirs_menu())

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
        ai_tokens = [t for t in self.report.get("tokens", []) if t["name"] in secret_audit.AI_USAGE_CHECKERS]
        if ai_tokens:
            rumps.notification(
                "Secret Audit", "Fetching live AI usage…",
                f"Checking {len(ai_tokens)} key(s) before opening the dashboard",
            )
        ai_usage = [
            {"name": t["name"], "masked": t["masked"], **secret_audit.check_ai_usage(t)}
            for t in ai_tokens
        ]
        path = secret_audit.generate_html_dashboard(self.report, ai_usage=ai_usage)
        result = subprocess.run(["open", path], capture_output=True, text=True)
        if result.returncode != 0:
            rumps.notification(
                "Secret Audit", "Couldn't auto-open dashboard",
                f"Open manually: {path}",
            )

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

    def _add_token_section(self):
        self.menu.add(rumps.MenuItem("— API / Service Tokens —", callback=None))
        tokens = self.report.get("tokens", [])
        if not tokens:
            self.menu.add(rumps.MenuItem("  none found", callback=None))
        else:
            for t in tokens:
                self.menu.add(self._build_token_item(t))
        self.menu.add(rumps.separator)

    def _build_token_item(self, t):
        item = rumps.MenuItem(self._token_label(t))
        item.add(rumps.MenuItem("Copy Token", callback=lambda _, tok=t: self.copy_token(tok)))
        if t["file"] != "environment variable":
            item.add(rumps.MenuItem("Reveal in Finder", callback=lambda _, tok=t: self.reveal_in_finder(tok["file"])))
        if t["name"] in secret_audit.TOKEN_VALIDATORS:
            item.add(rumps.MenuItem("Check Validity", callback=lambda _, tok=t: self.check_token_validity(tok)))
        if t["name"] in secret_audit.AI_USAGE_CHECKERS:
            item.add(rumps.MenuItem("Check Usage — Realtime (tiny live cost)", callback=lambda _, tok=t: self.check_ai_usage(tok)))
        return item

    def check_ai_usage(self, token):
        rumps.notification("Secret Audit", "Checking usage…", f"Making a minimal live call to the {token['name']} API")
        r = secret_audit.check_ai_usage(token)
        rumps.notification("Secret Audit — Realtime Usage", token["name"], self._format_usage(r))

    @staticmethod
    def _format_usage(r):
        if not r.get("found"):
            return r.get("message", "No usage data available")
        parts = []
        if r.get("requests_limit") and r.get("requests_remaining") is not None:
            parts.append(f"Requests {r['requests_remaining']}/{r['requests_limit']}")
        if r.get("tokens_limit") and r.get("tokens_remaining") is not None:
            parts.append(f"Tokens {r['tokens_remaining']}/{r['tokens_limit']}")
        if r.get("reset"):
            parts.append(f"resets {r['reset']}")
        return " · ".join(parts) if parts else "Rate-limit headers present but empty"

    def check_token_validity(self, token):
        rumps.notification("Secret Audit", "Checking…", f"Contacting the {token['name']} API")
        r = secret_audit.check_token_validity(token)
        if r.get("valid") is True:
            msg = r.get("message", "Valid")
        elif r.get("valid") is False:
            msg = f"Invalid/revoked — {r.get('message', '')}"
        else:
            msg = r.get("message", "unknown result")
        rumps.notification("Secret Audit — Validity Result", token["name"], msg)

    @staticmethod
    def _token_label(t):
        loc = "env var" if t["file"] == "environment variable" else Path(t["file"]).name
        if t.get("line"):
            loc += f":{t['line']}"
        tag = " (heuristic)" if t["confidence"] != "high" else ""
        return f"  {t['name']}{tag} — {t['masked']} — {loc}"

    def copy_token(self, token):
        subprocess.run(["pbcopy"], input=token["value"], text=True)
        rumps.notification(
            "Secret Audit", f"{token['name']} copied",
            f"Clipboard clears automatically in {CLIPBOARD_CLEAR_SECONDS}s",
        )
        threading.Timer(CLIPBOARD_CLEAR_SECONDS, _clear_clipboard_if_unchanged, args=(token["value"],)).start()

    def reveal_in_finder(self, path):
        subprocess.run(["open", "-R", path])

    def fix_permissions(self, path):
        r = secret_audit.fix_permissions(path)
        if r["success"]:
            rumps.notification("Secret Audit", "Permissions fixed", f"{Path(path).name} set to 600 (owner read/write only)")
        else:
            rumps.notification("Secret Audit", "Fix failed", r.get("message", "unknown error"))
        self.refresh(None)

    def fix_all_permissions(self, _):
        targets = [k["file"] for k in self.report.get("ssh_keys", []) if k["insecure_permissions"]]
        targets += [c["file"] for c in self.report.get("credential_files", []) if c["insecure_permissions"]]
        fixed = sum(1 for path in targets if secret_audit.fix_permissions(path)["success"])
        failed = len(targets) - fixed
        msg = f"{fixed} file(s) set to 600" + (f", {failed} failed" if failed else "")
        rumps.notification("Secret Audit", "Fix All Permissions", msg)
        self.refresh(None)

    def _add_actionable_section(self, title, items, builder):
        self.menu.add(rumps.MenuItem(f"— {title} —", callback=None))
        if not items:
            self.menu.add(rumps.MenuItem("  none found", callback=None))
        else:
            for item in items:
                self.menu.add(builder(item))
        self.menu.add(rumps.separator)

    def _build_ssh_item(self, k):
        item = rumps.MenuItem(self._ssh_line(k))
        if k["insecure_permissions"]:
            item.add(rumps.MenuItem("Fix Permissions (chmod 600)", callback=lambda _, kk=k: self.fix_permissions(kk["file"])))
        item.add(rumps.MenuItem("Reveal in Finder", callback=lambda _, kk=k: self.reveal_in_finder(kk["file"])))
        return item

    def _build_cred_item(self, c):
        item = rumps.MenuItem(self._cred_line(c))
        if c["insecure_permissions"]:
            item.add(rumps.MenuItem("Fix Permissions (chmod 600)", callback=lambda _, cc=c: self.fix_permissions(cc["file"])))
        item.add(rumps.MenuItem("Reveal in Finder", callback=lambda _, cc=c: self.reveal_in_finder(cc["file"])))
        return item

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

    def _count_permission_warnings(self):
        n = sum(1 for k in self.report.get("ssh_keys", []) if k["insecure_permissions"])
        n += sum(1 for c in self.report.get("credential_files", []) if c["insecure_permissions"])
        return n

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
