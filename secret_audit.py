#!/usr/bin/env python3
"""
secret_audit.py — scanning + validity-check logic for the Secret Audit
menu bar app. No external dependencies beyond the stdlib and whatever
system CLIs happen to be installed (ssh-keygen, git, aws).

Run directly for a CLI report:
    python3 secret_audit.py
"""

import configparser
import html
import json
import os
import re
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

HOME = Path.home()

# ---------------------------------------------------------------------------
# permissions
# ---------------------------------------------------------------------------

def _insecure_permissions(path, max_mode=0o600):
    try:
        mode = stat.S_IMODE(os.stat(path).st_mode)
    except OSError:
        return False
    return bool(mode & ~max_mode)


# ---------------------------------------------------------------------------
# SSH keys
# ---------------------------------------------------------------------------

def _looks_like_private_key(path):
    try:
        with open(path, "rb") as f:
            head = f.read(64)
    except OSError:
        return False
    return b"PRIVATE KEY" in head


def _fingerprint_parts(path):
    try:
        out = subprocess.run(
            ["ssh-keygen", "-lf", str(path)],
            capture_output=True, text=True, timeout=5,
        )
    except Exception:
        return None
    if out.returncode != 0:
        return None
    # e.g. "256 SHA256:xxxxx comment (ED25519)"
    parts = out.stdout.strip().split(None, 2)
    return parts if len(parts) >= 2 else None


def scan_ssh_keys():
    ssh_dir = HOME / ".ssh"
    results = []
    if not ssh_dir.is_dir():
        return results
    for entry in sorted(ssh_dir.iterdir()):
        if not entry.is_file() or entry.suffix == ".pub":
            continue
        if entry.name in ("known_hosts", "known_hosts.old", "config", "authorized_keys"):
            continue
        if not _looks_like_private_key(entry):
            continue
        parts = _fingerprint_parts(entry)
        fingerprint = parts[1] if parts else "?"
        key_type = "unknown"
        if parts and len(parts) >= 3 and "(" in parts[2]:
            key_type = parts[2].rsplit("(", 1)[-1].rstrip(")").lower()
        results.append({
            "file": str(entry),
            "key_type": key_type,
            "fingerprint": fingerprint,
            "insecure_permissions": _insecure_permissions(entry, 0o600),
        })
    return results


# ---------------------------------------------------------------------------
# credential files
# ---------------------------------------------------------------------------

CREDENTIAL_FILES = [
    "~/.aws/credentials",
    "~/.aws/config",
    "~/.netrc",
    "~/.npmrc",
    "~/.pypirc",
    "~/.git-credentials",
    "~/.docker/config.json",
    "~/.kube/config",
    "~/.config/gh/hosts.yml",
    "~/.gem/credentials",
    "~/.cargo/credentials",
]


def scan_credential_files():
    results = []
    for raw in CREDENTIAL_FILES:
        path = Path(raw).expanduser()
        if path.is_file():
            results.append({
                "file": str(path),
                "insecure_permissions": _insecure_permissions(path, 0o600),
            })
    return results


# ---------------------------------------------------------------------------
# project .env / secret files
# ---------------------------------------------------------------------------

PROJECT_SECRET_NAMES = {
    ".env", ".env.local", ".env.development", ".env.production", ".env.test",
    "secrets.yaml", "secrets.yml", "secrets.json", "credentials.json",
}

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__"}


def _is_gitignored(path):
    try:
        out = subprocess.run(
            ["git", "check-ignore", "-q", str(path)],
            cwd=str(path.parent), capture_output=True, timeout=5,
        )
        return out.returncode == 0
    except Exception:
        return False


def scan_project_secret_files(scan_dirs):
    results = []
    seen = set()
    for raw in scan_dirs:
        root = Path(raw).expanduser()
        if not root.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                if name not in PROJECT_SECRET_NAMES:
                    continue
                fpath = Path(dirpath) / name
                key = str(fpath.resolve())
                if key in seen:
                    continue
                seen.add(key)
                results.append({
                    "file": str(fpath),
                    "likely_gitignored": _is_gitignored(fpath),
                })
    return results


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------

def build_report(scan_dirs=None):
    return {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "ssh_keys": scan_ssh_keys(),
        "credential_files": scan_credential_files(),
        "project_secret_files": scan_project_secret_files(scan_dirs or []),
    }


def print_human(report):
    print(f"Secret Audit — {report.get('generated_at', '')}")

    print("\nSSH Keys:")
    for k in report["ssh_keys"]:
        flag = "  ⚠ insecure permissions" if k["insecure_permissions"] else ""
        print(f"  {k['file']} — {k['key_type']} {k['fingerprint']}{flag}")
    if not report["ssh_keys"]:
        print("  none found")

    print("\nCredential Files:")
    for c in report["credential_files"]:
        flag = "  ⚠ insecure permissions" if c["insecure_permissions"] else ""
        print(f"  {c['file']}{flag}")
    if not report["credential_files"]:
        print("  none found")

    print("\nProject .env / Secret Files:")
    for p in report["project_secret_files"]:
        flag = "" if p["likely_gitignored"] else "  ⚠ not gitignored"
        print(f"  {p['file']}{flag}")
    if not report["project_secret_files"]:
        print("  none found")


def generate_html_dashboard(report):
    def esc(s):
        return html.escape(str(s))

    rows_ssh = "".join(
        f"<tr><td>{esc(k['file'])}</td><td>{esc(k['key_type'])}</td>"
        f"<td>{esc(k['fingerprint'])}</td>"
        f"<td>{'⚠ insecure' if k['insecure_permissions'] else 'ok'}</td></tr>"
        for k in report["ssh_keys"]
    ) or "<tr><td colspan=4>none found</td></tr>"

    rows_cred = "".join(
        f"<tr><td>{esc(c['file'])}</td>"
        f"<td>{'⚠ insecure' if c['insecure_permissions'] else 'ok'}</td></tr>"
        for c in report["credential_files"]
    ) or "<tr><td colspan=2>none found</td></tr>"

    rows_proj = "".join(
        f"<tr><td>{esc(p['file'])}</td>"
        f"<td>{'ok' if p['likely_gitignored'] else '⚠ not gitignored'}</td></tr>"
        for p in report["project_secret_files"]
    ) or "<tr><td colspan=2>none found</td></tr>"

    doc = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Secret Audit</title>
<style>
body {{ font-family: -apple-system, sans-serif; margin: 2rem; color: #222; }}
table {{ border-collapse: collapse; width: 100%; margin-bottom: 2rem; }}
td, th {{ border: 1px solid #ccc; padding: 6px 10px; text-align: left; font-size: 14px; }}
th {{ background: #f0f0f0; }}
</style></head><body>
<h1>🔑 Secret Audit</h1>
<p>Generated: {esc(report.get('generated_at', ''))}</p>
<h2>SSH Keys</h2>
<table><tr><th>File</th><th>Type</th><th>Fingerprint</th><th>Permissions</th></tr>{rows_ssh}</table>
<h2>Credential Files</h2>
<table><tr><th>File</th><th>Permissions</th></tr>{rows_cred}</table>
<h2>Project .env / Secret Files</h2>
<table><tr><th>File</th><th>Gitignored</th></tr>{rows_proj}</table>
</body></html>"""

    path = Path(tempfile.gettempdir()) / "secret_audit_dashboard.html"
    path.write_text(doc)
    return str(path)


# ---------------------------------------------------------------------------
# AWS profiles
# ---------------------------------------------------------------------------

def list_aws_profiles():
    profiles = set()
    for raw in ("~/.aws/credentials", "~/.aws/config"):
        path = Path(raw).expanduser()
        if not path.is_file():
            continue
        cp = configparser.ConfigParser()
        try:
            cp.read(path)
        except configparser.Error:
            continue
        for section in cp.sections():
            name = section[len("profile "):] if section.startswith("profile ") else section
            profiles.add(name)
    return sorted(profiles) if profiles else ["default"]


# ---------------------------------------------------------------------------
# validity checks
# ---------------------------------------------------------------------------

def _find_github_token():
    for var in ("GITHUB_TOKEN", "GH_TOKEN"):
        if os.environ.get(var):
            return os.environ[var]
    gh_hosts = HOME / ".config" / "gh" / "hosts.yml"
    if gh_hosts.is_file():
        m = re.search(r"oauth_token:\s*(\S+)", gh_hosts.read_text(errors="ignore"))
        if m:
            return m.group(1)
    git_creds = HOME / ".git-credentials"
    if git_creds.is_file():
        for line in git_creds.read_text(errors="ignore").splitlines():
            if "github.com" in line:
                m = re.search(r"://[^:]*:([^@]+)@", line)
                if m:
                    return m.group(1)
    return None


def check_github_token_validity():
    token = _find_github_token()
    if not token:
        return {"found": False, "message": "No GitHub token found ($GITHUB_TOKEN/$GH_TOKEN, gh config, git-credentials)"}
    req = urllib.request.Request(
        "https://api.github.com/user",
        headers={"Authorization": f"token {token}", "User-Agent": "secret-audit"},
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read())
            return {
                "found": True, "valid": True,
                "identity": data.get("login"),
                "scopes": resp.headers.get("X-OAuth-Scopes", ""),
            }
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return {"found": True, "valid": False, "message": "401 Unauthorized — token invalid/revoked"}
        return {"found": True, "valid": None, "message": f"HTTP {e.code}"}
    except Exception as e:
        return {"found": True, "valid": None, "message": str(e)}


def _find_npm_token():
    npmrc = HOME / ".npmrc"
    if not npmrc.is_file():
        return None
    m = re.search(r"_authToken=(\S+)", npmrc.read_text(errors="ignore"))
    return m.group(1) if m else None


def check_npm_token_validity():
    token = _find_npm_token()
    if not token:
        return {"found": False, "message": "No npm token found in ~/.npmrc"}
    req = urllib.request.Request(
        "https://registry.npmjs.org/-/whoami",
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read())
            return {"found": True, "valid": True, "identity": data.get("username")}
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return {"found": True, "valid": False, "message": f"HTTP {e.code} — token invalid/revoked"}
        return {"found": True, "valid": None, "message": f"HTTP {e.code}"}
    except Exception as e:
        return {"found": True, "valid": None, "message": str(e)}


def check_aws_validity(profile="default"):
    try:
        out = subprocess.run(
            ["aws", "sts", "get-caller-identity", "--profile", profile, "--output", "json"],
            capture_output=True, text=True, timeout=10,
        )
    except FileNotFoundError:
        return {"found": False, "message": "aws CLI not installed"}
    except Exception as e:
        return {"found": False, "message": str(e)}
    if out.returncode != 0:
        return {"found": True, "valid": False, "message": out.stderr.strip()[:200]}
    try:
        data = json.loads(out.stdout)
    except json.JSONDecodeError:
        return {"found": True, "valid": None, "message": "could not parse aws output"}
    return {"found": True, "valid": True, "account": data.get("Account"), "identity": data.get("Arn")}


def check_ssh_github_validity(key_file):
    try:
        out = subprocess.run(
            [
                "ssh", "-T", "git@github.com",
                "-i", str(key_file),
                "-o", "IdentitiesOnly=yes",
                "-o", "StrictHostKeyChecking=accept-new",
                "-o", "BatchMode=yes",
                "-o", "ConnectTimeout=8",
            ],
            capture_output=True, text=True, timeout=12,
        )
    except Exception as e:
        return {"valid": None, "message": str(e)}
    text = out.stdout + out.stderr
    m = re.search(r"Hi ([^!]+)!", text)
    if m:
        return {"valid": True, "identity": m.group(1)}
    if "Permission denied" in text:
        return {"valid": False, "message": "Permission denied — key not registered with GitHub"}
    return {"valid": None, "message": text.strip()[:200] or "no response"}


if __name__ == "__main__":
    print_human(build_report())
