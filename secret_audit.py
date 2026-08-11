#!/usr/bin/env python3
"""
secret_audit.py — scanning + validity-check logic for the Secret Audit
menu bar app. No external dependencies beyond the stdlib and whatever
system CLIs happen to be installed (ssh-keygen, git, aws).

Run directly for a CLI report:
    python3 secret_audit.py
"""

import base64
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
import urllib.parse
import urllib.request
from pathlib import Path

HOME = Path.home()
CONFIG_DIR = HOME / "Library" / "Application Support" / "SecretAudit"
CONFIG_FILE = CONFIG_DIR / "config.json"


def load_config():
    if CONFIG_FILE.is_file():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except (OSError, json.JSONDecodeError):
            pass
    return {"scan_dirs": []}


def save_config(config):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(config, indent=2))


def fix_permissions(path, mode=0o600):
    try:
        os.chmod(path, mode)
        return {"success": True}
    except OSError as e:
        return {"success": False, "message": str(e)}

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
# API / service token detection — fixed-signature regexes for well-known
# providers (high confidence) plus a var-name heuristic fallback so newer
# or less common services (most AI model APIs included) still get flagged.
# ---------------------------------------------------------------------------

# Order matters: more specific prefixes must come before looser ones that
# would otherwise also match them (e.g. Anthropic's "sk-ant-" before the
# generic OpenAI "sk-" pattern).
TOKEN_PATTERNS = [
    ("Anthropic API Key", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("OpenAI API Key", re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}")),
    ("Google/Gemini API Key", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("Groq API Key", re.compile(r"gsk_[A-Za-z0-9]{20,}")),
    ("Hugging Face Token", re.compile(r"hf_[A-Za-z0-9]{20,}")),
    ("Replicate Token", re.compile(r"r8_[A-Za-z0-9]{20,}")),
    ("Perplexity API Key", re.compile(r"pplx-[A-Za-z0-9]{20,}")),
    ("GitHub Fine-Grained PAT", re.compile(r"github_pat_[A-Za-z0-9_]{20,}")),
    ("GitHub Personal Access Token", re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("GitHub OAuth Token", re.compile(r"gho_[A-Za-z0-9]{36}")),
    ("GitHub App Token", re.compile(r"ghs_[A-Za-z0-9]{36}")),
    ("npm Token", re.compile(r"npm_[A-Za-z0-9]{36}")),
    ("Slack Token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Stripe Secret Key", re.compile(r"sk_(?:live|test)_[A-Za-z0-9]{10,}")),
    ("SendGrid API Key", re.compile(r"SG\.[A-Za-z0-9_\-.]{20,}")),
    ("DigitalOcean Token", re.compile(r"dop_v1_[a-f0-9]{64}")),
]

# Var-name hints so heuristic (no fixed-prefix) matches get a readable label
# instead of the raw env var name — mostly AI-provider keys that are opaque
# strings with no recognizable signature.
KNOWN_VAR_NAME_HINTS = {
    "OPENAI_API_KEY": "OpenAI", "ANTHROPIC_API_KEY": "Anthropic",
    "GOOGLE_API_KEY": "Google/Gemini", "GEMINI_API_KEY": "Google/Gemini",
    "COHERE_API_KEY": "Cohere", "MISTRAL_API_KEY": "Mistral",
    "AZURE_OPENAI_API_KEY": "Azure OpenAI", "AZURE_OPENAI_KEY": "Azure OpenAI",
    "HUGGINGFACE_API_KEY": "Hugging Face", "HF_TOKEN": "Hugging Face",
    "REPLICATE_API_TOKEN": "Replicate", "GROQ_API_KEY": "Groq",
    "PERPLEXITY_API_KEY": "Perplexity", "TOGETHER_API_KEY": "Together AI",
    "DEEPSEEK_API_KEY": "DeepSeek", "ELEVENLABS_API_KEY": "ElevenLabs",
    "STRIPE_SECRET_KEY": "Stripe", "TWILIO_AUTH_TOKEN": "Twilio",
    "SLACK_BOT_TOKEN": "Slack", "SENDGRID_API_KEY": "SendGrid",
    "DIGITALOCEAN_TOKEN": "DigitalOcean", "HEROKU_API_KEY": "Heroku",
    "NPM_TOKEN": "npm", "_AUTHTOKEN": "npm", "GITHUB_TOKEN": "GitHub",
    "GH_TOKEN": "GitHub",
}

GENERIC_SECRET_NAME_RE = re.compile(
    r".*(API[_-]?KEY|SECRET|TOKEN|ACCESS[_-]?KEY|AUTH[_-]?TOKEN)$", re.IGNORECASE
)

PLACEHOLDER_VALUES = {"", "changeme", "your_api_key_here", "xxx", "todo", "replace_me"}

_ASSIGN_RE_EQ = re.compile(r'^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.+)$')
_ASSIGN_RE_COLON = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_.-]*)\s*:\s*(.+)$')

SHELL_RC_FILES = ["~/.zshrc", "~/.zprofile", "~/.zshenv", "~/.bashrc", "~/.bash_profile", "~/.profile"]


def _is_placeholder(value):
    return len(value) < 8 or value.lower() in PLACEHOLDER_VALUES


def _strip_quotes(value):
    value = value.split("#", 1)[0].strip() if not value.startswith(("'", '"')) else value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        value = value[1:-1]
    return value.strip()


def _classify_value(var_name, value):
    for name, pattern in TOKEN_PATTERNS:
        if pattern.search(value):
            return name, "high"
    if var_name and GENERIC_SECRET_NAME_RE.match(var_name):
        return KNOWN_VAR_NAME_HINTS.get(var_name.upper(), var_name), "heuristic"
    return None, None


def _mask(value):
    if len(value) <= 8:
        return "•" * len(value)
    return f"{value[:4]}…{value[-4:]}"


def _make_token(name, var_name, file, line, value, confidence):
    return {
        "name": name, "var_name": var_name, "file": file, "line": line,
        "value": value, "masked": _mask(value), "confidence": confidence,
    }


def _scan_kv_file_for_tokens(path, sep="="):
    pattern = _ASSIGN_RE_EQ if sep == "=" else _ASSIGN_RE_COLON
    found = []
    try:
        lines = Path(path).read_text(errors="ignore").splitlines()
    except OSError:
        return found
    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = pattern.match(line)
        if not m:
            continue
        var_name, raw_value = m.group(1), _strip_quotes(m.group(2))
        if _is_placeholder(raw_value):
            continue
        label, confidence = _classify_value(var_name, raw_value)
        if not label:
            continue
        found.append(_make_token(label, var_name, str(path), i, raw_value, confidence))
    return found


def scan_shell_rc_tokens():
    found = []
    for raw in SHELL_RC_FILES:
        path = Path(raw).expanduser()
        if path.is_file():
            found.extend(_scan_kv_file_for_tokens(path, sep="="))
    return found


def scan_git_credentials_tokens():
    path = HOME / ".git-credentials"
    if not path.is_file():
        return []
    found = []
    for i, line in enumerate(path.read_text(errors="ignore").splitlines(), start=1):
        m = re.search(r"://[^:/]*:([^@/]+)@([^/\s]+)", line)
        if not m:
            continue
        value, host = m.group(1), m.group(2)
        if _is_placeholder(value):
            continue
        label, confidence = _classify_value(f"{host}_TOKEN", value)
        found.append(_make_token(label or f"Git Credential ({host})", host, str(path), i, value, confidence or "heuristic"))
    return found


def scan_docker_config_tokens():
    path = HOME / ".docker" / "config.json"
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return []
    found = []
    for host, entry in (data.get("auths") or {}).items():
        auth_b64 = entry.get("auth")
        if not auth_b64:
            continue
        try:
            decoded = base64.b64decode(auth_b64).decode("utf-8", "replace")
        except (ValueError, UnicodeDecodeError):
            decoded = auth_b64
        found.append(_make_token(f"Docker Registry Auth ({host})", host, str(path), None, decoded, "heuristic"))
    return found


def scan_credential_file_tokens():
    found = []
    for raw in ("~/.aws/credentials", "~/.aws/config", "~/.npmrc", "~/.pypirc", "~/.cargo/credentials", "~/.gem/credentials"):
        path = Path(raw).expanduser()
        if path.is_file():
            found.extend(_scan_kv_file_for_tokens(path, sep="="))
    for raw in ("~/.config/gh/hosts.yml", "~/.kube/config"):
        path = Path(raw).expanduser()
        if path.is_file():
            found.extend(_scan_kv_file_for_tokens(path, sep=":"))
    found.extend(scan_git_credentials_tokens())
    found.extend(scan_docker_config_tokens())
    return found


def scan_env_tokens():
    # NOTE: a menu-bar app launched via Finder/LaunchServices gets launchd's
    # minimal environment, not your shell's exported vars — this only finds
    # everything when run from a terminal. The rc-file and dotfile scans
    # above are what catch things regardless of how the app was launched.
    found = []
    for var_name, value in os.environ.items():
        if _is_placeholder(value):
            continue
        label, confidence = _classify_value(var_name, value)
        if not label:
            continue
        found.append(_make_token(label, var_name, "environment variable", None, value, confidence))
    return found


def scan_tokens(scan_dirs=None, project_files=None):
    if project_files is None:
        project_files = scan_project_secret_files(scan_dirs or [])
    found = []
    found.extend(scan_env_tokens())
    found.extend(scan_shell_rc_tokens())
    found.extend(scan_credential_file_tokens())
    for p in project_files:
        found.extend(_scan_kv_file_for_tokens(p["file"], sep="="))

    seen, deduped = set(), []
    for t in found:
        key = (t["name"], t["file"], t["line"], t["value"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(t)
    return deduped


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------

def build_report(scan_dirs=None):
    scan_dirs = scan_dirs or []
    project_files = scan_project_secret_files(scan_dirs)
    return {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "ssh_keys": scan_ssh_keys(),
        "credential_files": scan_credential_files(),
        "project_secret_files": project_files,
        "tokens": scan_tokens(scan_dirs, project_files=project_files),
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

    print("\nAPI / Service Tokens Found (masked — use the app's Copy Token action for the real value):")
    for t in report.get("tokens", []):
        loc = "env var" if t["file"] == "environment variable" else t["file"]
        line = f":{t['line']}" if t.get("line") else ""
        tag = "" if t["confidence"] == "high" else "  (heuristic)"
        print(f"  {t['name']}{tag} — {t['masked']} — {loc}{line}")
    if not report.get("tokens"):
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

    def _token_row(t):
        loc = "env var" if t["file"] == "environment variable" else t["file"]
        if t.get("line"):
            loc += f":{t['line']}"
        return (
            f"<tr><td>{esc(t['name'])}</td><td>{esc(t['masked'])}</td>"
            f"<td>{esc(loc)}</td><td>{esc(t['confidence'])}</td></tr>"
        )

    rows_tokens = "".join(_token_row(t) for t in report.get("tokens", [])) or "<tr><td colspan=4>none found</td></tr>"

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
<h2>API / Service Tokens (masked — copy the real value from the menu bar app)</h2>
<table><tr><th>Name</th><th>Masked</th><th>Location</th><th>Confidence</th></tr>{rows_tokens}</table>
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


# ---------------------------------------------------------------------------
# validity checks for detected API/service tokens (read-only endpoints only)
# ---------------------------------------------------------------------------

def _bearer_check(url, token, header="Authorization", value_fmt="Bearer {}"):
    req = urllib.request.Request(url, headers={header: value_fmt.format(token)})
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            return json.loads(resp.read()), None
    except urllib.error.HTTPError as e:
        return None, e
    except Exception as e:
        return None, e


def _check_openai(token):
    data, err = _bearer_check("https://api.openai.com/v1/models", token)
    if err is None:
        return {"valid": True, "message": "Key is active"}
    if isinstance(err, urllib.error.HTTPError) and err.code == 401:
        return {"valid": False, "message": "401 Unauthorized — invalid/revoked"}
    return {"valid": None, "message": str(err)}


def _check_anthropic(token):
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/models",
        headers={"x-api-key": token, "anthropic-version": "2023-06-01"},
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            json.loads(resp.read())
            return {"valid": True, "message": "Key is active"}
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return {"valid": False, "message": "401 Unauthorized — invalid/revoked"}
        return {"valid": None, "message": f"HTTP {e.code}"}
    except Exception as e:
        return {"valid": None, "message": str(e)}


def _check_google_gemini(token):
    url = f"https://generativelanguage.googleapis.com/v1/models?key={urllib.parse.quote(token)}"
    try:
        with urllib.request.urlopen(url, timeout=8) as resp:
            json.loads(resp.read())
            return {"valid": True, "message": "Key is active"}
    except urllib.error.HTTPError as e:
        if e.code in (400, 401, 403):
            return {"valid": False, "message": f"HTTP {e.code} — invalid/revoked"}
        return {"valid": None, "message": f"HTTP {e.code}"}
    except Exception as e:
        return {"valid": None, "message": str(e)}


def _check_groq(token):
    data, err = _bearer_check("https://api.groq.com/openai/v1/models", token)
    if err is None:
        return {"valid": True, "message": "Key is active"}
    if isinstance(err, urllib.error.HTTPError) and err.code == 401:
        return {"valid": False, "message": "401 Unauthorized — invalid/revoked"}
    return {"valid": None, "message": str(err)}


def _check_huggingface(token):
    data, err = _bearer_check("https://huggingface.co/api/whoami-v2", token)
    if err is None:
        return {"valid": True, "message": f"Valid — {data.get('name', '?')}"}
    if isinstance(err, urllib.error.HTTPError) and err.code == 401:
        return {"valid": False, "message": "401 Unauthorized — invalid/revoked"}
    return {"valid": None, "message": str(err)}


def _check_replicate(token):
    data, err = _bearer_check("https://api.replicate.com/v1/account", token, value_fmt="Token {}")
    if err is None:
        return {"valid": True, "message": f"Valid — {data.get('username', '?')}"}
    if isinstance(err, urllib.error.HTTPError) and err.code == 401:
        return {"valid": False, "message": "401 Unauthorized — invalid/revoked"}
    return {"valid": None, "message": str(err)}


TOKEN_VALIDATORS = {
    "OpenAI API Key": _check_openai,
    "Anthropic API Key": _check_anthropic,
    "Google/Gemini API Key": _check_google_gemini,
    "Groq API Key": _check_groq,
    "Hugging Face Token": _check_huggingface,
    "Replicate Token": _check_replicate,
}


def check_token_validity(token):
    validator = TOKEN_VALIDATORS.get(token["name"])
    if not validator:
        return {"valid": None, "message": "No validity check available for this token type"}
    try:
        return validator(token["value"])
    except Exception as e:
        return {"valid": None, "message": str(e)}


if __name__ == "__main__":
    print_human(build_report())
