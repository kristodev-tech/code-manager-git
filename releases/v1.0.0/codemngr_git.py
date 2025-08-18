#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Code/Version Organizer – PyQt5 Desktop App
Adds:
- Auto init + initial commit
- Release folder: <repo>/releases/<version>/
- Sync artifacts into release folder
- Create/list downloadable ZIP per release
- Open artifact / open folder from app
- Edit & save notes for existing releases
"""

import os
import re
import sys
import sqlite3
import shutil
import subprocess
import requests
import json
import webbrowser
from pathlib import Path
import subprocess
from datetime import datetime
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED
from datetime import datetime
from collections import defaultdict
from PyQt5.QtCore import Qt, QSettings, QThread, pyqtSignal
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QFileDialog, QMessageBox, QSplitter, QListWidget,
    QListWidgetItem, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QLineEdit, QTextEdit,
    QTableWidget, QTableWidgetItem, QAbstractItemView, QFormLayout, QGroupBox, QCheckBox,
    QDialog, QDialogButtonBox, QProgressBar, QAction, QStyle, QSizePolicy, QTabWidget
)

# ────────────────────────────────────────────────────────────────────────────────
APP_DIR        = Path.home() / ".codemgr"
DB_PATH        = APP_DIR / "codemgr.db"
SEMVER_RE      = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$")   # v1.2.3 / 1.2.3
DEFAULT_PREFIX = "v"

PYTHON_GITIGNORE = """# Python
__pycache__/
*.py[cod]
*.so
*.dylib
*.pyd
*.egg-info/
.eggs/
dist/
build/
.vscode/
.idea/
.env
.venv
env/
venv/
pip-wheel-metadata/
*.log
"""

# ────────────────────────────────────────────────────────────────────────────────
def show_error(parent, title, text): QMessageBox.critical(parent, title, text)
def show_info(parent, title, text): QMessageBox.information(parent, title, text)

def get_conn():
    APP_DIR.mkdir(parents=True, exist_ok=True)
    need_init = not DB_PATH.exists()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    if need_init:
        cur = conn.cursor()
        cur.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                path TEXT NOT NULL
            );
            CREATE TABLE versions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL,
                version TEXT NOT NULL,
                commit_sha TEXT NOT NULL,
                commit_date TEXT NOT NULL,
                notes TEXT DEFAULT '',
                UNIQUE(project_id, version),
                FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
            );
            CREATE TABLE artifacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                version_id INTEGER NOT NULL,
                label TEXT NOT NULL,
                file_path TEXT NOT NULL,
                FOREIGN KEY(version_id) REFERENCES versions(id) ON DELETE CASCADE
            );
        """)
        conn.commit()
    return conn

# ────────────────────────────────────────────────────────────────────────────────
# Git helpers
def git_remote_exists(path: str, name: str = "origin") -> bool:
    try:
        run_git(path, "remote", "get-url", name)
        return True
    except Exception:
        return False

def run_git(repo_path, *args) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo_path,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False
    )
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed:\n{result.stderr.strip()}")
    return result.stdout

def is_git_repo(path: str) -> bool:
    try:
        run_git(path, "rev-parse", "--is-inside-work-tree")
        return True
    except Exception:
        return False
    
def is_git_available() -> bool:
    # Fast path
    if shutil.which("git"):
        return True
    # Fallback: try invoking to cover PATH edge cases
    try:
        subprocess.run(["git", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return True
    except Exception:
        return False

def repo_has_commits(path: str) -> bool:
    try:
        run_git(path, "rev-parse", "--verify", "HEAD")
        return True
    except Exception:
        return False

def git_init_if_needed(path: str):
    # If already a repo, return
    try:
        run_git(path, "rev-parse", "--is-inside-work-tree")
        return
    except Exception:
        pass

    # Prefer init with main. Older git may not support -b; fallback then rename.
    try:
        run_git(path, "init", "-b", "main")
    except Exception:
        run_git(path, "init")
        try:
            run_git(path, "checkout", "-b", "main")
        except Exception:
            # fallback last resort: rename from whatever default
            run_git(path, "branch", "-M", "main")

def ensure_correct_origin(path: str, owner: str, repo: str) -> None:
    correct = f"https://github.com/{owner}/{repo}.git"
    try:
        current = run_git(path, "remote", "get-url", "origin").strip()
        if current == correct:
            return
        # If origin exists but mismatches, ask to retarget
        ret = QMessageBox.question(
            None, "Retarget origin?",
            f"Current 'origin' is:\n{current}\n\nExpected:\n{correct}\n\n"
            "Update the origin URL to the expected repository?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes
        )
        if ret == QMessageBox.Yes:
            run_git(path, "remote", "set-url", "origin", correct)
    except Exception:
        # No origin set; add it
        run_git(path, "remote", "add", "origin", correct)


def ensure_initial_commit(path: str, project_name: str) -> bool:
    if repo_has_commits(path):
        return False
    root = Path(path)
    has_any_file = any(p.is_file() and ".git" not in p.parts for p in root.rglob("*"))
    readme_path = root / "README.md"
    if not has_any_file or not readme_path.exists():
        readme_path.write_text(f"# {project_name}\n\nInitial repository setup.\n", encoding="utf-8")
    gi_path = root / ".gitignore"
    if not gi_path.exists():
        gi_path.write_text(PYTHON_GITIGNORE, encoding="utf-8")
    run_git(path, "add", ".")
    try:
        run_git(path, "commit", "-m", "Initial commit")
    except RuntimeError as e:
        if "nothing to commit" in str(e).lower():
            # Force a trivial change
            readme_path.write_text(readme_path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            run_git(path, "add", "README.md")
            run_git(path, "commit", "-m", "Initial commit")
        else:
            raise
    return True

def get_tags_with_meta(path: str):
    tags = run_git(path, "tag", "--list").splitlines()
    out = []
    for t in tags:
        t = t.strip()
        if not t: continue
        try:
            sha = run_git(path, "rev-list", "-n", "1", t).strip()
            date_raw = run_git(path, "show", "-s", "--format=%cI", sha).strip()
            out.append({"tag": t, "sha": sha, "date": date_raw})
        except Exception:
            continue
    return out

def get_last_tag(path: str) -> str | None:
    try:
        return run_git(path, "describe", "--tags", "--abbrev=0").strip()
    except Exception:
        return None

def make_release_notes_from_range(path: str, since_tag: str | None) -> str:
    today = datetime.now().strftime("%Y-%m-%d")
    header = f"# Release Notes\n\n**Date:** {today}\n"
    if since_tag:
        header += f"**Changes since:** {since_tag}\n\n"
        try:
            lines = run_git(path, "log", f"{since_tag}..HEAD", "--pretty=format:%s (%h)").splitlines()
            bullets = [f"- {l}" for l in lines if l.strip()]
            if bullets:
                return header + "\n".join(bullets) + "\n"
        except Exception:
            pass
    else:
        header += "**Initial release**\n\n"
    return header + "_No changes found_\n"

def create_git_tag(path: str, version: str, message: str):
    run_git(path, "tag", "-a", version, "-m", message)

def push_tags(path: str, remote: str = "origin"):
    run_git(path, "push", remote, "--tags")

# ────────────────────────────────────────────────────────────────────────────────
# Remote + push helpers
def git_current_branch(path: str) -> str:
    try:
        b = run_git(path, "rev-parse", "--abbrev-ref", "HEAD").strip()
        return "main" if b == "HEAD" else b
    except Exception:
        return "main"

def git_set_remote_origin_if_missing(path: str, https_url: str):
    # If origin exists, leave it; otherwise add.
    try:
        _ = run_git(path, "remote", "get-url", "origin")
    except Exception:
        run_git(path, "remote", "add", "origin", https_url)

def git_push_all(path: str, branch: str = None):
    branch = branch or git_current_branch(path)
    run_git(path, "push", "-u", "origin", branch)
    run_git(path, "push", "origin", "--tags")

def ensure_commit_release_folder(path: str, version: str, project_name: str, log_fn=None) -> bool:
    """
    Stage releases/<version>/ and commit only if there are changes.
    Returns True if a commit was made, False if nothing to commit.
    """
    from subprocess import run, PIPE

    def _log(msg):
        if log_fn:
            log_fn(msg)

    rel_dir = get_release_dir(path, version)
    rel_dir.mkdir(parents=True, exist_ok=True)

    # Stage the release folder (add new/modified/deleted within it)
    r_add = run(["git", "add", "-A", str(rel_dir)], cwd=path, text=True, stdout=PIPE, stderr=PIPE)
    if r_add.returncode != 0:
        raise RuntimeError(f"'git add' failed:\n{r_add.stderr.strip() or r_add.stdout.strip()}")

    # Are there any staged changes?
    # --quiet returns 0 if no differences, 1 if differences, >1 on error.
    r_diff = run(["git", "diff", "--cached", "--quiet"], cwd=path)
    if r_diff.returncode == 0:
        _log("🟦 No changes to commit in release folder.")
        return False
    if r_diff.returncode > 1:
        raise RuntimeError("Failed to check staged changes (git diff --cached --quiet).")

    # Commit
    msg = f"chore(release): add release files for {project_name} {version}"
    r_commit = run(["git", "commit", "-m", msg], cwd=path, text=True, stdout=PIPE, stderr=PIPE)
    if r_commit.returncode != 0:
        err = (r_commit.stderr or r_commit.stdout).strip()
        # Be lenient if Git still says nothing to commit here for any reason
        if "nothing to commit" in err.lower():
            _log("🟦 Nothing to commit (working tree clean).")
            return False
        raise RuntimeError(f"'git commit' failed:\n{err}")
    _log(f"✅ Commit created: {msg}")
    return True


def parse_owner_repo_from_origin_url(url: str) -> tuple[str, str] | None:
    """
    Accepts https or ssh origin URLs and returns (owner, repo) or None.
    Examples:
      https://github.com/owner/repo.git
      git@github.com:owner/repo.git
    """
    if not url:
        return None
    u = url.strip()
    # https
    if u.startswith("http://") or u.startswith("https://"):
        parts = u.split("/")
        # ... github.com/owner/repo(.git)
        try:
            idx = parts.index("github.com")
        except ValueError:
            # maybe has protocol prefix; normalize
            if "github.com" not in u:
                return None
            parts = u.split("/")
            idx = parts.index("github.com")
        if len(parts) > idx + 2:
            owner = parts[idx + 1]
            repo = parts[idx + 2]
            if repo.endswith(".git"):
                repo = repo[:-4]
            return owner, repo
        return None
    # ssh: git@github.com:owner/repo.git
    if u.startswith("git@github.com:"):
        tail = u[len("git@github.com:") :]
        if "/" in tail:
            owner, repo = tail.split("/", 1)
            if repo.endswith(".git"):
                repo = repo[:-4]
            return owner, repo
    return None


def git_push_all_token(path: str, owner: str, repo: str, username: str, token: str, branch: str | None = None):
    """One-off push using a token-embedded URL (does not modify 'origin')."""
    import subprocess, os
    branch = branch or git_current_branch(path)
    # Token in URL for one-shot push; avoids interactive auth.
    auth_url = f"https://{username}:{token}@github.com/{owner}/{repo}.git"
    env = os.environ.copy()
    # Ensure git won’t try to prompt
    env["GIT_ASKPASS"] = env.get("GIT_ASKPASS", "")
    env["GIT_TERMINAL_PROMPT"] = "0"
    # push branch (set upstream) and tags
    for args in (["push", "-u", auth_url, branch], ["push", auth_url, "--tags"]):
        p = subprocess.run(["git", *args], cwd=path, text=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        if p.returncode != 0:
            raise RuntimeError(f"git {' '.join(args)} failed:\n{(p.stderr or p.stdout).strip()}")


# ── Repo existence / creation helpers ───────────────────────────────────────────
def github_get_user(token: str) -> dict:
    r = requests.get("https://api.github.com/user", headers=gh_headers(token), timeout=20)
    if r.status_code != 200:
        raise RuntimeError(f"GitHub /user failed: {r.status_code} {r.text}")
    return r.json()

def github_repo_exists(owner: str, repo: str, token: str) -> bool:
    url = f"https://api.github.com/repos/{owner}/{repo}"
    r = requests.get(url, headers=gh_headers(token), timeout=20)
    return r.status_code == 200

def github_create_repo_user(repo: str, token: str, private: bool = True) -> dict:
    """Create a repo under the authenticated user."""
    url = "https://api.github.com/user/repos"
    payload = {"name": repo, "private": bool(private)}
    r = requests.post(url, headers=gh_headers(token), json=payload, timeout=30)
    if r.status_code not in (200, 201):
        raise RuntimeError(f"Create user repo failed: {r.status_code} {r.text}")
    return r.json()

def github_create_repo_org(org: str, repo: str, token: str, private: bool = True) -> dict:
    """Create a repo under an organization."""
    url = f"https://api.github.com/orgs/{org}/repos"
    payload = {"name": repo, "private": bool(private)}
    r = requests.post(url, headers=gh_headers(token), json=payload, timeout=30)
    if r.status_code not in (200, 201):
        # Bubble up exact status for better handling (404 often means no permission / org hidden)
        raise RuntimeError(f"Create org repo failed ({r.status_code}): {r.text}")
    return r.json()

def ensure_remote_repo_exists(owner: str, repo: str, token: str, make_private: bool, log_fn=None) -> tuple[str, str]:
    """
    Ensure https://github.com/{owner}/{repo} exists.
    - If owner is the authenticated user: create under user when missing.
    - If owner is an org: try org creation; on failure, offer user fallback.
    - Treat 422 'name already exists' as success.
    Returns (owner, repo) to use (may switch to user on fallback).
    """
    def _log(msg):
        if log_fn:
            log_fn(msg)

    # Already exists?
    try:
        if github_repo_exists(owner, repo, token):
            _log(f"ℹ️ Remote repo already exists: {owner}/{repo}")
            return owner, repo
    except Exception as e:
        raise RuntimeError(f"Failed to check repository existence: {e}")

    # Need to create
    me = github_get_user(token)
    login = (me.get("login") or "").strip()

    # Try user or org creation
    if owner.lower() == login.lower():
        try:
            created = github_create_repo_user(repo, token, private=make_private)
            _log(f"✅ Created GitHub repo: {created.get('full_name', f'{owner}/{repo}')}")
            return owner, repo
        except Exception as ee:
            msg = str(ee)
            # If name exists (422), proceed as success
            if "422" in msg and "name already exists" in msg.lower():
                _log(f"ℹ️ Repo already existed under user: {owner}/{repo}")
                return owner, repo
            raise
    else:
        try:
            created = github_create_repo_org(owner, repo, token, private=make_private)
            _log(f"✅ Created GitHub org repo: {created.get('full_name', f'{owner}/{repo}')}")
            return owner, repo
        except Exception as ee:
            msg = str(ee)
            # Offer fallback to user
            choice = QMessageBox.question(
                None,
                "Cannot Create in Org",
                f"I couldn't create '{owner}/{repo}' in the org.\n\n"
                f"{msg}\n\n"
                f"Do you want to create the repo under your user '{login}' instead?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes
            )
            if choice != QMessageBox.Yes:
                raise RuntimeError(
                    "Org creation failed and fallback declined. "
                    "Ensure org permissions and SSO token authorization, then try again."
                )
            try:
                created = github_create_repo_user(repo, token, private=make_private)
                _log(f"✅ Created user repo instead: {created.get('full_name', f'{login}/{repo}')}")
                return login, repo  # switched owner to user
            except Exception as e2:
                msg2 = str(e2)
                if "422" in msg2 and "name already exists" in msg2.lower():
                    _log(f"ℹ️ Repo already existed under user: {login}/{repo}")
                    return login, repo
                raise


# ────────────────────────────────────────────────────────────────────────────────
# GitHub API helpers
def parse_owner_repo(s: str) -> tuple[str, str]:
    """
    Accepts 'owner/repo' or full https URL and returns (owner, repo).
    """
    s = s.strip().rstrip("/")
    if s.startswith("http://") or s.startswith("https://"):
        # https://github.com/owner/repo(.git)?
        parts = s.split("/")
        if len(parts) >= 5 and parts[2].lower() == "github.com":
            owner = parts[3]
            repo = parts[4]
            if repo.endswith(".git"):
                repo = repo[:-4]
            return owner, repo
        raise ValueError("Unrecognized GitHub URL")
    # owner/repo
    if "/" not in s:
        raise ValueError("Use 'owner/repo' or a full GitHub URL")
    owner, repo = s.split("/", 1)
    return owner, repo

def gh_headers(token: str) -> dict:
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token.strip()}",
        "X-GitHub-Api-Version": "2022-11-28",
    }

def github_create_release(owner: str, repo: str, token: str, tag: str, title: str, body: str) -> dict:
    url = f"https://api.github.com/repos/{owner}/{repo}/releases"
    payload = {
        "tag_name": tag,
        "name": title,
        "body": body or "",
        "draft": False,
        "prerelease": False
    }
    r = requests.post(url, headers=gh_headers(token), json=payload, timeout=30)
    if r.status_code not in (200, 201):
        raise RuntimeError(f"GitHub create release failed: {r.status_code} {r.text}")
    return r.json()

def github_find_release_by_tag(owner: str, repo: str, token: str, tag: str) -> dict | None:
    url = f"https://api.github.com/repos/{owner}/{repo}/releases/tags/{tag}"
    r = requests.get(url, headers=gh_headers(token), timeout=30)
    if r.status_code == 200:
        return r.json()
    return None

def github_upload_asset(upload_url_template: str, filepath: Path, token: str):
    # upload_url template looks like: https://uploads.github.com/repos/owner/repo/releases/ID/assets{?name,label}
    upload_base = upload_url_template.split("{", 1)[0]
    params = {"name": filepath.name}
    with open(filepath, "rb") as f:
        r = requests.post(
            upload_base,
            headers={
                **gh_headers(token),
                "Content-Type": "application/octet-stream"
            },
            params=params,
            data=f,
            timeout=120
        )
    if r.status_code not in (200, 201):
        raise RuntimeError(f"Upload asset failed for {filepath.name}: {r.status_code} {r.text}")
    return r.json()

def _platform_credential_helper() -> str:
    import sys
    if sys.platform.startswith("win"):
        return "manager-core"   # Git Credential Manager
    if sys.platform == "darwin":
        return "osxkeychain"    # macOS keychain
    return "libsecret"          # GNOME Keyring / libsecret

def ensure_git_credential_helper(path: str, helper: str | None = None):
    """Ensure a credential helper is configured for this repo."""
    helper = helper or _platform_credential_helper()
    try:
        current = run_git(path, "config", "--get", "credential.helper").strip()
        if current:
            return  # already set (don't override)
    except Exception:
        pass
    # set helper locally for the repo
    run_git(path, "config", "credential.helper", helper)

def git_store_github_pat(path: str, username: str, token: str):
    """
    Store PAT in OS keychain via 'git credential approve' for https://github.com.
    Requires a credential helper (manager-core/osxkeychain/libsecret).
    """
    import subprocess
    ensure_git_credential_helper(path)
    payload = "protocol=https\nhost=github.com\nusername={u}\npassword={p}\n\n".format(u=username, p=token)
    p = subprocess.run(
        ["git", "credential", "approve"],
        cwd=path, text=True, input=payload,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    if p.returncode != 0:
        raise RuntimeError(f"git credential approve failed:\n{(p.stderr or p.stdout).strip()}")




def slugify_repo_name(name: str) -> str:
    name = name.strip().lower()
    name = re.sub(r"[^a-z0-9._-]+", "-", name)   # keep letters, digits, dot, underscore, dash
    name = re.sub(r"-{2,}", "-", name).strip("-")
    return name or "repo"


# ────────────────────────────────────────────────────────────────────────────────
# Release folder utilities
def get_release_dir(repo_path: str, version: str) -> Path:
    return Path(repo_path) / "releases" / version

def open_path(pth: Path):
    try:
        if sys.platform.startswith("win"):
            os.startfile(str(pth))  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.run(["open", str(pth)], check=False)
        else:
            subprocess.run(["xdg-open", str(pth)], check=False)
    except Exception:
        pass

def sync_artifacts_to_release(conn, project_id: int, repo_path: str, version: str) -> tuple[list[str], list[str]]:
    """Copy all artifacts of (project_id, version) into releases/<version>/.
       Returns (copied_files, missing_files)."""
    cur = conn.cursor()
    vrow = cur.execute("SELECT id FROM versions WHERE project_id=? AND version=?", (project_id, version)).fetchone()
    if not vrow: return ([], [])
    arts = cur.execute("SELECT file_path FROM artifacts WHERE version_id=? ORDER BY id", (vrow["id"],)).fetchall()
    rel_dir = get_release_dir(repo_path, version)
    rel_dir.mkdir(parents=True, exist_ok=True)
    copied, missing = [], []
    for a in arts:
        src = Path(a["file_path"])
        if src.exists():
            dst = rel_dir / src.name
            try:
                if src.resolve() != dst.resolve():
                    shutil.copy2(str(src), str(dst))
                copied.append(str(dst))
            except Exception:
                missing.append(str(src))
        else:
            missing.append(str(src))
    return (copied, missing)

def build_release_zip(repo_path: str, project_name: str, version: str) -> Path:
    rel_dir = get_release_dir(repo_path, version)
    rel_dir.mkdir(parents=True, exist_ok=True)
    zip_path = rel_dir / f"{project_name}_{version}_artifacts.zip"
    # Zip all files in the release folder except existing zip(s)
    with ZipFile(str(zip_path), "w", compression=ZIP_DEFLATED) as zf:
        for f in rel_dir.iterdir():
            if f.is_file() and f.suffix.lower() != ".zip":
                zf.write(str(f), arcname=f.name)
    return zip_path

def list_release_files(repo_path: str, version: str) -> list[Path]:
    rel_dir = get_release_dir(repo_path, version)
    if not rel_dir.exists(): return []
    return sorted([p for p in rel_dir.iterdir() if p.is_file()], key=lambda p: (p.suffix.lower(), p.name.lower()))

class GitHubPublishDialog(QDialog):
    def __init__(self, parent=None, default_repo="", remember_token=False, default_store_creds=True):
        super().__init__(parent)
        self.setWindowTitle("Publish to GitHub")
        self.setMinimumWidth(460)

        # Fields
        self.repo_edit = QLineEdit(default_repo)
        self.repo_edit.setPlaceholderText("owner/repo  or  https://github.com/owner/repo")

        self.token_edit = QLineEdit()
        self.token_edit.setEchoMode(QLineEdit.Password)
        self.token_edit.setPlaceholderText("GitHub Personal Access Token (repo scope)")

        self.cb_commit_release = QCheckBox("Commit release folder & changelog before pushing")
        self.cb_commit_release.setChecked(True)

        self.cb_push_all = QCheckBox("Push current branch and tags to origin")
        self.cb_push_all.setChecked(True)

        self.cb_remember = QCheckBox("Remember token (stores in app settings as plain text)")
        self.cb_remember.setChecked(remember_token)

        # NEW: store creds via git credential helper
        self.cb_store_git_creds = QCheckBox("Remember for future pushes (save token to OS keychain)")
        self.cb_store_git_creds.setChecked(bool(default_store_creds))  # ← use preference-driven default

        # Layout
        form = QFormLayout()
        form.addRow("Repository:", self.repo_edit)
        form.addRow("Token:", self.token_edit)
        form.addRow("", self.cb_commit_release)
        form.addRow("", self.cb_push_all)
        form.addRow("", self.cb_remember)
        form.addRow("", self.cb_store_git_creds)   # ← now safe; 'form' exists

        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)

        lay = QVBoxLayout(self)
        lay.addLayout(form)
        lay.addWidget(bb)

    def data(self):
        return {
            "repo": self.repo_edit.text().strip(),
            "token": self.token_edit.text().strip(),
            "commit_release": self.cb_commit_release.isChecked(),
            "push_all": self.cb_push_all.isChecked(),
            "remember": self.cb_remember.isChecked(),
            "store_git_creds": self.cb_store_git_creds.isChecked(),  # NEW
        }


# ────────────────────────────────────────────────────────────────────────────────
class ReleaseWorker(QThread):
    progress = pyqtSignal(int, str)
    error    = pyqtSignal(str)
    done     = pyqtSignal(dict)

    def __init__(self, task: dict):
        super().__init__()
        self.task = task

    def run(self):
        try:
            repo_path = self.task["repo_path"]
            proj_name = self.task["project_name"]

            self.progress.emit(5, "Checking repository…")
            git_init_if_needed(repo_path)
            if not repo_has_commits(repo_path):
                self.progress.emit(10, "No commits found. Creating initial commit…")
                ensure_initial_commit(repo_path, proj_name)
                self.progress.emit(20, "Initial commit created.")

            self.progress.emit(25, "Validating version…")
            version = self.task["version"].strip()
            prefix  = self.task.get("tag_prefix") or DEFAULT_PREFIX
            if prefix and not version.startswith(prefix):
                version = f"{prefix}{version}"
            if self.task.get("enforce_semver", True) and not SEMVER_RE.match(version):
                raise RuntimeError("Version must look like SemVer (e.g., v1.2.3).")

            notes = self.task.get("notes") or f"Release {version}"

            if self.task.get("create_tag", True):
                self.progress.emit(40, f"Creating git tag {version}…")
                create_git_tag(repo_path, version, notes)

            self.progress.emit(55, "Resolving commit metadata…")
            sha      = run_git(repo_path, "rev-list", "-n", "1", version if self.task.get("create_tag", True) else "HEAD").strip()
            date_iso = run_git(repo_path, "show", "-s", "--format=%cI", sha).strip()

            if self.task.get("push", False):
                self.progress.emit(65, "Pushing tags to origin…")
                push_tags(repo_path, "origin")

            # New: ensure release folder exists right away.
            self.progress.emit(75, "Preparing release folder…")
            rel_dir = get_release_dir(repo_path, version)
            rel_dir.mkdir(parents=True, exist_ok=True)

            self.progress.emit(90, "Finalizing…")
            payload = {"version": version, "sha": sha, "date": date_iso, "notes": notes}
            self.progress.emit(100, "Done.")
            self.done.emit(payload)
        except Exception as e:
            self.error.emit(str(e))

# ────────────────────────────────────────────────────────────────────────────────
class AddProjectDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Project")
        self.setMinimumWidth(450)
        self.name_edit = QLineEdit()
        self.path_edit = QLineEdit()
        browse_btn     = QPushButton("Browse…")
        browse_btn.clicked.connect(self.on_browse)
        fl = QFormLayout()
        fl.addRow("Name:", self.name_edit)
        h = QHBoxLayout()
        h.addWidget(self.path_edit); h.addWidget(browse_btn)
        fl.addRow("Folder:", h)
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(self.accept); bb.rejected.connect(self.reject)
        lay = QVBoxLayout(self); lay.addLayout(fl); lay.addWidget(bb)
    def on_browse(self):
        d = QFileDialog.getExistingDirectory(self, "Select Project Folder")
        if d: self.path_edit.setText(d)
    def get_data(self): return self.name_edit.text().strip(), self.path_edit.text().strip()

# ────────────────────────────────────────────────────────────────────────────────
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Code/Version Organizer")
        self.setWindowIcon(self.style().standardIcon(QStyle.SP_ComputerIcon))
        self.resize(1200, 750)
        self.setMinimumSize(1000, 650)


        self.conn = get_conn()
        self._ensure_activity_table()
        self.settings = QSettings("CodeMgr", "DesktopApp")

        self.pref_enforce_semver = self.settings.value("enforce_semver", True, type=bool)
        self.pref_tag_prefix     = self.settings.value("tag_prefix", DEFAULT_PREFIX, type=str)
        self.pref_push           = self.settings.value("push_to_origin", False, type=bool)
        self.pref_store_git_creds_default = self.settings.value("github_store_creds_default", True, type=bool)


        self._build_ui()
        self.load_projects()

    # ── UI ──
    def _build_ui(self):
        splitter = QSplitter(self)
        splitter.setChildrenCollapsible(False)
        self.setCentralWidget(splitter)

        # LEFT: Projects
        left = QWidget()
        lv = QVBoxLayout(left)
        self.project_list = QListWidget()
        self.project_list.setSelectionMode(QAbstractItemView.SingleSelection)
        self.project_list.itemSelectionChanged.connect(self.on_project_selected)
        self._mem_logs = defaultdict(list)   # key: project_id (int or None) → list[str] entries


        btn_row = QHBoxLayout()
        btn_add = QPushButton("Add")
        btn_del = QPushButton("Remove")
        btn_res = QPushButton("Rescan")
        btn_add.clicked.connect(self.add_project)
        btn_del.clicked.connect(self.remove_project)
        btn_res.clicked.connect(self.rescan_versions)
        btn_row.addWidget(btn_add); btn_row.addWidget(btn_del); btn_row.addWidget(btn_res)

        lv.addWidget(QLabel("Projects"))
        lv.addWidget(self.project_list)
        lv.addLayout(btn_row)

        # RIGHT: Versions (top) + Tabs (Release, Artifacts, Release Files, Notes, Activity)
        right = QWidget()
        rv = QVBoxLayout(right)
        rv.setContentsMargins(6, 6, 6, 6)
        rv.setSpacing(8)

        # ── Versions table (compact) ──
        versions_box = QGroupBox("Versions")
        vb = QVBoxLayout(versions_box)
        self.versions_table = QTableWidget(0, 4)
        self.versions_table.setHorizontalHeaderLabels(["Version", "Commit", "Date", "Notes"])
        self.versions_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.versions_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.versions_table.setAlternatingRowColors(True)
        self.versions_table.verticalHeader().setVisible(False)
        self.versions_table.horizontalHeader().setStretchLastSection(True)
        self.versions_table.itemSelectionChanged.connect(self.on_version_selected)
        self.versions_table.setMinimumHeight(180)   # keep it from ballooning
        vb.addWidget(self.versions_table)

        # ── Tabs container ──
        tabs = QTabWidget()
        tabs.setDocumentMode(True)
        tabs.setTabBarAutoHide(False)

        # ===== Release tab =====
        release_tab = QWidget()
        rel_layout = QVBoxLayout(release_tab)
        rel_layout.setContentsMargins(8, 8, 8, 8)
        rel_layout.setSpacing(8)

        release_box = QGroupBox("Create Tag + Release")
        rf = QFormLayout(release_box)
        rf.setLabelAlignment(Qt.AlignLeft)

        self.version_edit = QLineEdit()
        self.version_edit.setPlaceholderText("e.g., 1.2.3 (prefix will be added)")

        self.notes_edit = QTextEdit()
        self.notes_edit.setPlaceholderText("Auto-filled from commits; edit before releasing.")
        self.notes_edit.setMinimumHeight(140)
        self.notes_edit.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)

        self.cb_enforce_semver = QCheckBox("Enforce SemVer (e.g., v1.2.3)")
        self.cb_enforce_semver.setChecked(self.pref_enforce_semver)
        self.cb_push = QCheckBox("Push tags to origin after creating")
        self.cb_push.setChecked(self.pref_push)

        self.prefix_edit = QLineEdit(self.pref_tag_prefix)
        self.prefix_edit.setMaximumWidth(80)

        auto_btn   = QPushButton("Generate Notes from Commits")
        create_btn = QPushButton("Create Tag + Record Release")
        # Prevent “thin line” buttons:
        for b in (auto_btn, create_btn):
            b.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
            b.setMinimumHeight(34)

        auto_btn.clicked.connect(self.autofill_notes)
        create_btn.clicked.connect(self.create_release)

        rf.addRow("Version:", self.version_edit)

        pf = QHBoxLayout()
        pf.addWidget(QLabel("Tag Prefix:"))
        pf.addWidget(self.prefix_edit)
        pf.addStretch(1)
        rf.addRow("", pf)

        rf.addRow("Notes:", self.notes_edit)
        rf.addRow("", self.cb_enforce_semver)
        rf.addRow("", self.cb_push)

        btn_row_release = QHBoxLayout()
        btn_row_release.addWidget(auto_btn)
        btn_row_release.addStretch(1)
        btn_row_release.addWidget(create_btn)
        rf.addRow("", btn_row_release)

        rel_layout.addWidget(release_box, 1)
        tabs.addTab(release_tab, "Release")

        # ===== Artifacts tab =====
        artifacts_tab = QWidget()
        ab_layout = QVBoxLayout(artifacts_tab)

        artifacts_box = QGroupBox("Artifacts (drag files here)")
        ab = QVBoxLayout(artifacts_box)
        self.artifacts_list = QListWidget()
        self.artifacts_list.setSelectionMode(QAbstractItemView.SingleSelection)
        self.artifacts_list.setAcceptDrops(True)
        self.artifacts_list.dragEnterEvent = self._artifacts_drag_enter  # type: ignore
        self.artifacts_list.dropEvent      = self._artifacts_drop        # type: ignore
        self.artifacts_list.itemDoubleClicked.connect(self.open_selected_artifact)
        self.artifacts_list.setMinimumHeight(160)
        ab.addWidget(self.artifacts_list)

        art_btns = QHBoxLayout()
        btn_add_art = QPushButton("Add File…")
        btn_rm_art  = QPushButton("Remove")
        btn_open_art = QPushButton("Open")
        btn_open_art_folder = QPushButton("Open Folder")
        for b in (btn_add_art, btn_rm_art, btn_open_art, btn_open_art_folder):
            b.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
            b.setMinimumHeight(30)
        btn_add_art.clicked.connect(self.add_artifact_file)
        btn_rm_art.clicked.connect(self.remove_artifact)
        btn_open_art.clicked.connect(self.open_selected_artifact)
        btn_open_art_folder.clicked.connect(self.open_selected_artifact_folder)
        art_btns.addWidget(btn_add_art); art_btns.addWidget(btn_rm_art)
        art_btns.addWidget(btn_open_art); art_btns.addWidget(btn_open_art_folder); art_btns.addStretch(1)
        ab.addLayout(art_btns)

        ab_layout.addWidget(artifacts_box, 1)
        tabs.addTab(artifacts_tab, "Artifacts")

        # ===== Release Files tab =====
        relfiles_tab = QWidget()
        rlf_layout = QVBoxLayout(relfiles_tab)

        rel_box = QGroupBox("Release Folder (version files & ZIP)")
        rlb = QVBoxLayout(rel_box)

        self.release_files_list = QListWidget()
        self.release_files_list.setSelectionMode(QAbstractItemView.SingleSelection)
        self.release_files_list.itemDoubleClicked.connect(self.open_selected_release_file)
        self.release_files_list.setMinimumHeight(160)
        rlb.addWidget(self.release_files_list)

        rel_btns = QHBoxLayout()
        btn_sync = QPushButton("Sync Artifacts → Release Folder")
        btn_zip  = QPushButton("Create/Update Release ZIP")
        btn_open_rel = QPushButton("Open Release Folder")
        btn_open_rel_file = QPushButton("Open Selected")
        btn_publish = QPushButton("Publish to GitHub")
        # NEW: open release page
        btn_open_release_page = QPushButton("Open GitHub Release")

        for b in (btn_sync, btn_zip, btn_open_rel, btn_open_rel_file, btn_publish, btn_open_release_page):
            b.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
            b.setMinimumHeight(30)

        btn_sync.clicked.connect(self.sync_release_folder)
        btn_zip.clicked.connect(self.create_release_zip)
        btn_open_rel.clicked.connect(self.open_release_folder)
        btn_open_rel_file.clicked.connect(self.open_selected_release_file)
        btn_publish.clicked.connect(self.publish_to_github)
        # NEW: connect handler
        btn_open_release_page.clicked.connect(self.open_github_release)

        rel_btns.addWidget(btn_sync)
        rel_btns.addWidget(btn_zip)
        rel_btns.addWidget(btn_open_rel)
        rel_btns.addWidget(btn_open_rel_file)
        rel_btns.addWidget(btn_publish)
        rel_btns.addWidget(btn_open_release_page)   # ← NEW
        rel_btns.addStretch(1)

        rlb.addLayout(rel_btns)

        rlf_layout.addWidget(rel_box, 1)
        tabs.addTab(relfiles_tab, "Release Files")



        # ===== Notes tab (edit existing) =====
        notes_tab = QWidget()
        nt_layout = QVBoxLayout(notes_tab)

        notes_box = QGroupBox("Notes for Selected Release")
        nb = QVBoxLayout(notes_box)
        self.selected_notes_edit = QTextEdit()
        self.selected_notes_edit.setMinimumHeight(160)
        self.selected_notes_edit.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)

        btn_save_notes = QPushButton("Save Notes")
        btn_save_notes.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        btn_save_notes.setMinimumHeight(30)
        btn_save_notes.clicked.connect(self.save_selected_notes)
        nb.addWidget(self.selected_notes_edit, 1)
        nb.addWidget(btn_save_notes, 0, Qt.AlignRight)

        nt_layout.addWidget(notes_box, 1)
        tabs.addTab(notes_tab, "Notes")

        # ===== Activity tab =====
        activity_tab = QWidget()
        act_layout = QVBoxLayout(activity_tab)
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setMinimumHeight(140)
        self.log.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        act_layout.addWidget(QLabel("Activity"))
        act_layout.addWidget(self.progress)
        act_layout.addWidget(self.log, 1)
        tabs.addTab(activity_tab, "Activity")

        # Add top group + tabs to the right pane
        rv.addWidget(versions_box, 0)   # stays compact
        rv.addWidget(tabs, 1)           # tabs take remaining space

        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setSizes([400, 980])
        splitter.setStretchFactor(1, 1)

        # Menu: Preferences
        pref_act = QAction("Preferences…", self)
        pref_act.triggered.connect(self.open_prefs)
        menubar = self.menuBar()
        app_menu = menubar.addMenu("&App")
        app_menu.addAction(pref_act)

    def _reset_release_ui(self):
        """Clear release-related fields so a new/other project doesn't inherit previous state."""
        # inputs
        self.version_edit.clear()
        self.notes_edit.clear()
        self.selected_notes_edit.clear()

        # lists
        self.artifacts_list.clear()
        self.release_files_list.clear()

        # tables / selection
        self.versions_table.clearSelection()

        # progress/log visuals (optional: keep per-project logs if you implemented that)
        self.progress.setValue(0)


    def _select_version_in_table(self, version: str):
        # Column 0 is "Version" per your setup
        for r in range(self.versions_table.rowCount()):
            it = self.versions_table.item(r, 0)
            if it and it.text() == version:
                self.versions_table.selectRow(r)
                self.versions_table.scrollToItem(it)
                break


    def load_activity_for_current_project(self, limit: int = 500):
        """Load the latest activity for the selected project into the Activity panel."""
        self.log.clear()
        proj = self.current_project()
        if not proj:
            self.log.append("No project selected.")
            return

        cur = self.conn.cursor()
        rows = cur.execute(
            "SELECT ts, message FROM activity WHERE project_id=? ORDER BY id DESC LIMIT ?",
            (proj["id"], limit)
        ).fetchall()

        # Show newest at bottom (reverse the DESC fetch)
        for ts, msg in reversed(rows):
            self.log.append(f"[{ts}] {msg}")


    def _ensure_activity_table(self):
        cur = self.conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS activity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER,
                ts TEXT NOT NULL,
                level TEXT,
                message TEXT NOT NULL
            )
        """)
        self.conn.commit()


    # ── Helpers: current selections ──
    def current_project_row(self):
        items = self.project_list.selectedItems()
        return items[0] if items else None

    def current_project(self):
        item = self.current_project_row()
        return item.data(Qt.UserRole) if item else None

    def selected_version_text(self) -> str | None:
        sels = self.versions_table.selectedItems()
        if not sels:
            if self.versions_table.rowCount() > 0:
                return self.versions_table.item(0, 0).text()
            return None
        row = sels[0].row()
        return self.versions_table.item(row, 0).text()

    # ── Load/refresh UI ──
    def load_projects(self):
        self.project_list.clear()
        cur = self.conn.cursor()
        rows = cur.execute("SELECT id, name, path FROM projects ORDER BY name").fetchall()
        for r in rows:
            item = QListWidgetItem(f"{r['name']}\n{r['path']}")
            item.setData(Qt.UserRole, {"id": r["id"], "name": r["name"], "path": r["path"]})
            item.setToolTip(r["path"])
            self.project_list.addItem(item)
        if self.project_list.count() > 0:
            self.project_list.setCurrentRow(0)

    def on_project_selected(self):
        self._reset_release_ui()  
        self.refresh_versions()
        self.refresh_artifacts()
        self.refresh_release_files()
        self.load_selected_notes()
        self.load_activity_for_current_project()
        self.refresh_activity_panel() 

    def on_version_selected(self):
        # Always refresh the right-hand panes
        self.refresh_artifacts()
        self.refresh_release_files()

        # Guard: nothing selected → clear notes panel
        items = self.versions_table.selectedItems()
        if not items:
            self.selected_notes_edit.clear()
            return

        # Grab selected version
        version = self.selected_version_text()
        if not version:
            self.selected_notes_edit.clear()
            return

        # Load notes for THIS project's selected version
        proj = self.current_project()
        if not proj:
            self.selected_notes_edit.clear()
            return

        cur = self.conn.cursor()
        row = cur.execute(
            "SELECT notes FROM versions WHERE project_id=? AND version=?",
            (proj["id"], version)
        ).fetchone()
        self.selected_notes_edit.setPlainText((row["notes"] or "") if row else "")


    def refresh_versions(self):
        self.versions_table.setRowCount(0)
        proj = self.current_project()
        if not proj:
            return
        cur = self.conn.cursor()
        rows = cur.execute(
            "SELECT id, version, commit_sha, commit_date, notes FROM versions WHERE project_id=? ORDER BY commit_date DESC",
            (proj["id"],)
        ).fetchall()
        self.versions_table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            self.versions_table.setItem(i, 0, QTableWidgetItem(r["version"]))
            self.versions_table.setItem(i, 1, QTableWidgetItem(r["commit_sha"][:10]))
            self.versions_table.setItem(i, 2, QTableWidgetItem(r["commit_date"]))
            self.versions_table.setItem(i, 3, QTableWidgetItem(r["notes"] or ""))

    def refresh_artifacts(self):
        self.artifacts_list.clear()
        proj = self.current_project()
        if not proj: return
        v = self.selected_version_text()
        if not v: return
        cur = self.conn.cursor()
        ver = cur.execute("SELECT id FROM versions WHERE project_id=? AND version=?", (proj["id"], v)).fetchone()
        if not ver: return
        arts = cur.execute("SELECT id, label, file_path FROM artifacts WHERE version_id=? ORDER BY id", (ver["id"],)).fetchall()
        for a in arts:
            disp = f"{a['label']}  —  {a['file_path']}"
            item = QListWidgetItem(disp)
            item.setData(Qt.UserRole, {"id": a["id"], "label": a["label"], "file": a["file_path"]})
            self.artifacts_list.addItem(item)

    def refresh_release_files(self):
        self.release_files_list.clear()
        proj = self.current_project()
        if not proj: return
        v = self.selected_version_text()
        if not v: return
        for p in list_release_files(proj["path"], v):
            item = QListWidgetItem(p.name)
            item.setToolTip(str(p))
            item.setData(Qt.UserRole, str(p))
            self.release_files_list.addItem(item)

    def publish_to_github(self):
        """Publish the selected version to GitHub:
        - ensure repo/init + identity + initial commit
        - ensure release folder + zip
        - optionally commit release folder & changelog (only if changed)
        - push branch + tags (with seamless auth; can store creds)
        - create/find GitHub release and upload assets
        - open release page in browser
        - auto-create the GitHub repo if missing (org fallback handled)
        """
        proj = self.current_project()
        if not proj:
            show_error(self, "No Project", "Select a project first.")
            return
        version = self.selected_version_text()
        if not version:
            show_error(self, "No Version", "Select a version to publish.")
            return

        # NEW: Require Git to be installed / available on PATH
        if not is_git_available():
            show_error(
                self,
                "Git Required",
                "Git is not installed or not on PATH.\n\n"
                "Install Git first (Preferences → Install Git…) and try again."
            )
            return


        # Read notes (body) for GitHub release
        cur = self.conn.cursor()
        row = cur.execute(
            "SELECT notes FROM versions WHERE project_id=? AND version=?",
            (proj["id"], version)
        ).fetchone()
        body = (row["notes"] or "").strip() if row else ""
        title = f"{proj['name']} {version}"
        tag = version

        # === Defaults (per-project) ===
        proj = self.current_project()
        proj_key = f"github_repo::{proj['path']}"  # per-project storage key

        default_repo_global = self.settings.value("github_repo", "", type=str)  # legacy/global (may include owner/repo)
        default_repo_perproj = self.settings.value(proj_key, "", type=str)

        # Derive an owner prefix from legacy/global setting if present (e.g., "kristodev-tech/")
        owner_prefix = ""
        if default_repo_global and "/" in default_repo_global:
            owner_prefix = default_repo_global.split("/")[0].strip() + "/"

        # Prefer per-project value; otherwise suggest just owner prefix (no leaking old repo names)
        default_repo = default_repo_perproj or owner_prefix

        remember_token = self.settings.value("github_remember_token", False, type=bool)
        saved_token = self.settings.value("github_token", "", type=str) if remember_token else ""

        # === Dialog ===
        dlg = GitHubPublishDialog(
            self,
            default_repo=default_repo,
            remember_token=remember_token,
            default_store_creds=self.pref_store_git_creds_default  # from Preferences
        )
        if saved_token:
            dlg.token_edit.setText(saved_token)
        if dlg.exec_() != QDialog.Accepted:
            return
        data = dlg.data()

        # If user entered only "owner/" (no repo name), auto-fill with a slug from the project name
        repo_field = data["repo"].strip()
        auto_filled = False
        if repo_field.endswith("/") and "/" in repo_field:
            owner = repo_field.split("/")[0].strip()
            suggested = slugify_repo_name(proj["name"])
            repo_field = f"{owner}/{suggested}"
            data["repo"] = repo_field
            auto_filled = True
            # (3) Show the auto-filled repo back to the user in Activity
            self.log_append(f"ℹ️ Auto-suggested GitHub repository: {data['repo']}")

        # === Persist (per-project + legacy + defaults) ===
        self.settings.setValue(proj_key, data["repo"])           # per-project repo (correct for each project)
        self.settings.setValue("github_repo", data["repo"])      # keep legacy in sync (optional)
        self.settings.setValue("github_remember_token", data["remember"])
        if data["remember"]:
            self.settings.setValue("github_token", data["token"])
        else:
            self.settings.remove("github_token")

        # Keep “store creds” default aligned with latest choice
        self.settings.setValue("github_store_creds_default", data.get("store_git_creds", True))
        self.pref_store_git_creds_default = data.get("store_git_creds", True)


        # Parse owner/repo
        try:
            owner, repo = parse_owner_repo(data["repo"])
        except Exception as e:
            show_error(self, "Bad Repository", str(e))
            return

        token = data["token"].strip()
        if not token:
            show_error(self, "Missing Token", "Please enter a GitHub Personal Access Token with 'repo' scope.")
            return

        try:
            # ── A) Ensure local Git is ready (repo, identity, initial commit)
            try:
                git_init_if_needed(proj["path"])
            except Exception as e:
                show_error(self, "Git Init Failed", str(e))
                return

            def _ensure_identity():
                try:
                    _ = run_git(proj["path"], "config", "--get", "user.name").strip()
                except Exception:
                    run_git(proj["path"], "config", "user.name", "Code Manager")
                try:
                    _ = run_git(proj["path"], "config", "--get", "user.email").strip()
                except Exception:
                    run_git(proj["path"], "config", "user.email", "msepro.software@gmail.com")
            _ensure_identity()

            if not repo_has_commits(proj["path"]):
                self.log_append("ℹ️ No commits found; creating initial commit…")
                ensure_initial_commit(proj["path"], proj["name"])
                self.log_append("✅ Initial commit created.")

            # ── B) Ensure the remote repository exists / create if needed (handles 422 + org fallback)
            res = QMessageBox.question(
                self,
                "Create GitHub Repository?",
                f"If '{owner}/{repo}' does not exist, create it now as a PRIVATE repo?\n\n"
                "Yes = Private   ·   No = Public",
                QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel,
                QMessageBox.Yes
            )
            if res == QMessageBox.Cancel:
                return
            make_private = (res == QMessageBox.Yes)

            try:
                owner, repo = ensure_remote_repo_exists(owner, repo, token, make_private, log_fn=self.log_append)
            except Exception as e:
                show_error(self, "Create Repo Failed", str(e))
                self.log_append("❌ " + str(e))
                return

            # Attach origin remote now that the repo exists
            origin_https = f"https://github.com/{owner}/{repo}.git"
            git_set_remote_origin_if_missing(proj["path"], origin_https)

            # ── C) Ensure release folder + ZIP
            self.sync_release_folder()
            zip_path = build_release_zip(proj["path"], proj["name"], version)
            self.log_append(f"📦 ZIP ready: {zip_path}")

            # ── D) Optionally commit the release folder/changelog (only if changed)
            if data["commit_release"]:
                committed = ensure_commit_release_folder(
                    proj["path"], version, proj["name"], log_fn=self.log_append
                )
                if committed:
                    self.log_append("✅ Committed release folder to git.")
                else:
                    self.log_append("ℹ️ Release folder already up to date; no commit needed.")

            # ── E) (Optional) Store PAT in OS keychain via git credential helper
            if data.get("store_git_creds"):
                try:
                    me = github_get_user(token)
                    gh_user = (me.get("login") or "").strip()
                    if not gh_user:
                        raise RuntimeError("Could not resolve GitHub username from token.")
                    ensure_git_credential_helper(proj["path"])          # sets manager-core/osxkeychain/libsecret
                    git_store_github_pat(proj["path"], gh_user, token)  # store creds for https://github.com
                    self.log_append("🔐 Stored GitHub credentials in OS keychain for future pushes.")
                except Exception as cred_err:
                    self.log_append(f"⚠️ Could not store credentials: {cred_err}")

            # ── F) Push branch + tags (seamless; retry with token URL if needed)
            if data["push_all"]:
                try:
                    # Pre-publish sanity logging
                    self.log_append("🔎 Pre-publish sanity check:")
                    try:
                        repo_root = run_git(proj["path"], "rev-parse", "--show-toplevel").strip()
                        self.log_append(f"• repo root: {repo_root}")
                    except Exception:
                        self.log_append("• repo root: (unknown)")

                    try:
                        branch = run_git(proj["path"], "rev-parse", "--abbrev-ref", "HEAD").strip()
                        self.log_append(f"• branch: {branch}")
                    except Exception:
                        self.log_append("• branch: (unknown)")

                    try:
                        origin_url = run_git(proj["path"], "remote", "get-url", "origin").strip()
                        self.log_append(f"• origin: {origin_url}")
                    except Exception:
                        self.log_append("• origin: (none)")

                    # Ensure correct origin before pushing
                    ensure_correct_origin(proj["path"], owner, repo)

                    # First push attempt
                    git_push_all(proj["path"])
                    self.log_append("✅ Pushed branch and tags to origin.")

                except Exception as push_err:
                    err_txt = str(push_err)
                    if any(k in err_txt for k in ["401", "Unauthorized", "could not read Username", "failed to execute prompt script"]):
                        try:
                            me = github_get_user(token)
                            gh_user = (me.get("login") or "").strip()
                            if not gh_user:
                                raise RuntimeError("Could not resolve GitHub username from token.")
                            branch = git_current_branch(proj["path"])
                            git_push_all_token(proj["path"], owner, repo, gh_user, token, branch)
                            self.log_append("✅ Pushed branch and tags using token-auth URL (one-off).")
                        except Exception as e2:
                            raise RuntimeError(f"Initial push failed:\n{err_txt}\n\nToken retry failed:\n{e2}") from e2
                    else:
                        raise


            # ── G) Create or reuse GitHub Release
            rel = github_find_release_by_tag(owner, repo, token, tag)
            if rel:
                upload_url = rel.get("upload_url")
                self.log_append(f"ℹ️ GitHub release already exists for {tag} (id={rel.get('id')}).")
            else:
                rel = github_create_release(owner, repo, token, tag, title, body)
                upload_url = rel.get("upload_url")
                self.log_append(f"✅ Created GitHub release: {title}")

            if not upload_url:
                raise RuntimeError("No upload URL returned by GitHub release API.")

            # ── H) Upload assets from releases/<version>
            uploaded = []
            for p in list_release_files(proj["path"], version):
                try:
                    github_upload_asset(upload_url, p, token)
                    uploaded.append(p.name)
                except Exception as e:
                    self.log_append(f"⚠️ Failed to upload {p.name}: {e}")

            if uploaded:
                self.log_append("📤 Uploaded assets:\n  " + "\n  ".join(uploaded))
            else:
                self.log_append("ℹ️ No files found to upload in the release folder.")

            # ── I) Open release page
            self.open_github_release()

            show_info(self, "Published", f"Published {version} to GitHub with {len(uploaded)} asset(s).")

        except Exception as e:
            show_error(self, "Publish Failed", f"{e.__class__.__name__}: {e}")
            self.log_append("❌ " + str(e))


    def open_github_release(self):
        proj = self.current_project()
        if not proj:
            show_error(self, "No Project", "Select a project first.")
            return
        tag = self.selected_version_text()
        if not tag:
            show_error(self, "No Version", "Select a version to open.")
            return

        # 1) Prefer explicit repo from settings (set during Publish dialog)
        repo_hint = self.settings.value("github_repo", "", type=str).strip()
        owner = repo = None
        if repo_hint:
            try:
                owner, repo = parse_owner_repo(repo_hint)
            except Exception:
                owner = repo = None

        # 2) Fallback: parse from `origin` remote
        if not owner or not repo:
            try:
                origin_url = run_git(proj["path"], "remote", "get-url", "origin").strip()
                parsed = parse_owner_repo_from_origin_url(origin_url)
                if parsed:
                    owner, repo = parsed
            except Exception:
                pass

        if not owner or not repo:
            show_error(self, "GitHub Repo Unknown",
                    "I couldn't determine the GitHub repository.\n"
                    "Use 'Publish to GitHub' once, or set the origin remote.")
            return

        url = f"https://github.com/{owner}/{repo}/releases/tag/{tag}"
        # Open in default browser
        try:
            webbrowser.open(url)
            self.log_append(f"🌐 Opened: {url}")
        except Exception as e:
            show_error(self, "Open Failed", str(e))
            self.log_append("❌ " + str(e))


    def load_selected_notes(self):
        proj = self.current_project()
        if not proj:
            self.selected_notes_edit.clear()
            return
        v = self.selected_version_text()
        if not v:
            self.selected_notes_edit.clear()
            return
        cur = self.conn.cursor()
        r = cur.execute("SELECT notes FROM versions WHERE project_id=? AND version=?", (proj["id"], v)).fetchone()
        self.selected_notes_edit.setText(r["notes"] if r and r["notes"] else "")

    # ── Project actions ──
    def add_project(self):
        dlg = AddProjectDialog(self)
        if dlg.exec_() != QDialog.Accepted:
            return
        name, path = dlg.get_data()
        if not name or not path:
            show_error(self, "Missing Info", "Please provide both a name and a folder."); return
        p = Path(path).resolve()
        if not p.exists() or not p.is_dir():
            show_error(self, "Invalid Folder", "Please choose an existing folder."); return
        try:
            cur = self.conn.cursor()
            cur.execute("INSERT INTO projects(name, path) VALUES(?,?)", (name, str(p)))
            self.conn.commit()
            self._reset_release_ui()
            self.refresh_versions()

        except sqlite3.IntegrityError:
            show_error(self, "Duplicate", "A project with that name already exists."); return
        try:
            if not is_git_repo(str(p)):
                if QMessageBox.question(self, "Initialize Git?",
                    f"'{name}' is not a Git repo. Initialize it now?") == QMessageBox.Yes:
                    run_git(str(p), "init")
                    self.log_append(f"✅ Initialized Git in {p}")
            if not repo_has_commits(str(p)):
                if QMessageBox.question(self, "Make Initial Commit?",
                    "No commits found. Create a README and make the initial commit now?") == QMessageBox.Yes:
                    ensure_initial_commit(str(p), name)
                    self.log_append("✅ Initial commit created.")
        except Exception as e:
            self.log_append("⚠️ Git setup warning: " + str(e))
        self.log_append(f"✅ Project added: {name} -> {p}")
        self.load_projects()

    def remove_project(self):
        proj = self.current_project()
        if not proj: return
        if QMessageBox.question(self, "Remove Project",
                f"Remove '{proj['name']}' from the catalog? (This won't delete files)") != QMessageBox.Yes:
            return
        cur = self.conn.cursor()
        cur.execute("DELETE FROM projects WHERE id=?", (proj["id"],))
        self.conn.commit()
        self.log_append(f"🗑️ Removed project: {proj['name']}")
        self.load_projects()

    def rescan_versions(self):
        proj = self.current_project()
        if not proj: return
        try:
            git_init_if_needed(proj["path"])
            if not repo_has_commits(proj["path"]):
                self.log_append("ℹ️ No commits yet; nothing to scan. (Create a release to auto-commit.)")
                return
            self.log_append("🔎 Scanning tags…")
            tags = get_tags_with_meta(proj["path"])
            added = 0
            cur = self.conn.cursor()
            for t in tags:
                if not SEMVER_RE.match(t["tag"]): continue
                cur.execute(
                    "INSERT OR IGNORE INTO versions(project_id, version, commit_sha, commit_date) VALUES(?,?,?,?)",
                    (proj["id"], t["tag"], t["sha"], t["date"])
                )
                if cur.rowcount: added += 1
            self.conn.commit()
            self.log_append(f"✅ Scan complete. Tags indexed: {added}")
            self.refresh_versions(); self.refresh_artifacts(); self.refresh_release_files()
        except Exception as e:
            show_error(self, "Scan Failed", str(e)); self.log_append("❌ " + str(e))

    # ── Notes + Release ──
    def autofill_notes(self):
        proj = self.current_project()
        if not proj: return show_error(self, "No Project", "Select a project first.")
        try:
            git_init_if_needed(proj["path"])
            if not repo_has_commits(proj["path"]):
                if QMessageBox.question(self, "No Commits",
                    "This repo has no commits yet. Create an initial commit now?") == QMessageBox.Yes:
                    ensure_initial_commit(proj["path"], proj["name"])
                    self.log_append("✅ Initial commit created.")
                else:
                    self.notes_edit.setText("# Release Notes\n\n_Initial note draft_\n")
                    self.log_append("ℹ️ Notes drafted without commits."); return
            last = get_last_tag(proj["path"])
            self.notes_edit.setText(make_release_notes_from_range(proj["path"], last))
            self.log_append(f"📝 Release notes generated (since {last or 'beginning'}).")
        except Exception as e:
            show_error(self, "Notes Error", str(e)); self.log_append("❌ " + str(e))

    # ── Release flow ──
    def create_release(self):
        proj = self.current_project()
        if not proj:
            return show_error(self, "No Project", "Select a project first.")

        version_in = self.version_edit.text().strip()
        if not version_in:
            return show_error(self, "Missing Version", "Enter a version (e.g., 1.2.3).")

        notes   = self.notes_edit.toPlainText().strip()
        enforce = self.cb_enforce_semver.isChecked()
        prefix  = self.prefix_edit.text().strip() or DEFAULT_PREFIX
        push    = self.cb_push.isChecked()

        # Save prefs
        self.settings.setValue("enforce_semver", enforce)
        self.settings.setValue("tag_prefix",      prefix)
        self.settings.setValue("push_to_origin",  push)

        # Pre-check repo & commits
        try:
            git_init_if_needed(proj["path"])
            if not repo_has_commits(proj["path"]):
                self.log_append("ℹ️ No commits found; creating initial commit…")
                ensure_initial_commit(proj["path"], proj["name"])
                self.log_append("✅ Initial commit created.")
        except Exception as e:
            show_error(self, "Git Setup Failed", str(e))
            self.log_append("❌ " + str(e))
            return

        # Normalize version with prefix if enforcing semver/prefix
        version = version_in if version_in.startswith(prefix) else f"{prefix}{version_in}"

        # If user asked to push but there's no origin yet, skip push (avoid fatal error)
        if push and not git_remote_exists(proj["path"], "origin"):
            self.log_append("ℹ️ No 'origin' remote; tags will not be pushed. "
                            "Use 'Publish to GitHub' to create a remote and push.")
            push = False  # override for this task

        task = {
            "repo_path":     proj["path"],
            "project_id":    proj["id"],
            "project_name":  proj["name"],
            "version":       version,
            "notes":         notes,
            "create_tag":    True,
            "push":          push,
            "enforce_semver": enforce,
            "tag_prefix":    prefix,
        }

        self.worker = ReleaseWorker(task)
        self.worker.progress.connect(self.on_progress)
        self.worker.error.connect(self.on_release_error)
        self.worker.done.connect(self.on_release_done)

        self.progress.setValue(0)
        self.log_append(f"🚀 Releasing {version} …")
        self.worker.start()


    def on_progress(self, pct, msg):
        self.progress.setValue(pct)
        self.log_append(msg)


    def on_release_error(self, err):
        self.progress.setValue(0)
        show_error(self, "Release Failed", err)
        self.log_append("❌ " + err)


    def on_release_done(self, payload: dict):
        proj = self.current_project()
        if not proj:
            return

        # Record/Update DB
        cur = self.conn.cursor()
        cur.execute(
            "INSERT OR REPLACE INTO versions(project_id, version, commit_sha, commit_date, notes) "
            "VALUES(?,?,?,?,?)",
            (
                proj["id"],
                payload["version"],
                payload["sha"],
                payload["date"],
                payload.get("notes") or ""
            )
        )
        self.conn.commit()

        self.log_append(f"✅ Release recorded: {payload['version']}  {payload['sha'][:10]}")

        # Refresh Versions UI immediately and select the new row
        self.refresh_versions()
        self._select_version_in_table(payload["version"])

        # Sync artifacts into release folder now (so files list is up to date)
        self.sync_release_folder()

        self.progress.setValue(100)


    # ── Artifact actions ──
    def _artifacts_drag_enter(self, e):
        if e.mimeData().hasUrls(): e.acceptProposedAction()

    def _artifacts_drop(self, e):
        urls = e.mimeData().urls()
        files = [u.toLocalFile() for u in urls if u.isLocalFile()]
        if files:
            for f in files: self._add_artifact(f, label=os.path.basename(f))
            self.refresh_artifacts()
            # Optional: keep release folder synced when user adds artifacts
            self.sync_release_folder()

    def add_artifact_file(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select artifact files")
        for f in files:
            self._add_artifact(f, label=os.path.basename(f))
        if files:
            self.refresh_artifacts()
            self.sync_release_folder()

    def _add_artifact(self, fpath: str, label: str):
        proj = self.current_project()
        if not proj: return show_error(self, "No Project", "Select a project first.")
        version = self.selected_version_text()
        if not version: return show_error(self, "No Version", "Select or create a version first.")
        cur = self.conn.cursor()
        ver = cur.execute("SELECT id FROM versions WHERE project_id=? AND version=?", (proj["id"], version)).fetchone()
        if not ver: return show_error(self, "Unknown Version", "Version record not found.")
        f = Path(fpath).resolve()
        if not f.exists(): return show_error(self, "Missing File", f"File not found:\n{f}")
        cur.execute("INSERT INTO artifacts(version_id, label, file_path) VALUES(?,?,?)", (ver["id"], label, str(f)))
        self.conn.commit()
        self.log_append(f"📎 Artifact added: {label} -> {f}")

    def remove_artifact(self):
        sel = self.artifacts_list.currentItem()
        if not sel: return
        data = sel.data(Qt.UserRole)
        if not data: return
        if QMessageBox.question(self, "Remove Artifact", f"Remove '{data['label']}'?") != QMessageBox.Yes:
            return
        cur = self.conn.cursor()
        cur.execute("DELETE FROM artifacts WHERE id=?", (data["id"],))
        self.conn.commit()
        self.refresh_artifacts()
        self.log_append(f"🗑️ Artifact removed: {data['label']}")
        self.sync_release_folder()

    def open_selected_artifact(self):
        sel = self.artifacts_list.currentItem()
        if not sel: return
        data = sel.data(Qt.UserRole); 
        if not data: return
        path = Path(data["file"])
        if path.exists(): open_path(path)
        else: show_error(self, "Missing File", f"File not found:\n{path}")

    def open_selected_artifact_folder(self):
        sel = self.artifacts_list.currentItem()
        if not sel: return
        data = sel.data(Qt.UserRole)
        if not data: return
        path = Path(data["file"]).parent
        if path.exists(): open_path(path)
        else: show_error(self, "Missing Folder", f"Folder not found:\n{path}")

    # ── Release folder actions ──
    def sync_release_folder(self):
        proj = self.current_project()
        if not proj: return
        version = self.selected_version_text()
        if not version: return
        copied, missing = sync_artifacts_to_release(self.conn, proj["id"], proj["path"], version)
        if copied: self.log_append("📥 Synced to release folder:\n  " + "\n  ".join(copied))
        if missing: self.log_append("⚠️ Missing (not copied):\n  " + "\n  ".join(missing))
        self.refresh_release_files()

    def create_release_zip(self):
        proj = self.current_project()
        if not proj: return
        version = self.selected_version_text()
        if not version: return
        # Ensure folder has latest artifacts first
        self.sync_release_folder()
        zip_path = build_release_zip(proj["path"], proj["name"], version)
        self.log_append(f"📦 Release ZIP created/updated: {zip_path}")
        self.refresh_release_files()
        show_info(self, "ZIP Ready", f"ZIP is available here:\n{zip_path}")

    def open_release_folder(self):
        proj = self.current_project()
        if not proj: return
        version = self.selected_version_text()
        if not version: return
        open_path(get_release_dir(proj["path"], version))

    def open_selected_release_file(self):
        sel = self.release_files_list.currentItem()
        if not sel: return
        p = Path(sel.data(Qt.UserRole))
        if p.exists(): open_path(p)
        else: show_error(self, "Missing File", f"File not found:\n{p}")

    # ── Export ──
    def export_changelog(self):
        proj = self.current_project()
        if not proj: return show_error(self, "No Project", "Select a project.")
        version = self.selected_version_text()
        if not version: return show_error(self, "No Version", "Select a version.")
        cur = self.conn.cursor()
        row = cur.execute(
            "SELECT commit_sha, commit_date, notes FROM versions WHERE project_id=? AND version=?",
            (proj["id"], version)
        ).fetchone()
        if not row: return show_error(self, "Not Found", "Version not found.")
        text = self._render_markdown_release(proj["name"], version, row["commit_sha"], row["commit_date"], row["notes"])
        # Offer to save either outside OR directly into release folder
        default_path = get_release_dir(proj["path"], version) / f"{proj['name']}_{version}.md"
        out, _ = QFileDialog.getSaveFileName(self, "Save Changelog", str(default_path), "Markdown (*.md)")
        if not out: return
        Path(out).write_text(text, encoding="utf-8")
        self.log_append(f"📤 Changelog saved: {out}")
        self.refresh_release_files()
        show_info(self, "Saved", f"Changelog saved to:\n{out}")

    def _render_markdown_release(self, project_name, version, sha, date_iso, notes):
        md = [
            f"# {project_name} {version}",
            "",
            f"- **Commit:** `{sha}`",
            f"- **Date:** {date_iso}",
            "",
            "## Notes",
            "",
            notes.strip() if notes.strip() else "_No notes_",
            "",
            "## Artifacts",
            ""
        ]
        cur = self.conn.cursor()
        prow = cur.execute("SELECT id FROM projects WHERE name=?", (project_name,)).fetchone()
        vrow = cur.execute("SELECT id FROM versions WHERE project_id=? AND version=?", (prow["id"], version)).fetchone()
        arts = cur.execute("SELECT label, file_path FROM artifacts WHERE version_id=? ORDER BY id", (vrow["id"],)).fetchall()
        if arts:
            for a in arts:
                md.append(f"- **{a['label']}**: `{a['file_path']}`")
        else:
            md.append("_No artifacts_")
        md.append("")
        return "\n".join(md)

    # ── Existing release notes: Save ──
    def save_selected_notes(self):
        proj = self.current_project()
        if not proj: return
        version = self.selected_version_text()
        if not version: return
        notes = self.selected_notes_edit.toPlainText()
        cur = self.conn.cursor()
        cur.execute(
            "UPDATE versions SET notes=? WHERE project_id=? AND version=?",
            (notes, proj["id"], version)
        )
        self.conn.commit()
        # Reflect in table immediately
        self.refresh_versions()
        self.log_append("✅ Notes updated for " + version)

    # ── Preferences ──
    def open_prefs(self):
        dlg = QDialog(self); dlg.setWindowTitle("Preferences")
        fl = QFormLayout(dlg)

        cb_semver = QCheckBox(); cb_semver.setChecked(self.settings.value("enforce_semver", True, type=bool))
        ed_prefix = QLineEdit(self.settings.value("tag_prefix", DEFAULT_PREFIX, type=str))
        cb_push   = QCheckBox(); cb_push.setChecked(self.settings.value("push_to_origin", False, type=bool))

        # Default for storing GitHub creds via OS keychain
        cb_store_creds_default = QCheckBox("Store GitHub credentials for future pushes (default)")
        cb_store_creds_default.setChecked(self.settings.value("github_store_creds_default", True, type=bool))

        # ── Git status row + Install button ──
        git_ok = is_git_available()
        git_status = QLabel("✅ Git detected" if git_ok else "❌ Git not found")
        btn_install_git = QPushButton("Install Git…")
        btn_install_git.setToolTip("Open the official Git download page")
        btn_install_git.clicked.connect(lambda: webbrowser.open("https://git-scm.com/downloads"))
        # Slight layout nicety: status + button in one row
        git_row = QWidget(); git_h = QHBoxLayout(git_row); git_h.setContentsMargins(0,0,0,0)
        git_h.addWidget(git_status); git_h.addStretch(1); git_h.addWidget(btn_install_git)

        fl.addRow("Enforce SemVer:", cb_semver)
        fl.addRow("Tag Prefix:", ed_prefix)
        fl.addRow("Push tags to origin:", cb_push)
        fl.addRow("", cb_store_creds_default)
        fl.addRow("Git:", git_row)  # NEW

        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        fl.addWidget(bb)
        bb.accepted.connect(dlg.accept); bb.rejected.connect(dlg.reject)

        if dlg.exec_() == QDialog.Accepted:
            self.settings.setValue("enforce_semver", cb_semver.isChecked())
            self.settings.setValue("tag_prefix", ed_prefix.text().strip() or DEFAULT_PREFIX)
            self.settings.setValue("push_to_origin", cb_push.isChecked())
            self.settings.setValue("github_store_creds_default", cb_store_creds_default.isChecked())

            # reflect in current UI state
            self.cb_enforce_semver.setChecked(cb_semver.isChecked())
            self.prefix_edit.setText(ed_prefix.text().strip() or DEFAULT_PREFIX)
            self.cb_push.setChecked(cb_push.isChecked())
            self.pref_store_git_creds_default = cb_store_creds_default.isChecked()

            self.log_append("✅ Preferences saved.")

    def refresh_activity_panel(self):
        self.log.clear()
        proj = self.current_project()
        if not proj:
            self.log.append("No project selected.")
            return
        for line in self._mem_logs.get(proj["id"], []):
            self.log.append(line)


    # ── Logging ──
    def log_append(self, msg: str, project_id: int | None = None):
        now = datetime.now().strftime("%H:%M:%S")
        entry = f"[{now}] {msg}"

        # Default to the currently selected project
        if project_id is None:
            proj = self.current_project()
            project_id = proj["id"] if proj else None

        # Store in memory
        self._mem_logs[project_id].append(entry)

        # If the selected project matches, show it in the Activity panel
        cur = self.current_project()
        if cur and project_id == cur["id"]:
            self.log.append(entry)


from PyQt5.QtGui import QPalette, QColor
from PyQt5.QtWidgets import QStyleFactory

def apply_dark_theme(app):
    # Use Fusion style for consistent theming across platforms
    app.setStyle(QStyleFactory.create("Fusion"))

    # --- Palette ---
    palette = QPalette()

    # Base tones
    bg        = QColor(32, 33, 36)   # window background
    panel     = QColor(40, 42, 46)   # groupboxes / panels
    base      = QColor(30, 31, 34)   # text area backgrounds
    alt_base  = QColor(41, 43, 47)   # alternating row
    text      = QColor(220, 220, 220)
    disabled  = QColor(140, 140, 140)
    highlight = QColor(66, 133, 244) # blue
    link      = QColor(138, 180, 248)

    palette.setColor(QPalette.Window, bg)
    palette.setColor(QPalette.WindowText, text)
    palette.setColor(QPalette.Base, base)
    palette.setColor(QPalette.AlternateBase, alt_base)
    palette.setColor(QPalette.ToolTipBase, panel)
    palette.setColor(QPalette.ToolTipText, text)
    palette.setColor(QPalette.Text, text)
    palette.setColor(QPalette.Button, panel)
    palette.setColor(QPalette.ButtonText, text)
    palette.setColor(QPalette.Highlight, highlight)
    palette.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
    palette.setColor(QPalette.Link, link)
    palette.setColor(QPalette.BrightText, QColor(255, 90, 90))

    # Disabled state
    palette.setColor(QPalette.Disabled, QPalette.Text, disabled)
    palette.setColor(QPalette.Disabled, QPalette.ButtonText, disabled)
    palette.setColor(QPalette.Disabled, QPalette.WindowText, disabled)
    palette.setColor(QPalette.Disabled, QPalette.Highlight, QColor(70, 70, 70))
    palette.setColor(QPalette.Disabled, QPalette.HighlightedText, QColor(180, 180, 180))

    app.setPalette(palette)

    # --- QSS polish ---
    app.setStyleSheet("""
        QMainWindow, QDialog, QWidget { background: #202124; color: #e0e0e0; }
        QGroupBox {
            border: 1px solid #3a3b3d; border-radius: 8px; margin-top: 12px; padding: 8px;
        }
        QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0px 4px; color: #d0d0d0; }
        QTabWidget::pane { border: 1px solid #3a3b3d; border-radius: 8px; top: -1px; }
        QTabBar::tab {
            background: #2a2c2f; padding: 8px 12px; border: 1px solid #3a3b3d; border-bottom: none;
            margin-right: 2px; border-top-left-radius: 6px; border-top-right-radius: 6px;
        }
        QTabBar::tab:selected { background: #35373a; }
        QTabBar::tab:hover { background: #3a3c40; }

        QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox, QComboBox, QListView, QTreeView, QTableView {
            background: #1e1f22; color: #e0e0e0; border: 1px solid #3a3b3d; border-radius: 6px;
            selection-background-color: #4285f4; selection-color: white;
        }
        QTableView::item:selected, QListView::item:selected { background: #4285f4; color: white; }

        QHeaderView::section {
            background: #2a2c2f; color: #e0e0e0; padding: 6px; border: 1px solid #3a3b3d;
        }

        QPushButton {
            background: #2b2d30; border: 1px solid #3a3b3d; border-radius: 6px; padding: 6px 10px;
        }
        QPushButton:hover { background: #34363a; }
        QPushButton:pressed { background: #3b3d41; }
        QPushButton:disabled { color: #8c8c8c; border-color: #2f3033; }

        QScrollBar:vertical, QScrollBar:horizontal {
            background: #202124; border: none; margin: 0; }
        QScrollBar::handle:vertical { background: #3a3b3d; min-height: 24px; border-radius: 6px; }
        QScrollBar::handle:horizontal { background: #3a3b3d; min-width: 24px; border-radius: 6px; }
        QScrollBar::handle:hover { background: #4a4b4f; }
        QScrollBar::add-line, QScrollBar::sub-line { background: none; height: 0; width: 0; }

        QToolTip { background: #2a2c2f; color: #e0e0e0; border: 1px solid #3a3b3d; }
        QMenu { background: #2a2c2f; color: #e0e0e0; border: 1px solid #3a3b3d; }
        QMenu::item:selected { background: #3a3c40; }
    """)


# ────────────────────────────────────────────────────────────────────────────────
def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Code/Version Organizer")
    app.setOrganizationName("CodeMgr")
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    apply_dark_theme(app)  # ← enable dark mode globally
    w = MainWindow(); w.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()


