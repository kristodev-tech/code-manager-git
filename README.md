# Code/Version Desktop Application for GitHub (PyQt Desktop App)

A friendly desktop app to organize your code versions and releases — without leaving your repo.  
It helps you:

- Track versions/tags, notes, and release history
- Generate release notes from commit messages
- Manage and bundle **artifacts** (drag & drop)
- Create a GitHub-style **Release Folder** with a one-click **ZIP**
- **Publish to GitHub** (create repo if missing, create release, upload assets)
- Open the release page in your browser
- Keep activity logs **per project**
- Dark mode by default 🌙

---

## ✨ Features

- **Projects pane**: add/remove local projects; auto-scan versions.
- **Versions table**: version/tag, commit, date, release notes.
- **Create tag + release**:
  - Optional SemVer tag prefix (e.g., `v1.2.3`).
  - Auto-initialize Git and create an **initial commit** when needed.
  - Optionally push tags to `origin` (skips gracefully if no remote yet).
  - Instant UI refresh (no manual rescan needed).
- **Release notes**:
  - Auto-generate from commits (then edit before tagging).
  - Edit notes for existing releases and save back.
- **Artifacts**:
  - Drag-and-drop files, add/remove/open, and open containing folder.
- **Release Folder** (GitHub-style):
  - Sync artifacts → `releases/<version>/`
  - One-click **ZIP** (`<project>-<version>.zip`) for distribution
  - List, open, and browse release files
- **GitHub integration**:
  - **Publish to GitHub** dialog:
    - Enter `owner/repo` or paste a full URL
    - Use a **Personal Access Token** **Best Choice**
    - Optionally commit release folder before pushing
    - **Push branch + tags** (seamless auth)
    - **Create repo if missing** (org or user, with fallback to user)
    - **Upload assets**: every file in `releases/<version>/`
    - **Open GitHub Release** page button
  - **Credential storage options**:
    - Store token in app settings (plaintext) — optional
    - Store token in **OS keychain** via Git’s credential helper (recommended)
    - One-off token push fallback if needed (no token saved)
- **Activity log (per project)**:
  - Only shows activity for the currently selected project
  - Persists in the app session (optional DB persistence can be enabled)
- **Preferences**:
  - Enforce SemVer + tag prefix
  - Push tags by default
  - **Store GitHub credentials by default** (Keychain/Cred Manager/libsecret)
  - **Install Git…** button (opens official downloads page)

---

## 🧰 Requirements

- **Python** 3.9+ (3.10/3.11/3.12 fine)
- **Git** installed and on PATH
  - Windows: Git for Windows
  - macOS: Xcode Command Line Tools or Git from brew/site
  - Linux: your distro package manager
- A **GitHub Personal Access Token**
  - Classic PAT: `repo` scope (or at least `public_repo` for public repos)
  - Fine-grained PAT: Contents (read/write), Metadata (read), Releases (write)**Recommended for admin     and content read/write permissions.
  - If your org uses SSO, **authorize** the token for the org

### Python dependencies

See `requirements.txt` (below). TL;DR:
- PyQt5 (UI)
- requests (GitHub API)

---

## 🧩 Installation

```bash
# 1) clone your app repo
git clone https://github.com/<you>/<your-repo>.git
cd <your-repo>

# 2) (recommended) create a virtual environment
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate

# 3) install dependencies
pip install -r requirements.txt
```

> If `pip` asks for build tools on some platforms, install them via your OS package manager or use Python from python.org.

---

## ▶️ Run

```bash
python codemngr.py
```

- The app starts in **dark mode**.
- Add your first project with **Add** (left pane).
- If the folder isn’t a Git repo, the app can initialize it and create the first commit (with a README prompt).

---

## 🚀 Typical workflow

1. **Add Project** → select your local code folder.
2. If prompted, accept **Initialize Git** and **Create initial commit** (README).
3. In **Create Tag + Release**:
   - Type a version (e.g., `1.0.0` — the prefix `v` is auto-applied if enabled).
   - Click **Generate Notes from Commits** (optional), edit as needed.
   - Click **Create Tag + Record Release**.
   - The Versions table **refreshes immediately** and selects the new version.

4. (Optional) Add **artifacts/assets** via drag-and-drop or “Add File…”.

5. **Release Folder** tab:
   - Click **Sync Artifacts → Release Folder**
   - Click **Create/Update Release ZIP**
   - Use **Open Release Folder** or **Open Selected** to validate assets.
6. **Publish to GitHub**:
   - Click **Publish to GitHub**
   - Enter `owner/repo` and token
   - *Reminder*Github wants your project folder(Repo name as a single name or with a dash between like this:
     (codemanager or code-manager)
   - Choose options (commit release folder, push branch/tags)
   - Optionally **Store credentials** to the OS keychain (recommended)
   - The app will:
     - Create the repo if missing (org or your user; falls back to user if org perms/SSO block it)
     - Push branch + tags
     - Create a GitHub Release (or reuse if it exists)
     - Upload all files in `releases/<version>/` as assets
     - **Open release page** in your browser

---

## ⚙️ Preferences

**App → Preferences…**

- **Enforce SemVer**: require prefix (e.g., `v1.2.3`)
- **Tag Prefix**: default `v`
- **Push tags to origin**: push tags when creating a release (skips safely if no `origin`)
- **Store GitHub credentials for future pushes (default)**:
  - When enabled, the **Publish** dialog defaults to storing your PAT via Git’s credential helper:
    - Windows: `manager-core`
    - macOS: `osxkeychain`
    - Linux: `libsecret`
- **Git**:
  - Status badge (Detected / Not found)
  - **Install Git…** button (opens `https://git-scm.com/downloads`)

---

## 🔐 Tokens & Credentials/Fine Grained PAT is highly recommended

- **Best practice**: store PAT in the **OS keychain** (Credential Manager / Keychain / libsecret).  
  The app can do this automatically on publish. You can revoke the PAT anytime from GitHub.
- **Plaintext storage**: if you tick “Remember token” in the Publish dialog, the PAT is saved in `QSettings` (plaintext). This is optional and less secure than the OS keychain.

---

## 🛠️ Troubleshooting

- **“Git is not installed or not on PATH”**  
  Use **Preferences → Install Git…**, then restart the app.

- **Push fails with 401 / “could not read Username”**  
  The app will retry with a one-off token URL if needed.  
  To avoid prompts entirely, enable **Store credentials** (OS keychain).

- **Org repo creation returns 404/403**  
  Your token likely lacks org permissions or isn’t SSO-authorized.  
  - Ensure you’re an org owner or allowed to create repos  
  - Authorize the PAT for the org (SSO)  
  - The app offers fallback to create the repo under your user.

- **422 “name already exists on this account”**  
  The repo already exists; the app continues as success and proceeds to attach `origin`.

- **“Nothing to commit” during release commit**  
  The app handles this gracefully and continues with publishing.

- **Tag pushed but Versions table didn’t update**  
  The app now refreshes immediately after release creation and selects the new version automatically.

---

## 📦 Project structure (key folders)

```
<your project>/
  releases/
    <version>/
      ...your artifacts for that release...
    <project>-<version>.zip
```

- **Artifacts** you add in the UI get synced here per-version.
- The app uploads **everything inside `releases/<version>/`** as GitHub release assets.

---

## 🧪 Development tips

- Python packaging: optional `pyinstaller` can generate a standalone executable.
- Logs are shown per project in **Activity**. You can add `self.log_append("...")` anywhere in the code for granular tracing.
- Settings use `QSettings("CodeMgr", "DesktopApp")`.

---

## 📄 License

MIT (or your choice).

---

## 🤝 Contributing

Issues and PRs welcome! Ideas:
- Keychain-backed secure token store (no plaintext option)
- Auto-changelog templates
- GitHub Releases draft/prerelease support
- Multi-remote support & GitLab integration
- Inline diffs for artifacts/notes
