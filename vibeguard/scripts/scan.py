#!/usr/bin/env python3
"""VibeGuard 项目安全扫描器

采集安全相关数据，输出 JSON 供 agent 分析分级：
  1. 仓库卫生检查（gitignore、敏感文件追踪、硬编码密钥）
  2. 依赖生态识别和包坐标提取
  3. 调用 VibeGuard API 检查漏洞
  4. 过旧依赖检查

扫描只读项目内容；脚本只会创建/更新 .vibeguard/ 本地工作区，并确保
.gitignore 忽略该目录。

Usage:
    python3 scan.py --preflight <preflight_json>
    python3 scan.py [project_path]              # 默认向上识别项目根目录
    python3 scan.py --no-root-discovery <path>  # 严格扫描传入目录
    python3 scan.py --api-concurrency 1 <path>  # 覆盖默认 API 并发
    python3 scan.py --outdated-concurrency 4 <path>
    python3 scan.py --skip-outdated <path>      # 跳过较慢的过旧依赖检查
    python3 scan.py --include-packages <path>   # 输出完整包清单
    python3 scan.py                             # 等同于 python3 scan.py .

VibeGuard API (https://vibeguard.ou.al):
  POST /api/security/check/packages       批量检查漏洞（100个一批）

  包检查请求: {"packages": [{"ecosystem":"npm","name":"next","version":"15.5.1"}]}
  支持 4 类代码项目: JavaScript/TypeScript(npm/pnpm/yarn), Python(pypi), Go, Rust(crates-io)
"""

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

API_BASE = "https://vibeguard.ou.al"
VIBEGUARD_DIR = ".vibeguard"
VIBEGUARD_GITIGNORE_ENTRY = ".vibeguard/"
VIBEGUARD_ASSETS_DIR = "assets"
VIBEGUARD_CONTENT_DIR = "content"
_GITIGNORE_STATUS_BY_PROJECT = {}


def has_vibeguard_gitignore_entry(content):
    for line in content.splitlines():
        stripped = line.strip()
        if stripped in {".vibeguard", VIBEGUARD_GITIGNORE_ENTRY}:
            return True
    return False


def inspect_vibeguard_gitignore(project_path):
    gitignore_path = os.path.join(project_path, ".gitignore")
    try:
        with open(gitignore_path, "r", encoding="utf-8") as handle:
            content = handle.read()
    except FileNotFoundError:
        content = ""

    return {
        "path": gitignore_path,
        "preexisting": os.path.isfile(gitignore_path),
        "had_vibeguard_entry": has_vibeguard_gitignore_entry(content),
    }


def ensure_vibeguard_gitignore(project_path):
    status = inspect_vibeguard_gitignore(project_path)
    gitignore_path = status["path"]
    try:
        with open(gitignore_path, "r", encoding="utf-8") as handle:
            content = handle.read()
    except FileNotFoundError:
        content = ""

    added_entry = False
    if has_vibeguard_gitignore_entry(content):
        status.update(
            {
                "added_vibeguard_entry": False,
                "exists_after": True,
            }
        )
        _GITIGNORE_STATUS_BY_PROJECT[os.path.abspath(project_path)] = status
        return gitignore_path

    prefix = ""
    if content and not content.endswith("\n"):
        prefix = "\n"
    elif content:
        prefix = "\n"

    with open(gitignore_path, "a", encoding="utf-8") as handle:
        handle.write(f"{prefix}# VibeGuard local workspace\n{VIBEGUARD_GITIGNORE_ENTRY}\n")
    added_entry = True
    status.update(
        {
            "added_vibeguard_entry": added_entry,
            "exists_after": True,
        }
    )
    _GITIGNORE_STATUS_BY_PROJECT[os.path.abspath(project_path)] = status
    return gitignore_path


def vibeguard_gitignore_status(project_path):
    project_path = os.path.abspath(project_path)
    if project_path in _GITIGNORE_STATUS_BY_PROJECT:
        return _GITIGNORE_STATUS_BY_PROJECT[project_path]
    status = inspect_vibeguard_gitignore(project_path)
    status.update(
        {
            "added_vibeguard_entry": False,
            "exists_after": status["preexisting"],
        }
    )
    return status


def ensure_vibeguard_workspace(project_path):
    workspace = os.path.join(project_path, VIBEGUARD_DIR)
    os.makedirs(workspace, exist_ok=True)
    ensure_vibeguard_gitignore(project_path)
    return workspace


def make_run_id():
    return time.strftime("%Y%m%d-%H%M%S")


def ensure_vibeguard_run(project_path, run_id=None):
    workspace = ensure_vibeguard_workspace(project_path)
    base_run_id = run_id or make_run_id()
    run_dir = os.path.join(workspace, base_run_id)
    suffix = 2
    while os.path.exists(run_dir) and run_id is None:
        run_dir = os.path.join(workspace, f"{base_run_id}-{suffix}")
        suffix += 1
    os.makedirs(os.path.join(run_dir, VIBEGUARD_ASSETS_DIR), exist_ok=True)
    os.makedirs(os.path.join(run_dir, VIBEGUARD_CONTENT_DIR), exist_ok=True)
    return run_dir


def run_dir_from_output_file(output_file):
    output_file = os.path.abspath(output_file)
    parent = os.path.basename(os.path.dirname(output_file))
    if parent == VIBEGUARD_ASSETS_DIR:
        return os.path.dirname(os.path.dirname(output_file))
    return os.path.dirname(output_file)


def default_asset_path(project_path, filename, preflight=None):
    if preflight and preflight.get("output_file"):
        run_dir = run_dir_from_output_file(preflight["output_file"])
        os.makedirs(os.path.join(run_dir, VIBEGUARD_ASSETS_DIR), exist_ok=True)
        os.makedirs(os.path.join(run_dir, VIBEGUARD_CONTENT_DIR), exist_ok=True)
        ensure_vibeguard_gitignore(project_path)
    else:
        run_dir = ensure_vibeguard_run(project_path)
    return os.path.join(run_dir, VIBEGUARD_ASSETS_DIR, filename)

# ---------------------------------------------------------------------------
# Secret detection patterns
# ---------------------------------------------------------------------------
SECRET_PATTERNS = [
    ("aws_access_key", r"AKIA[0-9A-Z]{16}"),
    ("private_key", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ("slack_token", r"xox[baprs]-[A-Za-z0-9-]+"),
    ("github_token", r"gh[pousr]_[A-Za-z0-9_]{36,}"),
    ("openai_key", r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
    ("generic_password", r"""(?:password|passwd|pwd)\s*[:=]\s*["'][^"']{4,}["']"""),
    (
        "generic_api_key",
        r"""(?:api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*["'][^"']{8,}["']""",
    ),
]
SECRET_REGEXES = [(name, re.compile(pattern)) for name, pattern in SECRET_PATTERNS]
SECRET_SKIP_MARKERS = ("example", "placeholder", "your_", "xxx", "todo", "sample")
HIGH_CONFIDENCE_SECRET_TYPES = {
    "aws_access_key",
    "private_key",
    "slack_token",
    "github_token",
}

SENSITIVE_FILE_PATTERNS = [
    ("env_file", r"(^|/)\.env(\.[\w-]+)?$"),
    ("private_key", r"\.(pem|key|p12|pfx|jks|keystore)$"),
    ("database", r"\.(sqlite|sqlite3|db|dump)$"),
    ("log", r"\.log$"),
    ("credentials", r"(^|/)credentials\.json$"),
    ("credentials", r"(^|/)service-account.*\.json$"),
    ("ssh_key", r"(^|/)id_(rsa|ed25519|ecdsa)$"),
]
SENSITIVE_FILE_REGEXES = [
    (file_type, re.compile(pattern)) for file_type, pattern in SENSITIVE_FILE_PATTERNS
]

ENV_TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist")

# 敏感文件类型 → 对应的 .gitignore 规则（只按实际发现的文件推荐，不一股脑全加）
SENSITIVE_TO_GITIGNORE = {
    "env_file":       [".env", ".env.*"],
    "private_key":    ["*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore"],
    "database":       ["*.sqlite", "*.sqlite3", "*.db", "*.dump"],
    "credentials":    ["credentials.json", "service-account*.json"],
    "ssh_key":        ["id_rsa", "id_ed25519", "id_ecdsa"],
    "log":            ["*.log"],
}

EXCLUDE_DIRS = {
    ".git",
    ".vibeguard",
    "node_modules",
    ".next",
    ".turbo",
    ".vercel",
    "dist",
    "build",
    "coverage",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".svelte-kit",
    ".venv",
    "venv",
    ".idea",
    ".vscode",
    "target",
    "vendor",
    "bower_components",
    ".cache",
    ".tox",
    ".eggs",
    ".cargo",
    ".npm",
    ".pnpm-store",
    ".yarn",
}

SCAN_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".mjs",
    ".cjs",
    ".go",
    ".rs",
    ".rb",
    ".php",
    ".java",
    ".kt",
    ".swift",
    ".c",
    ".cpp",
    ".h",
    ".hpp",
    ".cs",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".sh",
    ".bash",
    ".zsh",
    ".fish",
    ".html",
    ".css",
    ".scss",
    ".less",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def run_cmd(cmd, timeout=60, cwd=None):
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
        )
        return r.stdout.strip()
    except Exception:
        return ""


def run_cmd_checked(cmd, timeout=60, cwd=None, errors=None, step="command"):
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        if errors is not None:
            errors.append({"step": step, "message": f"命令不可用：{cmd[0]}"})
        return ""
    except subprocess.TimeoutExpired:
        if errors is not None:
            errors.append({"step": step, "message": f"命令超时：{' '.join(cmd)}"})
        return ""
    except OSError as e:
        if errors is not None:
            errors.append({"step": step, "message": f"命令执行失败：{' '.join(cmd)}: {e}"})
        return ""

    stdout = r.stdout.strip()
    if r.returncode != 0 and not stdout:
        if errors is not None:
            msg = (r.stderr or "无 stderr 输出").strip()
            errors.append({"step": step, "message": f"{' '.join(cmd)} 失败：{msg}"})
        return ""
    return stdout


def gitignore_rules(content):
    rules = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        rules.add(line.lower().rstrip("/"))
    return rules


def gitignore_ignores(content, pattern):
    norm = pattern.strip().lower().rstrip("/")
    state = False
    for line in content.splitlines():
        line = line.strip().lower().rstrip("/")
        if not line or line.startswith("#"):
            continue
        if line == norm:
            state = True
        elif line == "!" + norm:
            state = False
    return state


def find_project_root(start_path="."):
    """Walk up to find .git or a recognizable manifest."""
    path = os.path.abspath(start_path)
    for _ in range(20):
        if os.path.isdir(os.path.join(path, ".git")):
            return path
        parent = os.path.dirname(path)
        if parent == path:
            break
        path = parent
    path = os.path.abspath(start_path)
    for _ in range(20):
        if any(
            os.path.isfile(os.path.join(path, f))
            for f in [
                "package.json",
                "pyproject.toml",
                "go.mod",
                "Cargo.toml",
                "requirements.txt",
                "composer.json",
                "Gemfile",
            ]
        ):
            return path
        parent = os.path.dirname(path)
        if parent == path:
            break
        path = parent
    return os.path.abspath(start_path)


def is_env_template(path):
    name = os.path.basename(path).lower()
    return name.startswith(".env") and (
        name in {".env.example", ".env.sample", ".env.template", ".env.dist"}
        or name.endswith(ENV_TEMPLATE_SUFFIXES)
    )


def sensitive_file_type(path):
    if is_env_template(path):
        return ""
    for file_type, pattern in SENSITIVE_FILE_REGEXES:
        if pattern.search(path):
            return file_type
    return ""


def is_git_worktree(path):
    return run_cmd(["git", "rev-parse", "--is-inside-work-tree"], cwd=path) == "true"


# ---------------------------------------------------------------------------
# Step 1: Repository hygiene
# ---------------------------------------------------------------------------


def check_gitignore(project_path, sensitive_tracked):
    """Check .gitignore: only recommend rules for sensitive file types actually found."""
    gitignore_path = os.path.join(project_path, ".gitignore")
    gitignore_exists = os.path.isfile(gitignore_path)
    if not gitignore_exists:
        content = ""
    else:
        with open(gitignore_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

    # Collect types of sensitive files actually found in the project
    found_types = set()
    for item in sensitive_tracked:
        found_types.add(item.get("type", ""))
    # Also check if .env files exist (even if not tracked)
    for name in (".env", ".env.local", ".env.production", ".env.development"):
        if os.path.isfile(os.path.join(project_path, name)):
            found_types.add("env_file")

    missing = []
    for ftype, patterns in SENSITIVE_TO_GITIGNORE.items():
        if ftype not in found_types:
            continue
        for pat in patterns:
            if not gitignore_ignores(content, pat):
                missing.append(pat)
    return gitignore_exists, missing


def check_sensitive_tracked(project_path):
    output = run_cmd(["git", "ls-files"], cwd=project_path)
    if not output:
        return []
    findings = []
    for f in output.split("\n"):
        if not f.strip():
            continue
        ftype = sensitive_file_type(f)
        if not ftype:
            continue
        full = os.path.join(project_path, f)
        size = 0
        try:
            size = os.path.getsize(full)
        except OSError:
            pass
        findings.append({"file": f, "type": ftype, "size": size})
    return findings


def secret_preview(secret_type, match_text):
    if secret_type == "private_key":
        return "-----BEGIN *** PRIVATE KEY-----"

    if secret_type in {"generic_password", "generic_api_key"}:
        masked = re.sub(
            r"""([:=]\s*["']?)[^"']+(["']?)$""",
            r"\1***\2",
            match_text,
        )
        return masked if masked != match_text else "***"

    if len(match_text) <= 8:
        return "***"
    if len(match_text) <= 24:
        return match_text[:4] + "..." + match_text[-4:]
    return match_text[:15] + "..." + match_text[-10:]


def scan_secrets(project_path, max_files=500, max_bytes=1024 * 1024):
    findings = []
    count = 0
    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for fname in files:
            if count >= max_files:
                return findings
            ext = os.path.splitext(fname)[1].lower()
            if ext not in SCAN_EXTENSIONS and fname not in {".env", ".envrc"}:
                continue
            fpath = os.path.join(root, fname)
            try:
                if os.path.getsize(fpath) > max_bytes:
                    continue
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    for line_num, line in enumerate(f, 1):
                        stripped = line.strip()
                        if stripped.startswith("#") or stripped.startswith("//"):
                            continue
                        lowered = stripped.lower()
                        if any(x in lowered for x in SECRET_SKIP_MARKERS):
                            continue
                        for secret_type, pattern in SECRET_REGEXES:
                            m = pattern.search(line)
                            if m:
                                preview = secret_preview(secret_type, m.group(0))
                                rel = os.path.relpath(fpath, project_path)
                                findings.append(
                                    {
                                        "file": rel,
                                        "line": line_num,
                                        "type": secret_type,
                                        "preview": preview,
                                        "confidence": "high"
                                        if secret_type in HIGH_CONFIDENCE_SECRET_TYPES
                                        else "medium",
                                    }
                                )
            except (OSError, UnicodeDecodeError):
                continue
            count += 1
    return findings


def scan_hygiene(project_path, max_secret_files=500):
    # Scan sensitive files first, then use findings to drive gitignore recommendations
    sensitive_tracked = check_sensitive_tracked(project_path)
    tracked_secrets = scan_secrets(project_path, max_files=max_secret_files)
    gitignore_exists, gitignore_missing = check_gitignore(project_path, sensitive_tracked)
    return {
        "gitignore_exists": gitignore_exists,
        "gitignore_missing": gitignore_missing,
        "tracked_secrets": tracked_secrets,
        "sensitive_tracked": sensitive_tracked,
    }


# ---------------------------------------------------------------------------
# Step 2: Ecosystem detection & package extraction
# ---------------------------------------------------------------------------

LOCKFILE_MAP = {
    "npm": ["package-lock.json"],
    "pnpm": ["pnpm-lock.yaml"],
    "yarn": ["yarn.lock"],
    "pypi": ["poetry.lock", "uv.lock", "requirements.txt", "Pipfile.lock"],
    "go": ["go.sum"],
    "crates-io": ["Cargo.lock"],
}


def detect_ecosystems(project_path):
    ecosystems, lockfiles = [], {}
    for eco, names in LOCKFILE_MAP.items():
        for lf in names:
            if os.path.isfile(os.path.join(project_path, lf)):
                ecosystems.append(eco)
                lockfiles[eco] = lf
                break
    return ecosystems, lockfiles


def _tomllib():
    try:
        import tomllib

        return tomllib
    except ImportError:
        return None


# --- npm ---


def parse_npm_lock(project_path):
    path = os.path.join(project_path, "package-lock.json")
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []
    pkgs = []
    deps = data.get("dependencies") or data.get("packages") or {}
    if "dependencies" in data:
        for name, info in deps.items():
            pkgs.append(
                {
                    "ecosystem": "npm",
                    "name": name,
                    "version": info.get("version", ""),
                    "is_direct": False,
                    "source": "package-lock.json",
                }
            )
    else:
        for key, info in deps.items():
            if not key:
                continue
            name = key.removeprefix("node_modules/")
            if not name or name == key:
                continue
            pkgs.append(
                {
                    "ecosystem": "npm",
                    "name": name,
                    "version": info.get("version", ""),
                    "is_direct": not info.get("dev", True) and not info.get("resolved"),
                    "source": "package-lock.json",
                }
            )
    return pkgs


# --- pnpm ---


def parse_pnpm_lock(project_path):
    path = os.path.join(project_path, "pnpm-lock.yaml")
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
    except OSError:
        return []
    pkgs, seen = [], set()
    # pnpm v9: packages section uses "'@scope/name@version':" or "name@version:"
    in_packages = False
    for line in content.split("\n"):
        stripped = line.rstrip()
        if stripped == "packages:":
            in_packages = True
            continue
        if in_packages:
            # Lines starting with 2+ spaces are package entries
            m = re.match(r"^  (?:'([^']+)'|([^:\s]+)):", stripped)
            if m:
                entry = (m.group(1) or m.group(2)).lstrip("/")
                entry = entry.split("(", 1)[0]
                # Parse "name@version" from entry (may include @scope)
                pm = re.match(r"^(.+?)@(\d[^@]*)$", entry)
                if pm:
                    name, ver = pm.group(1).strip("'\""), pm.group(2)
                    if (name, ver) not in seen:
                        seen.add((name, ver))
                        pkgs.append(
                            {
                                "ecosystem": "npm",
                                "name": name,
                                "version": ver,
                                "is_direct": False,
                                "source": "pnpm-lock.yaml",
                            }
                        )
            elif stripped and not stripped.startswith("  "):
                in_packages = False
    # Fallback: older format with importers
    if not pkgs:
        for m in re.finditer(
            r"^\s+['\"/]([^@'\"/]+)@([^'\"/:]+)", content, re.MULTILINE
        ):
            name, ver = m.group(1), m.group(2)
            if (name, ver) not in seen:
                seen.add((name, ver))
                pkgs.append(
                    {
                        "ecosystem": "npm",
                        "name": name,
                        "version": ver,
                        "is_direct": False,
                        "source": "pnpm-lock.yaml",
                    }
                )
    return pkgs


# --- yarn ---


def parse_yarn_lock(project_path):
    path = os.path.join(project_path, "yarn.lock")
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
    except OSError:
        return []
    pkgs, seen = [], set()
    current_names = []
    for raw in content.splitlines():
        line = raw.rstrip()
        if not line or line.startswith("#"):
            continue
        if not line.startswith(" ") and line.endswith(":"):
            header = line[:-1].strip().strip('"')
            current_names = []
            for desc in re.split(r',\s*', header):
                desc = desc.strip().strip('"')
                name = yarn_descriptor_name(desc)
                if name and name not in current_names:
                    current_names.append(name)
            continue
        if current_names:
            m = re.match(r'\s+version\s+"([^"]+)"', line)
            if not m:
                continue
            ver = m.group(1)
            for name in current_names:
                if (name, ver) not in seen:
                    seen.add((name, ver))
                    pkgs.append(
                        {
                            "ecosystem": "npm",
                            "name": name,
                            "version": ver,
                            "is_direct": False,
                            "source": "yarn.lock",
                        }
                    )
            current_names = []
    return pkgs


def yarn_descriptor_name(desc):
    if not desc:
        return ""
    if desc.startswith("@"):
        parts = desc.split("@")
        if len(parts) >= 3:
            return "@" + parts[1]
        return desc
    return desc.split("@", 1)[0]


# --- Python ---


def parse_requirements_txt(project_path):
    path = os.path.join(project_path, "requirements.txt")
    if not os.path.isfile(path):
        return []
    pkgs = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                line = line.split(";", 1)[0].strip()
                m = re.match(
                    r"^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*([=~><!]{1,2})\s*([0-9][0-9A-Za-z.*+!_-]*)",
                    line,
                )
                if m:
                    pkgs.append(
                        {
                            "ecosystem": "pypi",
                            "name": m.group(1).lower(),
                            "version": m.group(3),
                            "specifier": m.group(2),
                            "is_direct": True,
                            "source": "requirements.txt",
                        }
                    )
    except OSError:
        pass
    return pkgs


def parse_pipfile_lock(project_path):
    path = os.path.join(project_path, "Pipfile.lock")
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []

    pkgs = []
    for section_name, is_direct in (("default", True), ("develop", False)):
        section = data.get(section_name) or {}
        for name, info in section.items():
            if isinstance(info, str):
                version = info
            elif isinstance(info, dict):
                version = info.get("version", "")
            else:
                version = ""
            version = str(version or "").strip()
            specifier = ""
            if version.startswith("=="):
                specifier = "=="
                version = version[2:]
            elif version.startswith("="):
                specifier = "="
                version = version[1:]
            if not version:
                continue
            pkgs.append(
                {
                    "ecosystem": "pypi",
                    "name": name.lower(),
                    "version": version,
                    "specifier": specifier or "==",
                    "is_direct": is_direct,
                    "source": "Pipfile.lock",
                }
            )
    return pkgs


def _parse_toml_lock(path, source_name):
    tl = _tomllib()
    if not tl:
        return _parse_toml_lock_fallback(path, source_name)
    try:
        with open(path, "rb") as f:
            data = tl.load(f)
    except Exception:
        return []
    pkgs = []
    for pkg in data.get("package", []):
        pkgs.append(
            {
                "ecosystem": "pypi",
                "name": pkg.get("name", "").lower(),
                "version": pkg.get("version", ""),
                "is_direct": False,
                "source": source_name,
            }
        )
    return pkgs


def _parse_toml_lock_fallback(path, source_name):
    pkgs = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
    except OSError:
        return []
    for m in re.finditer(
        r'\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"', content
    ):
        pkgs.append(
            {
                "ecosystem": "pypi",
                "name": m.group(1).lower(),
                "version": m.group(2),
                "is_direct": False,
                "source": source_name,
            }
        )
    return pkgs


def parse_poetry_lock(project_path):
    path = os.path.join(project_path, "poetry.lock")
    return _parse_toml_lock(path, "poetry.lock") if os.path.isfile(path) else []


def parse_uv_lock(project_path):
    path = os.path.join(project_path, "uv.lock")
    return _parse_toml_lock(path, "uv.lock") if os.path.isfile(path) else []


def parse_pypi(project_path):
    pkgs = []
    for parser in (parse_poetry_lock, parse_uv_lock, parse_pipfile_lock, parse_requirements_txt):
        pkgs.extend(parser(project_path))
    return pkgs


# --- Go ---


def parse_go_sum(project_path):
    path = os.path.join(project_path, "go.sum")
    if not os.path.isfile(path):
        return []
    pkgs, seen = [], set()
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 2:
                    name, ver = parts[0], parts[1].split("/")[0]
                    if (name, ver) not in seen:
                        seen.add((name, ver))
                        pkgs.append(
                            {
                                "ecosystem": "go",
                                "name": name,
                                "version": ver,
                                "is_direct": False,
                                "source": "go.sum",
                            }
                        )
    except OSError:
        pass
    return pkgs


# --- Rust ---


def parse_cargo_lock(project_path):
    path = os.path.join(project_path, "Cargo.lock")
    if not os.path.isfile(path):
        return []
    tl = _tomllib()
    if not tl:
        return _parse_cargo_lock_fallback(path)
    try:
        with open(path, "rb") as f:
            data = tl.load(f)
    except Exception:
        return []
    pkgs = []
    for pkg in data.get("package", []):
        if pkg.get("source"):
            pkgs.append(
                {
                    "ecosystem": "crates-io",
                    "name": pkg.get("name", ""),
                    "version": pkg.get("version", ""),
                    "is_direct": False,
                    "source": "Cargo.lock",
                }
            )
    return pkgs


def _parse_cargo_lock_fallback(path):
    pkgs = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
    except OSError:
        return []
    for m in re.finditer(
        r'\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"\s*\nsource\s*=\s*"([^"]+)"',
        content,
    ):
        pkgs.append(
            {
                "ecosystem": "crates-io",
                "name": m.group(1),
                "version": m.group(2),
                "is_direct": False,
                "source": "Cargo.lock",
            }
        )
    return pkgs


PARSERS = {
    "npm": parse_npm_lock,
    "pnpm": parse_pnpm_lock,
    "yarn": parse_yarn_lock,
    "pypi": parse_pypi,
    "go": parse_go_sum,
    "crates-io": parse_cargo_lock,
}


def extract_packages(project_path, ecosystems):
    all_pkgs, seen = [], set()
    for eco in ecosystems:
        parser = PARSERS.get(eco)
        if not parser:
            continue
        for pkg in parser(project_path):
            key = (pkg["ecosystem"], pkg["name"], pkg["version"])
            if key not in seen:
                seen.add(key)
                all_pkgs.append(pkg)
    return all_pkgs


def package_source_summary(packages):
    counts = {}
    for pkg in packages:
        key = (pkg.get("ecosystem", ""), pkg.get("source", ""))
        counts[key] = counts.get(key, 0) + 1
    return [
        {"ecosystem": eco, "source": source, "count": count}
        for (eco, source), count in sorted(counts.items())
    ]


def package_version_index(packages):
    index = {}
    for pkg in packages or []:
        ecosystem = pkg.get("ecosystem")
        name = pkg.get("name")
        version = pkg.get("version")
        if not ecosystem or not name or not version:
            continue
        key = (str(ecosystem).lower(), str(name).lower())
        index.setdefault(key, version)
    return index


def current_version_for(version_index, ecosystem, package):
    if not version_index or not ecosystem or not package:
        return ""
    return version_index.get((str(ecosystem).lower(), str(package).lower()), "")


def clean_version(value):
    return str(value or "").strip().lstrip("v")


# ---------------------------------------------------------------------------
# Step 3: Vulnerability check via VibeGuard API
# ---------------------------------------------------------------------------


def _cvss_to_severity(vector):
    """Parse CVSS vector string → severity level using impact metrics.

    Uses a simplified heuristic based on C/I/A impact values:
    - Any impact = H (High) → critical if AV:N (network), else high
    - All impacts = L (Low) → medium
    - No impact → low
    Falls back to None if vector can't be parsed.
    """
    if not vector or "CVSS:" not in vector:
        return None
    try:
        parts = {}
        for pair in vector.split("/"):
            if ":" in pair and not pair.startswith("CVSS:"):
                k, v = pair.split(":", 1)
                parts[k] = v
        c = parts.get("C", "N")
        i = parts.get("I", "N")
        a = parts.get("A", "N")
        av = parts.get("AV", "N")
        # Check for high impact (H) on any CIA
        cia = [c, i, a]
        if any(x == "H" for x in cia):
            return "critical" if av == "N" else "high"
        # Check for low impact (L) on any CIA
        if any(x == "L" for x in cia):
            return "medium"
        # No real impact
        return "low"
    except Exception:
        return None


def best_advisory_alias(aliases):
    aliases = [a for a in aliases if a]
    for alias in aliases:
        if str(alias).upper().startswith("CVE-"):
            return alias
    for alias in aliases:
        if not str(alias).upper().startswith("GHSA-"):
            return alias
    return aliases[0] if aliases else ""


def post_json(url, payload, timeout=120):
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8")
    return json.loads(raw)


def parse_vulnerability_findings(data):
    vulns = []
    for item in data.get("findings", []):
        if not item.get("affected"):
            continue
        adv = item.get("advisory") or {}
        ap = item.get("affectedPackage") or {}
        pkg = item.get("package") or {}
        risk = item.get("risk") or {}
        aliases = adv.get("aliases") or []
        # Severity: prefer CVSS-based level, fallback to risk.level
        cvss_vector = ""
        cvss = None
        for s in adv.get("severity") or []:
            if s.get("score"):
                cvss = s["score"]
                cvss_vector = s["score"]
                break
        sev = _cvss_to_severity(cvss_vector) or risk.get("level", "unknown")
        fixed = ap.get("fixedVersions") or []
        vulns.append(
            {
                "package": pkg.get("name", ""),
                "version": pkg.get("version", ""),
                "ecosystem": pkg.get("ecosystem", ""),
                "affected": True,
                "match_reason": item.get("matchReason", ""),
                "match_summary": item.get("matchSummary", ""),
                "confidence": item.get("confidence", ""),
                "advisory_id": adv.get("id", ""),
                "aliases": aliases,
                "cve_id": best_advisory_alias(aliases),
                "severity": sev,
                "cvss": cvss,
                "fixed_versions": fixed,
                "summary": adv.get("summary", ""),
                "risk_signals": risk.get("signals", []),
            }
        )
    return vulns


def check_vulnerability_batch(batch_no, batch):
    payload = {
        "packages": [
            {
                "ecosystem": p["ecosystem"],
                "name": p["name"],
                "version": p["version"],
            }
            for p in batch
        ]
    }
    try:
        data = post_json(f"{API_BASE}/api/security/check/packages", payload)
    except urllib.error.HTTPError as e:
        return [], [
            {
                "step": "vulnerability_check",
                "message": f"第 {batch_no} 批 API 返回 HTTP {e.code}",
            }
        ]
    except urllib.error.URLError as e:
        return [], [
            {
                "step": "vulnerability_check",
                "message": f"第 {batch_no} 批 API 连接失败：{e.reason}",
            }
        ]
    except (json.JSONDecodeError, TimeoutError, OSError) as e:
        return [], [
            {
                "step": "vulnerability_check",
                "message": f"第 {batch_no} 批 API 响应解析失败：{e}",
            }
        ]
    return parse_vulnerability_findings(data), []


def check_vulnerabilities(packages, batch_size=100, errors=None, concurrency=1):
    if not packages:
        return []
    if errors is None:
        errors = []
    batches = [
        (i // batch_size + 1, packages[i : i + batch_size])
        for i in range(0, len(packages), batch_size)
    ]
    workers = max(1, min(int(concurrency or 1), len(batches), 16))

    if workers == 1:
        results = []
        for batch_no, batch in batches:
            vulns, batch_errors = check_vulnerability_batch(batch_no, batch)
            results.append((batch_no, vulns, batch_errors))
    else:
        results = []
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_batch = {
                executor.submit(check_vulnerability_batch, batch_no, batch): batch_no
                for batch_no, batch in batches
            }
            for future in as_completed(future_to_batch):
                batch_no = future_to_batch[future]
                try:
                    vulns, batch_errors = future.result()
                except Exception as e:
                    vulns = []
                    batch_errors = [
                        {
                            "step": "vulnerability_check",
                            "message": f"第 {batch_no} 批 API 检查失败：{e}",
                        }
                    ]
                results.append((batch_no, vulns, batch_errors))

    all_vulns = []
    for _, vulns, batch_errors in sorted(results, key=lambda x: x[0]):
        all_vulns.extend(vulns)
        errors.extend(batch_errors)
    return all_vulns


# ---------------------------------------------------------------------------
# Step 4: Outdated check
# ---------------------------------------------------------------------------


def run_outdated_task(index, task):
    local_errors = []
    try:
        items = task(local_errors)
    except Exception as e:
        items = []
        local_errors.append({"step": "outdated_check", "message": str(e)})
    return index, items, local_errors


def check_outdated(project_path, ecosystems, errors=None, concurrency=4, packages=None):
    if errors is None:
        errors = []
    version_index = package_version_index(packages)
    tasks = []
    if "npm" in ecosystems:
        tasks.append(
            lambda task_errors: _outdated_json(
                "npm",
                ["npm", "outdated", "--json"],
                project_path,
                task_errors,
                version_index,
            )
        )
    if "pnpm" in ecosystems:
        tasks.append(
            lambda task_errors: _outdated_json(
                "npm",
                ["pnpm", "outdated", "--json"],
                project_path,
                task_errors,
                version_index,
            )
        )
    if "yarn" in ecosystems:
        tasks.append(lambda task_errors: _yarn_outdated(project_path, task_errors))
    if "pypi" in ecosystems:
        tasks.append(lambda task_errors: _pip_outdated(project_path, task_errors))
    if "go" in ecosystems:
        tasks.append(lambda task_errors: _go_outdated(project_path, task_errors))
    if "crates-io" in ecosystems:
        tasks.append(lambda task_errors: _cargo_outdated(project_path, task_errors))

    if not tasks:
        return []

    workers = max(1, min(int(concurrency or 1), len(tasks), 8))
    if workers == 1:
        results = [run_outdated_task(i, task) for i, task in enumerate(tasks)]
    else:
        results = []
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_index = {
                executor.submit(run_outdated_task, i, task): i
                for i, task in enumerate(tasks)
            }
            for future in as_completed(future_to_index):
                index = future_to_index[future]
                try:
                    results.append(future.result())
                except Exception as e:
                    results.append(
                        (
                            index,
                            [],
                            [{"step": "outdated_check", "message": str(e)}],
                        )
                    )

    outdated = []
    for _, items, task_errors in sorted(results, key=lambda x: x[0]):
        outdated.extend(item for item in items if is_outdated_item(item))
        errors.extend(task_errors)
    return outdated


def outdated_target(item):
    return item.get("wanted") or item.get("latest") or ""


def is_outdated_item(item):
    current = clean_version(item.get("current") or item.get("version"))
    target = clean_version(outdated_target(item))
    return bool(target and current != target)


def outdated_item(eco, package, data, version_index=None):
    current = data.get("current") or data.get("currentVersion") or data.get("version") or ""
    if not current:
        current = current_version_for(version_index, eco, package)
    return {
        "package": package,
        "current": current,
        "wanted": data.get("wanted") or data.get("update") or "",
        "latest": data.get("latest") or data.get("latestVersion") or "",
        "ecosystem": eco,
    }


def _outdated_json(eco, cmd, cwd, errors=None, version_index=None):
    output = run_cmd_checked(cmd, cwd=cwd, timeout=60, errors=errors, step="outdated_check")
    if not output:
        return []
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        if errors is not None:
            errors.append(
                {"step": "outdated_check", "message": f"{cmd[0]} outdated 输出不是有效 JSON"}
            )
        return []
    if isinstance(data, list):
        return [
            outdated_item(
                eco,
                p.get("name") or p.get("packageName", ""),
                p,
                version_index=version_index,
            )
            for p in data
        ]
    return [
        outdated_item(eco, n, v if isinstance(v, dict) else {}, version_index=version_index)
        for n, v in data.items()
    ]


def _yarn_outdated(cwd, errors=None):
    output = run_cmd_checked(
        ["yarn", "outdated", "--json"],
        cwd=cwd,
        timeout=60,
        errors=errors,
        step="outdated_check",
    )
    if not output:
        return []
    result = []
    for line in output.split("\n"):
        try:
            d = json.loads(line)
            if d.get("type") == "table":
                for row in d.get("data", {}).get("body", []):
                    if len(row) >= 4:
                        result.append(
                            {
                                "package": row[0],
                                "current": row[1],
                                "latest": row[3],
                                "ecosystem": "npm",
                            }
                        )
        except json.JSONDecodeError:
            continue
    return result


def _pip_outdated(cwd, errors=None):
    output = run_cmd_checked(
        [sys.executable, "-m", "pip", "list", "--outdated", "--format=json"],
        cwd=cwd,
        timeout=60,
        errors=errors,
        step="outdated_check",
    )
    if not output:
        return []
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        if errors is not None:
            errors.append({"step": "outdated_check", "message": "pip list --outdated 输出不是有效 JSON"})
        return []
    return [
        {
            "package": p.get("name", ""),
            "current": p.get("version", ""),
            "latest": p.get("latest_version", ""),
            "ecosystem": "pypi",
        }
        for p in data
    ]


def _go_outdated(cwd, errors=None):
    output = run_cmd_checked(
        ["go", "list", "-u", "-m", "-json", "all"],
        cwd=cwd,
        timeout=120,
        errors=errors,
        step="outdated_check",
    )
    if not output:
        return []
    result = []
    for d in iter_json_objects(output):
        if d.get("Update"):
            result.append(
                {
                    "package": d.get("Path", ""),
                    "current": d.get("Version", ""),
                    "latest": d["Update"].get("Version", ""),
                    "ecosystem": "go",
                }
            )
    return result


def iter_json_objects(text):
    decoder = json.JSONDecoder()
    pos = 0
    length = len(text)
    while pos < length:
        while pos < length and text[pos].isspace():
            pos += 1
        if pos >= length:
            break
        try:
            obj, pos = decoder.raw_decode(text, pos)
        except json.JSONDecodeError:
            break
        if isinstance(obj, dict):
            yield obj


def _cargo_outdated(cwd, errors=None):
    output = run_cmd_checked(
        ["cargo", "outdated"],
        cwd=cwd,
        timeout=120,
        errors=errors,
        step="outdated_check",
    )
    if not output:
        return []
    result = []
    for line in output.split("\n"):
        parts = line.split()
        if len(parts) >= 3 and parts[0] != "Name":
            result.append(
                {
                    "package": parts[0],
                    "current": parts[1],
                    "latest": parts[-1],
                    "ecosystem": "crates-io",
                }
            )
    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def parse_args(argv):
    parser = argparse.ArgumentParser(description="VibeGuard local project scanner")
    parser.add_argument("project_path", nargs="?", default=".")
    parser.add_argument(
        "--preflight",
        help="reuse a preflight JSON file to choose project path and scan mode",
    )
    parser.add_argument(
        "--output",
        help="write JSON to this path instead of the default temp-file path",
    )
    parser.add_argument(
        "--no-root-discovery",
        action="store_true",
        help="scan the provided path directly instead of walking up to a repo root",
    )
    parser.add_argument(
        "--api-concurrency",
        type=int,
        default=1,
        help="number of concurrent VibeGuard API package-check requests",
    )
    parser.add_argument(
        "--outdated-concurrency",
        type=int,
        default=None,
        help="number of concurrent outdated dependency checks",
    )
    parser.add_argument(
        "--skip-outdated",
        action="store_true",
        help="skip package-manager outdated checks for faster vulnerability-only scans",
    )
    parser.add_argument(
        "--skip-hygiene",
        action="store_true",
        help="skip gitignore, tracked sensitive file, and hardcoded secret checks",
    )
    parser.add_argument(
        "--max-secret-files",
        type=int,
        default=500,
        help="maximum number of candidate files to scan for hardcoded secrets",
    )
    parser.add_argument(
        "--include-packages",
        action="store_true",
        help="include the full package list in output JSON",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="emit compact JSON instead of pretty-printed JSON",
    )
    return parser.parse_args(argv)


def default_concurrency(cap):
    return max(1, min(os.cpu_count() or 4, cap))


def bounded_concurrency(value, cap):
    if value is None:
        value = default_concurrency(cap)
    return max(1, min(int(value or 1), cap))


def load_preflight(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def default_output_path(project_path, preflight=None):
    return default_asset_path(project_path, "scan.json", preflight=preflight)


def write_json_output(path, text):
    output_dir = os.path.dirname(os.path.abspath(path))
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.write("\n")


def main():
    started = time.time()
    args = parse_args(sys.argv[1:])
    try:
        preflight = load_preflight(args.preflight) if args.preflight else None
    except (json.JSONDecodeError, OSError) as e:
        print(f"Failed to read preflight JSON: {e}", file=sys.stderr)
        return 2

    preflight_project_path = (preflight or {}).get("project", {}).get("path")
    if preflight_project_path:
        project_path = os.path.abspath(preflight_project_path)
    else:
        start = args.project_path
        project_path = (
            os.path.abspath(start) if args.no_root_discovery else find_project_root(start)
        )
    preflight_scan_mode = (preflight or {}).get("recommended_scan_mode")
    preflight_hygiene_only = preflight_scan_mode == "hygiene_only"
    api_concurrency = bounded_concurrency(args.api_concurrency, 16)
    outdated_concurrency = bounded_concurrency(args.outdated_concurrency, 8)
    output_file = args.output or default_output_path(project_path, preflight=preflight)
    errors = []
    step_seconds = {}

    # Step 1: detect ecosystems
    step_started = time.time()
    if preflight_hygiene_only:
        ecosystems, lockfiles = [], {}
    else:
        try:
            ecosystems, lockfiles = detect_ecosystems(project_path)
        except Exception as e:
            ecosystems, lockfiles = [], {}
            errors.append({"step": "ecosystem_detection", "message": str(e)})
    step_seconds["ecosystem_detection"] = round(time.time() - step_started, 3)
    scan_mode = preflight_scan_mode or (
        "full_dependency_scan" if ecosystems else "hygiene_only"
    )
    skip_dependency_checks = scan_mode == "hygiene_only"

    # Step 2: parse package coordinates
    step_started = time.time()
    if skip_dependency_checks:
        packages = []
    else:
        try:
            packages = extract_packages(project_path, ecosystems)
        except Exception as e:
            packages = []
            errors.append({"step": "package_extraction", "message": str(e)})
    step_seconds["package_extraction"] = round(time.time() - step_started, 3)

    # Step 3-5: independent I/O-heavy checks run in parallel.
    def run_hygiene_step():
        step_started = time.time()
        if args.skip_hygiene:
            return "hygiene", {"skipped": True}, [], round(time.time() - step_started, 3)
        try:
            result = scan_hygiene(
                project_path,
                max_secret_files=max(0, int(args.max_secret_files or 0)),
            )
            return "hygiene", result, [], round(time.time() - step_started, 3)
        except Exception as e:
            return "hygiene", {}, [{"step": "hygiene", "message": str(e)}], round(
                time.time() - step_started,
                3,
            )

    def run_vulnerability_step():
        step_started = time.time()
        if skip_dependency_checks:
            return "vulnerabilities", [], [], round(time.time() - step_started, 3)
        step_errors = []
        try:
            result = check_vulnerabilities(
                packages,
                errors=step_errors,
                concurrency=api_concurrency,
            )
        except Exception as e:
            result = []
            step_errors.append({"step": "vulnerability_check", "message": str(e)})
        return "vulnerabilities", result, step_errors, round(time.time() - step_started, 3)

    def run_outdated_step():
        step_started = time.time()
        if skip_dependency_checks or args.skip_outdated:
            return "outdated", [], [], round(time.time() - step_started, 3)
        step_errors = []
        try:
            result = check_outdated(
                project_path,
                ecosystems,
                errors=step_errors,
                concurrency=outdated_concurrency,
                packages=packages,
            )
        except Exception as e:
            result = []
            step_errors.append({"step": "outdated_check", "message": str(e)})
        return "outdated", result, step_errors, round(time.time() - step_started, 3)

    hygiene, vulnerabilities, outdated = {}, [], []
    parallel_steps = [run_hygiene_step, run_vulnerability_step, run_outdated_step]
    with ThreadPoolExecutor(max_workers=len(parallel_steps)) as executor:
        futures = [executor.submit(step) for step in parallel_steps]
        for future in as_completed(futures):
            name, result, step_errors, elapsed = future.result()
            step_seconds[name] = elapsed
            errors.extend(step_errors)
            if name == "hygiene":
                hygiene = result
            elif name == "vulnerabilities":
                vulnerabilities = result
            elif name == "outdated":
                outdated = result

    git_repo = is_git_worktree(project_path)
    git_branch = (
        run_cmd(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=project_path)
        if git_repo
        else ""
    )

    output = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "scan_seconds": round(time.time() - started, 1),
        "project": {
            "path": project_path,
            "name": os.path.basename(project_path),
            "ecosystems": ecosystems,
            "lockfiles": list(lockfiles.values()),
            "git_repo": git_repo,
            "git_branch": git_branch or None,
            "total_packages": len(packages),
            "total_vulnerabilities": len(vulnerabilities),
        },
        "scan_config": {
            "api_concurrency": api_concurrency,
            "outdated_concurrency": outdated_concurrency,
            "preflight_file": os.path.abspath(args.preflight) if args.preflight else None,
            "scan_mode": scan_mode,
            "skip_dependency_checks": skip_dependency_checks,
            "skip_hygiene": bool(args.skip_hygiene),
            "skip_outdated": bool(args.skip_outdated),
            "include_packages": bool(args.include_packages),
            "max_secret_files": max(0, int(args.max_secret_files or 0)),
        },
        "output_file": output_file,
        "vibeguard_workspace": {
            "gitignore": (
                ((preflight or {}).get("vibeguard_workspace") or {}).get("gitignore")
                or vibeguard_gitignore_status(project_path)
            ),
        },
        "step_seconds": step_seconds,
        "hygiene": hygiene,
        "package_count": len(packages),
        "package_sources": package_source_summary(packages),
        "vulnerabilities": vulnerabilities,
        "vulnerability_count": len(vulnerabilities),
        "outdated": outdated,
        "outdated_count": len(outdated),
        "errors": errors,
    }
    if args.include_packages:
        output["packages"] = packages
    if args.compact:
        text = json.dumps(output, ensure_ascii=False, separators=(",", ":"))
    else:
        text = json.dumps(output, ensure_ascii=False, indent=2)
    write_json_output(output_file, text)
    print(text)


if __name__ == "__main__":
    sys.exit(main() or 0)
