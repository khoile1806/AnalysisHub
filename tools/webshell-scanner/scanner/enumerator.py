from __future__ import annotations

import fnmatch
import os
from collections.abc import Iterator
from pathlib import Path

SCAN_EXTENSIONS: frozenset[str] = frozenset({
    ".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".phar",
    ".asp", ".aspx", ".ashx", ".asmx",
    ".jsp", ".jspx", ".jspf",
    ".py", ".pyc",
    ".pl", ".pm", ".cgi",
    ".sh", ".bash",
    ".cfm", ".cfc",
    ".rb",
    ".js", ".mjs",
    ".htaccess",
})

SKIP_DIRS: frozenset[str] = frozenset({
    ".git", ".svn", ".hg",
    "node_modules", "vendor",
    "__pycache__", ".pytest_cache",
    ".venv", "venv", "env",
    "proc", "sys", "dev",
})


def _ext(path: Path) -> str:
    name = path.name.lower()
    if name in {".htaccess", "htaccess"}:
        return ".htaccess"
    return path.suffix.lower()


def enumerate_targets(
    targets: list[str],
    *,
    max_size_mb: float = 50.0,
    excludes: list[str] | None = None,
    follow_symlinks: bool = False,
) -> Iterator[Path]:
    """Walk targets and yield candidate file paths.

    A target may be a single file or a directory. Files are filtered by
    extension allowlist, size, and exclude globs. Skips well-known noise
    directories and symlinks-out-of-scope unless ``follow_symlinks`` is set.
    """
    excludes = excludes or []
    max_bytes = int(max_size_mb * 1024 * 1024)

    for raw in targets:
        root = Path(raw).expanduser()
        if not root.exists():
            continue

        if root.is_file():
            if _accept_file(root, max_bytes, excludes):
                yield root.resolve()
            continue

        for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
            for fname in filenames:
                p = Path(dirpath) / fname
                if _accept_file(p, max_bytes, excludes):
                    try:
                        yield p.resolve()
                    except OSError:
                        continue


def _accept_file(path: Path, max_bytes: int, excludes: list[str]) -> bool:
    ext = _ext(path)
    if ext not in SCAN_EXTENSIONS:
        return False
    try:
        st = path.stat()
    except OSError:
        return False
    if st.st_size == 0 or st.st_size > max_bytes:
        return False
    sp = str(path).replace("\\", "/")
    return not any(fnmatch.fnmatch(sp, g) for g in excludes)
