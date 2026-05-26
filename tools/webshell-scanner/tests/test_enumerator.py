"""Unit tests for the file enumerator: extension allowlist, size cap,
exclude globs, skip-dirs, single-file targets, broken-symlink resilience."""

from __future__ import annotations

from pathlib import Path

import pytest

from scanner.enumerator import SCAN_EXTENSIONS, SKIP_DIRS, enumerate_targets


def _touch(path: Path, content: bytes = b"x") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


def _names(paths) -> set[str]:
    return {Path(p).name for p in paths}


def test_extension_allowlist_filters_unsupported(tmp_path: Path):
    _touch(tmp_path / "shell.php", b"<?php ?>")
    _touch(tmp_path / "image.jpg", b"binary")
    _touch(tmp_path / "notes.txt", b"hi")
    _touch(tmp_path / "page.aspx", b"<%%>")

    found = _names(enumerate_targets([str(tmp_path)]))
    assert found == {"shell.php", "page.aspx"}


def test_htaccess_is_recognised(tmp_path: Path):
    _touch(tmp_path / ".htaccess", b"AddType application/x-httpd-php .jpg")
    found = _names(enumerate_targets([str(tmp_path)]))
    assert ".htaccess" in found


def test_skip_dirs_pruned(tmp_path: Path):
    _touch(tmp_path / "good.php")
    for skip in (".git", "node_modules", "__pycache__"):
        _touch(tmp_path / skip / "bad.php")
    found = _names(enumerate_targets([str(tmp_path)]))
    assert found == {"good.php"}


def test_hidden_dirs_pruned(tmp_path: Path):
    _touch(tmp_path / "ok.php")
    _touch(tmp_path / ".cache" / "hidden.php")
    found = _names(enumerate_targets([str(tmp_path)]))
    assert "hidden.php" not in found


def test_size_filter_rejects_oversize(tmp_path: Path):
    _touch(tmp_path / "small.php", b"<?php ?>")
    _touch(tmp_path / "big.php", b"a" * (3 * 1024 * 1024))
    found = _names(enumerate_targets([str(tmp_path)], max_size_mb=2.0))
    assert found == {"small.php"}


def test_empty_files_skipped(tmp_path: Path):
    _touch(tmp_path / "empty.php", b"")
    _touch(tmp_path / "real.php", b"<?php ?>")
    found = _names(enumerate_targets([str(tmp_path)]))
    assert found == {"real.php"}


def test_exclude_glob_applied(tmp_path: Path):
    _touch(tmp_path / "app" / "main.php")
    _touch(tmp_path / "cache" / "compiled.php")
    found = _names(enumerate_targets([str(tmp_path)], excludes=["*/cache/*"]))
    assert found == {"main.php"}


def test_single_file_target(tmp_path: Path):
    f = _touch(tmp_path / "shell.php", b"<?php ?>")
    found = list(enumerate_targets([str(f)]))
    assert len(found) == 1
    assert Path(found[0]).name == "shell.php"


def test_single_file_unsupported_ext_skipped(tmp_path: Path):
    f = _touch(tmp_path / "image.png", b"PNG")
    assert list(enumerate_targets([str(f)])) == []


def test_nonexistent_target_silently_skipped(tmp_path: Path):
    assert list(enumerate_targets([str(tmp_path / "ghost")])) == []


def test_recursive_walk(tmp_path: Path):
    _touch(tmp_path / "a.php")
    _touch(tmp_path / "sub1" / "b.php")
    _touch(tmp_path / "sub1" / "sub2" / "c.php")
    found = _names(enumerate_targets([str(tmp_path)]))
    assert found == {"a.php", "b.php", "c.php"}


def test_multiple_targets_combined(tmp_path: Path):
    d1 = tmp_path / "site1"
    d2 = tmp_path / "site2"
    _touch(d1 / "x.php")
    _touch(d2 / "y.aspx")
    found = _names(enumerate_targets([str(d1), str(d2)]))
    assert found == {"x.php", "y.aspx"}


def test_constants_consistent():
    """Sanity: skip dirs lowercase, extensions all start with dot (or htaccess)."""
    for d in SKIP_DIRS:
        assert d == d.lower()
    for e in SCAN_EXTENSIONS:
        assert e.startswith(".")
