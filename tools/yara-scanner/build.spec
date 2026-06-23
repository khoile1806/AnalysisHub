# PyInstaller spec — single-file binary bundling rules/ + templates/.
# Run: pyinstaller build.spec  →  dist/yara-scanner(.exe)

import os
from PyInstaller.utils.hooks import collect_submodules

block_cipher = None
ROOT = os.path.dirname(os.path.abspath(SPEC))

a = Analysis(
    [os.path.join(ROOT, "scanner", "cli.py")],
    pathex=[ROOT],
    binaries=[],
    datas=[
        (os.path.join(ROOT, "rules"), "rules"),
        (os.path.join(ROOT, "templates"), "templates"),
    ],
    hiddenimports=collect_submodules("scanner"),
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="yara-scanner",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
