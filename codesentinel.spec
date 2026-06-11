# codesentinel.spec
# PyInstaller build spec for CodeSentinel
# Build command:  pyinstaller codesentinel.spec
# Output:         dist/CodeSentinel  (folder)  or dist/CodeSentinel.exe  (Windows)
#
# For a true single-file exe, change onedir=False → onefile=True below.
# onedir is recommended for first distribution as it starts faster.

import sys
from pathlib import Path

block_cipher = None

a = Analysis(
    ['codesentinel.py'],
    pathex=[str(Path(__file__).parent)],
    binaries=[],
    datas=[
        # Bundle the customtkinter theme assets
        (
            str(Path(__import__('customtkinter').__file__).parent),
            'customtkinter'
        ),
    ],
    hiddenimports=[
        'customtkinter',
        'tkinter',
        'tkinter.filedialog',
        'tkinter.messagebox',
        'httpx',
        'httpcore',
        'anyio',
        'certifi',
        'charset_normalizer',
        'idna',
        'h11',
        'sniffio',
        'packaging',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['matplotlib', 'numpy', 'PIL', 'PyQt5', 'wx'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='CodeSentinel',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,          # No terminal window on Windows
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,              # Replace with 'assets/icon.ico' once you have one
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='CodeSentinel',
)
