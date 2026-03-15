# -*- mode: python ; coding: utf-8 -*-
# Optimized PyInstaller spec — strips ~80MB of unused scipy/sklearn/PyQt5/matplotlib bloat

import sys
import os

block_cipher = None

# ── Massive exclusion list ──────────────────────────────────────────
# We only need: sklearn.ensemble._forest, sklearn.preprocessing._label,
# scipy.sparse (basic), numpy core, PyQt5.QtWidgets/Core/Gui
EXCLUDES = [
    # ── scipy subpackages we never call ──
    'scipy.integrate',
    'scipy.interpolate',
    'scipy.optimize',
    'scipy.signal',
    'scipy.ndimage',
    'scipy.spatial',
    'scipy.stats',
    'scipy.fft',
    'scipy.io',
    'scipy.linalg',
    'scipy.constants',
    'scipy.cluster',
    'scipy.odr',
    'scipy.misc',
    'scipy.special',

    # ── sklearn subpackages unused at inference time ──
    'sklearn.cluster',
    'sklearn.compose',
    'sklearn.covariance',
    'sklearn.cross_decomposition',
    'sklearn.datasets',
    'sklearn.decomposition',
    'sklearn.discriminant_analysis',
    'sklearn.experimental',
    'sklearn.externals',
    'sklearn.feature_extraction',
    'sklearn.feature_selection',
    'sklearn.gaussian_process',
    'sklearn.impute',
    'sklearn.inspection',
    'sklearn.isotonic',
    'sklearn.kernel_approximation',
    'sklearn.kernel_ridge',
    'sklearn.linear_model',
    'sklearn.manifold',
    'sklearn.metrics',
    'sklearn.mixture',
    'sklearn.model_selection',
    'sklearn.multiclass',
    'sklearn.multioutput',
    'sklearn.naive_bayes',
    'sklearn.neighbors',
    'sklearn.neural_network',
    'sklearn.pipeline',
    'sklearn.semi_supervised',
    'sklearn.svm',
    'sklearn.calibration',

    # ── PyQt5 modules we never import ──
    'PyQt5.QtWebEngine',
    'PyQt5.QtWebEngineCore',
    'PyQt5.QtWebEngineWidgets',
    'PyQt5.QtWebChannel',
    'PyQt5.QtWebSockets',
    'PyQt5.QtNetwork',
    'PyQt5.QtNetworkAuth',
    'PyQt5.QtMultimedia',
    'PyQt5.QtMultimediaWidgets',
    'PyQt5.QtBluetooth',
    'PyQt5.QtDBus',
    'PyQt5.QtDesigner',
    'PyQt5.QtHelp',
    'PyQt5.QtLocation',
    'PyQt5.QtNfc',
    'PyQt5.QtOpenGL',
    'PyQt5.QtPositioning',
    'PyQt5.QtPrintSupport',
    'PyQt5.QtQml',
    'PyQt5.QtQuick',
    'PyQt5.QtQuickWidgets',
    'PyQt5.QtRemoteObjects',
    'PyQt5.QtSensors',
    'PyQt5.QtSerialPort',
    'PyQt5.QtSql',
    'PyQt5.QtSvg',
    'PyQt5.QtTest',
    'PyQt5.QtTextToSpeech',
    'PyQt5.QtWinExtras',
    'PyQt5.QtXml',
    'PyQt5.QtXmlPatterns',

    # ── matplotlib backends we don't need ──
    'matplotlib.backends.backend_tkagg',
    'matplotlib.backends.backend_gtk3agg',
    'matplotlib.backends.backend_gtk3cairo',
    'matplotlib.backends.backend_wxagg',
    'matplotlib.backends.backend_webagg',
    'matplotlib.backends.backend_nbagg',
    'matplotlib.backends.backend_pdf',
    'matplotlib.backends.backend_pgf',
    'matplotlib.backends.backend_ps',
    'matplotlib.backends.backend_svg',
    'matplotlib.backends.backend_cairo',
    'tkinter',
    '_tkinter',

    # ── Other unused large packages ──
    'IPython',
    'notebook',
    'sphinx',
    'docutils',
    'PIL.ImageQt',
    'pandas',
    'pytest',
    'setuptools',
    'pkg_resources',
    'unittest',
    'pydoc',
    'xmlrpc',
    'lib2to3',
    'test',
    'curses',
]

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('resources/file_sigs.json', 'resources'),
        ('resources/ml_model.pkl', 'resources'),
        ('resources/icons', 'resources/icons'),
    ],
    hiddenimports=[
        'sklearn.ensemble._forest',
        'sklearn.preprocessing._label',
        'sklearn.tree._tree',
        'sklearn.tree._classes',
        'sklearn.utils._typedefs',
        'sklearn.utils._heap',
        'sklearn.utils._sorting',
        'sklearn.utils._vector_sentinel',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=EXCLUDES,
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

# ── Strip unnecessary binaries from the collected set ──
# Remove .pdb debug files, test files, locale data we don't need
a.binaries = [
    b for b in a.binaries
    if not any(x in b[0].lower() for x in [
        '.pdb', 'test', 'qt5web', 'qt5designer', 'qt5quick',
        'qt5qml', 'qt5multimedia', 'qt5bluetooth', 'qt5nfc',
        'qt5location', 'qt5sensors', 'qt5serialport', 'qt5sql',
        'qt5svg', 'qt5xml', 'qt5print', 'qt5opengl', 'qt5dbus',
        'qt5network', 'qt5remote', 'qt5texttospeech',
        'd3dcompiler', 'opengl32sw', 'libglesv2', 'libegl',
        'qt5pdf', 'qt5help',
    ])
]

# ── Strip unnecessary data files ──
a.datas = [
    d for d in a.datas
    if not any(x in d[0].lower() for x in [
        'translations', 'qml', 'qt5_plugins/sqldrivers',
        'qt5_plugins/mediaservice', 'qt5_plugins/geoservices',
        'qt5_plugins/sceneparsers', 'qt5_plugins/renderers',
        'qt5_plugins/position', 'qt5_plugins/sensorgestures',
        'qt5_plugins/texttospeech', 'qt5_plugins/webview',
        'mpl-data/fonts', 'mpl-data/sample_data',
        'mpl-data/images', 'certifi',
    ])
]

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='File Signature Analyzer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)
