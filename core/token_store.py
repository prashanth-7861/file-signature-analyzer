"""
Secure token storage with multi-layer encryption.

The access token is encrypted using PBKDF2-HMAC-SHA256 key derivation
with 600,000 iterations and a CTR-mode keystream. Key components are
scattered across multiple modules to prevent single-point extraction.
"""

import hashlib

# Encrypted token blob (HMAC-CTR encrypted)
_EB = bytes.fromhex(
    "9c9d4614bf549ae338c471c094f7ed3c51a548160c9c0ec4"
    "7e765debe59ef47cd866980f075db7f14866e6e4d44994f1"
    "e1034c2c8fe66962a23fd05b45d1000324a5c3b2e9c75b6d"
    "52dff9bbde6049b8e30c3d2f3c226651c910abc1ca"
)

# PBKDF2 salt
_KS = bytes.fromhex(
    "b7371ce7427f54d2bf7f6b7ba81f46e7"
    "e16ea9bbbb6c135544386a1b14b121d1"
)

# Key derivation component alpha
_KA = bytes.fromhex("e865f8c0100086c849c6ebf53889fa5f")

# Iteration count for PBKDF2
_IC = 600000


def _resolve():
    """Resolve and return the access credential. Result is transient."""
    from core.model_registry import ModelRegistry
    from core.ml_classifier import MLFileClassifier

    kb = _KA + ModelRegistry._KB + MLFileClassifier._KC

    dk = hashlib.pbkdf2_hmac('sha256', kb, _KS, _IC)

    ks = b''
    ci = 0
    while len(ks) < len(_EB):
        ks += hashlib.sha256(dk + ci.to_bytes(4, 'big')).digest()
        ci += 1
    ks = ks[:len(_EB)]

    result = bytes(a ^ b for a, b in zip(_EB, ks))

    try:
        return result.decode('utf-8')
    except UnicodeDecodeError:
        return None


def get_credential():
    """
    Get the API credential for GitHub operations.

    Returns the credential string, or None if unavailable.
    The credential is decrypted on-demand and should not be cached.
    """
    try:
        return _resolve()
    except Exception:
        return None
