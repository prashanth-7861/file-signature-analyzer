"""
ML Model Registry with GitHub Releases Integration.

Manages a local registry of ML models, tracks the active model,
and integrates with GitHub Releases for cloud distribution.
"""

import os
import json
import hashlib
import shutil
import subprocess
import urllib.request
import urllib.error
from datetime import datetime


# GitHub repository for model distribution
GITHUB_REPO = "prashanth-7861/file-signature-analyzer"
GITHUB_API_BASE = f"https://api.github.com/repos/{GITHUB_REPO}"


class ModelRegistry:
    """
    Tracks all ML models locally and integrates with GitHub Releases.

    Models are stored in resources/models/ as .pkl files.
    Registry metadata is stored in resources/model_registry.json.
    """

    # Key derivation component beta (used by token_store)
    _KB = bytes.fromhex("b61085835d911c10be92d69bb9a95590")

    # Paths
    _BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    REGISTRY_PATH = os.path.join(_BASE_DIR, "resources", "model_registry.json")
    MODELS_DIR = os.path.join(_BASE_DIR, "resources", "models")
    LEGACY_MODEL_PATH = os.path.join(_BASE_DIR, "resources", "ml_model.pkl")

    def __init__(self):
        """Initialize the model registry."""
        os.makedirs(self.MODELS_DIR, exist_ok=True)
        self.registry = self._load_registry()
        self._migrate_legacy_model()

    def _load_registry(self):
        """Load registry from disk or create empty one."""
        try:
            if os.path.exists(self.REGISTRY_PATH):
                with open(self.REGISTRY_PATH, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                if isinstance(data, dict) and "models" in data:
                    return data
        except (json.JSONDecodeError, OSError):
            pass

        return {
            "version": 1,
            "active_model_id": None,
            "models": [],
            "last_update_check": None
        }

    def _save_registry(self):
        """Save registry to disk."""
        os.makedirs(os.path.dirname(self.REGISTRY_PATH), exist_ok=True)
        with open(self.REGISTRY_PATH, 'w', encoding='utf-8') as f:
            json.dump(self.registry, f, indent=2)

    def _migrate_legacy_model(self):
        """Auto-register resources/ml_model.pkl if not yet tracked."""
        if not os.path.exists(self.LEGACY_MODEL_PATH):
            return

        # Check if already registered by hash
        legacy_hash = self._file_sha256(self.LEGACY_MODEL_PATH)
        for model in self.registry["models"]:
            if model.get("sha256") == legacy_hash:
                return  # Already tracked

        # Register it
        self.register_model(self.LEGACY_MODEL_PATH, source_type="legacy")

    @staticmethod
    def _file_sha256(file_path):
        """Compute SHA-256 hash of a file."""
        h = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def _generate_id():
        """Generate a unique model ID."""
        return hashlib.sha256(os.urandom(32)).hexdigest()[:16]

    def register_model(self, source_path, source_type="loaded", release_tag=None):
        """
        Validate and register a model in the registry.

        Args:
            source_path: Path to the .pkl model file
            source_type: One of "trained", "loaded", "github_release", "legacy"
            release_tag: GitHub release tag if source is github_release

        Returns:
            dict with registration result
        """
        from core.ml_classifier import MLFileClassifier

        # Validate the model
        validation = MLFileClassifier.validate_model(source_path)
        if not validation["valid"]:
            return {"success": False, "error": validation["error"]}

        # Check for duplicate by SHA256
        file_hash = self._file_sha256(source_path)
        for model in self.registry["models"]:
            if model.get("sha256") == file_hash:
                # Already exists, just set as active
                self.registry["active_model_id"] = model["id"]
                self._save_registry()
                return {
                    "success": True,
                    "duplicate": True,
                    "model": model,
                    "message": "Model already registered (same hash)"
                }

        # Generate unique filename and copy to models dir
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ml_model_{timestamp}.pkl"
        dest_path = os.path.join(self.MODELS_DIR, filename)

        # Avoid overwriting
        counter = 1
        while os.path.exists(dest_path):
            filename = f"ml_model_{timestamp}_{counter}.pkl"
            dest_path = os.path.join(self.MODELS_DIR, filename)
            counter += 1

        shutil.copy2(source_path, dest_path)

        # Build model entry
        info = validation["info"]
        model_id = self._generate_id()
        entry = {
            "id": model_id,
            "name": f"ml_model_{timestamp}",
            "filename": filename,
            "sha256": file_hash,
            "date_added": datetime.now().isoformat(),
            "source": source_type,
            "num_classes": info.get("num_classes", 0),
            "cv_accuracy": info.get("cv_accuracy"),
            "num_samples": info.get("num_samples"),
            "github_release_tag": release_tag,
            "file_size_bytes": os.path.getsize(dest_path)
        }

        self.registry["models"].append(entry)
        self.registry["active_model_id"] = model_id
        self._save_registry()

        return {"success": True, "duplicate": False, "model": entry}

    def set_active(self, model_id):
        """Set the active model by ID."""
        for model in self.registry["models"]:
            if model["id"] == model_id:
                self.registry["active_model_id"] = model_id
                self._save_registry()
                return True
        return False

    def get_active_model_path(self):
        """Get the file path of the active model."""
        active_id = self.registry.get("active_model_id")
        if not active_id:
            return None

        for model in self.registry["models"]:
            if model["id"] == active_id:
                path = os.path.join(self.MODELS_DIR, model["filename"])
                if os.path.exists(path):
                    return path
        return None

    def get_active_model_info(self):
        """Get the registry entry for the active model."""
        active_id = self.registry.get("active_model_id")
        if not active_id:
            return None
        for model in self.registry["models"]:
            if model["id"] == active_id:
                return model
        return None

    def get_models(self):
        """Get all registered models."""
        return list(self.registry.get("models", []))

    def check_for_update(self):
        """
        Check GitHub Releases for a newer model.

        Returns:
            dict with update availability info
        """
        try:
            url = f"{GITHUB_API_BASE}/releases/latest"
            req = urllib.request.Request(url, headers={
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "FileSignatureAnalyzer"
            })
            with urllib.request.urlopen(req, timeout=10) as resp:
                release = json.loads(resp.read().decode('utf-8'))

            tag = release.get("tag_name", "")
            assets = release.get("assets", [])

            # Find .pkl asset
            pkl_asset = None
            for asset in assets:
                if asset.get("name", "").endswith(".pkl"):
                    pkl_asset = asset
                    break

            if not pkl_asset:
                return {"available": False, "reason": "No model in latest release"}

            # Check if we already have this release
            for model in self.registry["models"]:
                if model.get("github_release_tag") == tag:
                    return {"available": False, "reason": "Already have latest release"}

            self.registry["last_update_check"] = datetime.now().isoformat()
            self._save_registry()

            return {
                "available": True,
                "tag": tag,
                "asset_name": pkl_asset["name"],
                "download_url": pkl_asset["browser_download_url"],
                "size": pkl_asset.get("size", 0),
                "release_name": release.get("name", tag),
                "published_at": release.get("published_at", "")
            }

        except urllib.error.HTTPError as e:
            return {"available": False, "reason": f"GitHub API error: {e.code}"}
        except urllib.error.URLError as e:
            return {"available": False, "reason": f"Network error: {e.reason}"}
        except Exception as e:
            return {"available": False, "reason": str(e)}

    def download_release_model(self, download_url, asset_name, tag):
        """
        Download a model from a GitHub Release asset.

        Args:
            download_url: Direct download URL for the .pkl asset
            asset_name: Filename of the asset
            tag: Release tag for tracking

        Returns:
            dict with download result
        """
        from core.ml_classifier import MLFileClassifier

        try:
            # Download to temp location first
            temp_path = os.path.join(self.MODELS_DIR, f"_download_{asset_name}")

            req = urllib.request.Request(download_url, headers={
                "User-Agent": "FileSignatureAnalyzer"
            })
            with urllib.request.urlopen(req, timeout=60) as resp:
                with open(temp_path, 'wb') as f:
                    while True:
                        chunk = resp.read(8192)
                        if not chunk:
                            break
                        f.write(chunk)

            # Validate before registering
            validation = MLFileClassifier.validate_model(temp_path)
            if not validation["valid"]:
                os.unlink(temp_path)
                return {"success": False, "error": f"Downloaded model invalid: {validation['error']}"}

            # Register (this copies to final location and sets as active)
            result = self.register_model(temp_path, source_type="github_release", release_tag=tag)

            # Clean up temp file
            if os.path.exists(temp_path):
                os.unlink(temp_path)

            return result

        except Exception as e:
            # Clean up on failure
            temp_path = os.path.join(self.MODELS_DIR, f"_download_{asset_name}")
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            return {"success": False, "error": str(e)}

    def upload_model_to_release(self, model_id=None, tag=None):
        """
        Upload a model to GitHub as a release asset.

        Uses the encrypted API credential for authentication.
        If no model_id specified, uploads the active model.
        If no tag specified, creates a new release with auto-generated tag.

        Args:
            model_id: ID of model to upload (default: active model)
            tag: Release tag to upload to (default: auto-generate)

        Returns:
            dict with upload result
        """
        from core.token_store import get_credential

        credential = get_credential()
        if not credential:
            return {"success": False, "error": "API credential unavailable"}

        # Get model to upload
        if model_id:
            model_entry = None
            for m in self.registry["models"]:
                if m["id"] == model_id:
                    model_entry = m
                    break
        else:
            model_entry = self.get_active_model_info()

        if not model_entry:
            return {"success": False, "error": "No model found to upload"}

        model_path = os.path.join(self.MODELS_DIR, model_entry["filename"])
        if not os.path.exists(model_path):
            return {"success": False, "error": "Model file not found on disk"}

        # Generate tag if not provided
        if not tag:
            tag = f"model-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

        try:
            # Create release
            release_data = json.dumps({
                "tag_name": tag,
                "name": f"ML Model {tag}",
                "body": (
                    f"ML model for file type classification.\n\n"
                    f"- Classes: {model_entry.get('num_classes', '?')}\n"
                    f"- Accuracy: {model_entry.get('cv_accuracy', '?')}%\n"
                    f"- Samples: {model_entry.get('num_samples', '?')}\n"
                    f"- Source: {model_entry.get('source', '?')}"
                ),
                "draft": False,
                "prerelease": False
            }).encode('utf-8')

            req = urllib.request.Request(
                f"{GITHUB_API_BASE}/releases",
                data=release_data,
                method="POST",
                headers={
                    "Accept": "application/vnd.github.v3+json",
                    "Authorization": f"Bearer {credential}",
                    "Content-Type": "application/json",
                    "User-Agent": "FileSignatureAnalyzer"
                }
            )

            with urllib.request.urlopen(req, timeout=30) as resp:
                release = json.loads(resp.read().decode('utf-8'))

            release_id = release["id"]
            upload_url = release["upload_url"].replace("{?name,label}", "")

            # Upload the model file as a release asset
            with open(model_path, 'rb') as f:
                model_data = f.read()

            asset_url = f"{upload_url}?name=ml_model.pkl"
            req = urllib.request.Request(
                asset_url,
                data=model_data,
                method="POST",
                headers={
                    "Accept": "application/vnd.github.v3+json",
                    "Authorization": f"Bearer {credential}",
                    "Content-Type": "application/octet-stream",
                    "User-Agent": "FileSignatureAnalyzer"
                }
            )

            with urllib.request.urlopen(req, timeout=120) as resp:
                asset = json.loads(resp.read().decode('utf-8'))

            # Update model entry with release info
            model_entry["github_release_tag"] = tag
            self._save_registry()

            # Clear credential from memory
            credential = None

            return {
                "success": True,
                "tag": tag,
                "release_url": release.get("html_url", ""),
                "asset_name": asset.get("name", "ml_model.pkl"),
                "asset_size": asset.get("size", 0)
            }

        except urllib.error.HTTPError as e:
            error_body = ""
            try:
                error_body = e.read().decode('utf-8')
            except Exception:
                pass
            credential = None
            return {"success": False, "error": f"GitHub API error {e.code}: {error_body}"}
        except Exception as e:
            credential = None
            return {"success": False, "error": str(e)}
