"""
Machine Learning File Type Classifier

Uses byte-level features and statistical analysis to classify files
when signature-based matching is ambiguous or unavailable.
Requires scikit-learn for model training/prediction (optional dependency).
"""

import os
import json
import math
import pickle
import struct
from collections import Counter


class MLFileClassifier:
    """ML-based file type classifier using byte-level features."""

    # Key derivation component gamma (used by token_store)
    _KC = bytes.fromhex("53267df7994b6f104247d5b06de02144")

    # Default model path
    MODEL_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              "resources", "ml_model.pkl")
    CORRECTIONS_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                     "resources", "ml_corrections.json")

    # File type to extension mapping for predictions
    TYPE_TO_EXT = {
        "JPEG Image": "jpg",
        "PNG Image": "png",
        "GIF Image": "gif",
        "BMP Image": "bmp",
        "TIFF Image": "tiff",
        "WebP Image": "webp",
        "PDF Document": "pdf",
        "ZIP Archive": "zip",
        "Microsoft Word Document": "docx",
        "Microsoft Excel Spreadsheet": "xlsx",
        "Microsoft PowerPoint Presentation": "pptx",
        "MP3 Audio": "mp3",
        "WAV Audio": "wav",
        "MP4 Video": "mp4",
        "AVI Video": "avi",
        "MKV Video": "mkv",
        "EPUB eBook": "epub",
        "HTML Document": "html",
        "XML Document": "xml",
        "JSON Data": "json",
        "Text File": "txt",
        "Python Source": "py",
        "JavaScript Source": "js",
        "EXE Executable": "exe",
        "ELF Executable": "elf",
        "RAR Archive": "rar",
        "7-Zip Archive": "7z",
        "FLAC Audio": "flac",
        "OGG Audio": "ogg",
        "SVG Image": "svg",
        "SQLite Database": "sqlite",
    }

    def __init__(self, model_path=None):
        """
        Initialize the ML classifier.

        Args:
            model_path: Optional path to a pre-trained model file
        """
        self.model = None
        self.label_encoder = None
        self.model_path = model_path or self.MODEL_PATH
        self.feature_names = []
        self._load_model()

    def _load_model(self):
        """Load a pre-trained model from disk if available."""
        try:
            if os.path.exists(self.model_path):
                with open(self.model_path, 'rb') as f:
                    data = pickle.load(f)
                    self.model = data.get('model')
                    self.label_encoder = data.get('label_encoder')
                    self.feature_names = data.get('feature_names', [])
        except Exception as e:
            print(f"ML Classifier: Could not load model: {e}")
            self.model = None

    def load_model(self, model_path):
        """
        Load a model from a specific file path.

        Args:
            model_path: Path to the .pkl model file

        Returns:
            Dict with load result info
        """
        old_model = self.model
        old_encoder = self.label_encoder
        old_features = self.feature_names
        old_path = self.model_path

        try:
            if not os.path.exists(model_path):
                return {"success": False, "error": f"File not found: {model_path}"}

            with open(model_path, 'rb') as f:
                data = pickle.load(f)

            model = data.get('model')
            label_encoder = data.get('label_encoder')

            if model is None or label_encoder is None:
                return {"success": False, "error": "Invalid model file: missing model or label_encoder"}

            self.model = model
            self.label_encoder = label_encoder
            self.feature_names = data.get('feature_names', [])
            self.model_path = model_path

            training_info = data.get('training_info', {})
            return {
                "success": True,
                "num_classes": training_info.get('num_classes', len(label_encoder.classes_)),
                "classes": list(label_encoder.classes_),
                "cv_accuracy": training_info.get('cv_accuracy'),
                "num_samples": training_info.get('num_samples'),
                "model_path": model_path
            }

        except Exception as e:
            # Restore previous state on failure
            self.model = old_model
            self.label_encoder = old_encoder
            self.feature_names = old_features
            self.model_path = old_path
            return {"success": False, "error": str(e)}

    def export_model(self, export_path):
        """
        Export the current loaded model to a file.

        Args:
            export_path: Destination path for the .pkl file

        Returns:
            Dict with export result info
        """
        if not self.is_model_loaded():
            return {"success": False, "error": "No model is currently loaded"}

        try:
            os.makedirs(os.path.dirname(export_path), exist_ok=True)
            model_data = {
                'model': self.model,
                'label_encoder': self.label_encoder,
                'feature_names': self.feature_names,
            }
            # Preserve training_info if available from current model path
            try:
                if os.path.exists(self.model_path):
                    with open(self.model_path, 'rb') as f:
                        original = pickle.load(f)
                    model_data['training_info'] = original.get('training_info', {})
            except Exception:
                pass

            with open(export_path, 'wb') as f:
                pickle.dump(model_data, f)

            return {"success": True, "model_path": export_path}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def is_model_loaded(self):
        """Check if a trained model is available."""
        return self.model is not None and self.label_encoder is not None

    @staticmethod
    def extract_features(file_path, max_read=4096):
        """
        Extract numerical features from a file for ML classification.

        Features extracted:
        - Byte frequency histogram (256 values, normalized)
        - Shannon entropy
        - Top 64 bigram frequencies
        - File size (log-scaled)
        - First 16 bytes as integer values
        - Statistical features (mean, std, median byte values)

        Args:
            file_path: Path to the file
            max_read: Maximum bytes to read for analysis

        Returns:
            List of float features (~340 features)
        """
        features = []

        try:
            file_size = os.path.getsize(file_path)

            with open(file_path, 'rb') as f:
                data = f.read(max_read)

            if not data:
                return [0.0] * 340

            # === Feature Group 1: Byte frequency histogram (256 features) ===
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            total = len(data)
            byte_freq = [count / total for count in byte_counts]
            features.extend(byte_freq)

            # === Feature Group 2: Shannon entropy (1 feature) ===
            entropy = 0.0
            for freq in byte_freq:
                if freq > 0:
                    entropy -= freq * math.log2(freq)
            features.append(entropy)

            # === Feature Group 3: Bigram frequencies (64 features) ===
            if len(data) > 1:
                bigrams = Counter()
                for i in range(len(data) - 1):
                    bigrams[(data[i], data[i + 1])] += 1
                # Get top 64 most common bigrams, normalized
                top_bigrams = bigrams.most_common(64)
                bigram_total = sum(bigrams.values()) or 1
                bigram_features = [count / bigram_total for _, count in top_bigrams]
                # Pad to exactly 64 if fewer found
                bigram_features.extend([0.0] * (64 - len(bigram_features)))
                features.extend(bigram_features)
            else:
                features.extend([0.0] * 64)

            # === Feature Group 4: File size, log-scaled (1 feature) ===
            features.append(math.log2(file_size + 1))

            # === Feature Group 5: First 16 bytes as integers (16 features) ===
            header_bytes = list(data[:16])
            header_bytes.extend([0] * (16 - len(header_bytes)))
            features.extend([b / 255.0 for b in header_bytes])

            # === Feature Group 6: Statistical features (2 features) ===
            byte_values = list(data[:min(1024, len(data))])
            if not byte_values:
                features.extend([0.0, 0.0])
            else:
                mean_val = sum(byte_values) / len(byte_values)
                variance = sum((b - mean_val) ** 2 for b in byte_values) / len(byte_values)
                std_val = math.sqrt(variance)
                features.append(mean_val / 255.0)
                features.append(std_val / 128.0)

        except Exception as e:
            print(f"ML Feature extraction error: {e}")
            features = [0.0] * 340

        # Ensure consistent feature length
        target_len = 340
        if len(features) < target_len:
            features.extend([0.0] * (target_len - len(features)))
        elif len(features) > target_len:
            features = features[:target_len]

        return features

    def predict(self, file_path):
        """
        Predict file type using the ML model.

        Args:
            file_path: Path to the file to classify

        Returns:
            List of (file_type, confidence_pct, extension) tuples, sorted by confidence
        """
        if not self.is_model_loaded():
            return []

        try:
            features = self.extract_features(file_path)
            # Reshape for sklearn
            import numpy as np
            X = np.array(features).reshape(1, -1)

            # Get probability predictions
            probabilities = self.model.predict_proba(X)[0]
            classes = self.label_encoder.classes_

            # Create sorted predictions
            predictions = []
            for cls, prob in zip(classes, probabilities):
                confidence = round(float(prob) * 100, 1)
                ext = self.TYPE_TO_EXT.get(cls, "")
                predictions.append((cls, confidence, ext))

            # Sort by confidence descending
            predictions.sort(key=lambda x: x[1], reverse=True)

            # Return top 5 predictions
            return predictions[:5]

        except Exception as e:
            print(f"ML Prediction error: {e}")
            return []

    def train(self, labeled_data_dir, save_path=None):
        """
        Train the classifier on a labeled dataset.

        Directory structure should be:
            labeled_data_dir/
                JPEG Image/
                    file1.jpg
                    file2.jpg
                PNG Image/
                    file1.png
                PDF Document/
                    file1.pdf
                ...

        Args:
            labeled_data_dir: Path to directory with labeled files
            save_path: Where to save the trained model (defaults to MODEL_PATH)

        Returns:
            Dict with training results (accuracy, num_samples, etc.)
        """
        try:
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.preprocessing import LabelEncoder
            from sklearn.model_selection import cross_val_score
            import numpy as np
        except ImportError:
            return {
                "success": False,
                "error": "scikit-learn is required for training. Install with: pip install scikit-learn"
            }

        features_list = []
        labels = []
        skipped = 0

        # Scan directory structure
        if not os.path.isdir(labeled_data_dir):
            return {"success": False, "error": f"Directory not found: {labeled_data_dir}"}

        for label_name in os.listdir(labeled_data_dir):
            label_dir = os.path.join(labeled_data_dir, label_name)
            if not os.path.isdir(label_dir):
                continue

            for filename in os.listdir(label_dir):
                file_path = os.path.join(label_dir, filename)
                if not os.path.isfile(file_path):
                    continue

                try:
                    features = self.extract_features(file_path)
                    features_list.append(features)
                    labels.append(label_name)
                except Exception:
                    skipped += 1
                    continue

        if len(features_list) < 10:
            return {
                "success": False,
                "error": f"Not enough training data. Found {len(features_list)} files, need at least 10."
            }

        # Convert to numpy arrays
        X = np.array(features_list)
        le = LabelEncoder()
        y = le.fit_transform(labels)

        # Train Random Forest
        clf = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            min_samples_split=3,
            min_samples_leaf=1,
            random_state=42,
            n_jobs=-1
        )

        # Cross-validation
        n_splits = min(5, len(set(labels)))
        if n_splits >= 2 and len(features_list) >= n_splits * 2:
            cv_scores = cross_val_score(clf, X, y, cv=n_splits, scoring='accuracy')
            cv_accuracy = round(cv_scores.mean() * 100, 1)
        else:
            cv_accuracy = None

        # Train on full dataset
        clf.fit(X, y)

        # Save model
        save_path = save_path or self.model_path
        os.makedirs(os.path.dirname(save_path), exist_ok=True)

        model_data = {
            'model': clf,
            'label_encoder': le,
            'feature_names': [f"feature_{i}" for i in range(X.shape[1])],
            'training_info': {
                'num_samples': len(features_list),
                'num_classes': len(set(labels)),
                'classes': list(le.classes_),
                'cv_accuracy': cv_accuracy,
                'skipped_files': skipped
            }
        }

        with open(save_path, 'wb') as f:
            pickle.dump(model_data, f)

        # Update instance
        self.model = clf
        self.label_encoder = le

        return {
            "success": True,
            "num_samples": len(features_list),
            "num_classes": len(set(labels)),
            "classes": list(le.classes_),
            "cv_accuracy": cv_accuracy,
            "skipped_files": skipped,
            "model_path": save_path
        }

    def record_correction(self, file_path, correct_type):
        """
        Record a user correction for future retraining.

        Args:
            file_path: Path to the misidentified file
            correct_type: The correct file type string
        """
        corrections = []

        # Load existing corrections
        if os.path.exists(self.CORRECTIONS_PATH):
            try:
                with open(self.CORRECTIONS_PATH, 'r', encoding='utf-8') as f:
                    corrections = json.load(f)
            except (json.JSONDecodeError, IOError):
                corrections = []

        # Extract features and store correction
        features = self.extract_features(file_path)
        correction = {
            "file_path": file_path,
            "correct_type": correct_type,
            "features": features,
            "timestamp": _get_timestamp()
        }
        corrections.append(correction)

        # Save corrections
        os.makedirs(os.path.dirname(self.CORRECTIONS_PATH), exist_ok=True)
        with open(self.CORRECTIONS_PATH, 'w', encoding='utf-8') as f:
            json.dump(corrections, f, indent=2)

    def get_correction_count(self):
        """Get the number of stored corrections."""
        if os.path.exists(self.CORRECTIONS_PATH):
            try:
                with open(self.CORRECTIONS_PATH, 'r', encoding='utf-8') as f:
                    corrections = json.load(f)
                    return len(corrections)
            except (json.JSONDecodeError, IOError):
                pass
        return 0

    def get_model_info(self):
        """Get information about the loaded model."""
        if not self.is_model_loaded():
            return {
                "loaded": False,
                "message": "No model loaded. Train a model first."
            }

        info = {
            "loaded": True,
            "model_path": self.model_path,
            "num_classes": len(self.label_encoder.classes_),
            "classes": list(self.label_encoder.classes_),
            "corrections_pending": self.get_correction_count()
        }

        # Try to get training info from saved model
        try:
            with open(self.model_path, 'rb') as f:
                data = pickle.load(f)
                training_info = data.get('training_info', {})
                info.update(training_info)
        except Exception:
            pass

        return info

    @staticmethod
    def validate_model(model_path):
        """
        Validate that a .pkl file has the correct structure for this app.

        Checks that the file can be loaded, contains the required keys,
        and that the model accepts 340-feature input vectors.

        Args:
            model_path: Path to the .pkl model file

        Returns:
            dict with keys:
                valid (bool): Whether the model is valid
                error (str|None): Error message if invalid
                info (dict|None): Model metadata if valid
        """
        if not os.path.exists(model_path):
            return {"valid": False, "error": "File not found", "info": None}

        try:
            with open(model_path, 'rb') as f:
                data = pickle.load(f)
        except Exception as e:
            return {"valid": False, "error": f"Cannot load pickle file: {e}", "info": None}

        if not isinstance(data, dict):
            return {"valid": False, "error": "Model file must contain a dictionary", "info": None}

        model = data.get('model')
        label_encoder = data.get('label_encoder')

        if model is None:
            return {"valid": False, "error": "Missing 'model' key in model file", "info": None}

        if label_encoder is None:
            return {"valid": False, "error": "Missing 'label_encoder' key in model file", "info": None}

        if not hasattr(label_encoder, 'classes_'):
            return {"valid": False, "error": "Invalid label_encoder: missing classes_", "info": None}

        # Test that the model accepts 340-feature input
        try:
            import numpy as np
            test_input = np.zeros((1, 340))
            model.predict_proba(test_input)
        except Exception as e:
            return {
                "valid": False,
                "error": f"Model incompatible with 340-feature input: {e}",
                "info": None
            }

        # Extract metadata
        training_info = data.get('training_info', {})
        info = {
            "num_classes": len(label_encoder.classes_),
            "classes": list(label_encoder.classes_),
            "cv_accuracy": training_info.get('cv_accuracy'),
            "num_samples": training_info.get('num_samples'),
            "feature_count": len(data.get('feature_names', [])) or 340,
        }

        return {"valid": True, "error": None, "info": info}


def _get_timestamp():
    """Get current timestamp as ISO string."""
    from datetime import datetime
    return datetime.now().isoformat()
