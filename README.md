# File Signature Analyzer v2.0.0

A powerful Python GUI application for identifying file types based on their binary signatures, machine learning classification, and deep content inspection — regardless of file extensions.

## Features

### Core Analysis
- **Binary signature matching** against 600+ file signatures
- **Deep content inspection** for ZIP-based formats (DOCX, XLSX, PPTX, EPUB, JAR), ISO BMFF (MP4, MOV, HEIC, AVIF), and more
- **3-phase detection pipeline**: Deep inspection -> Signature DB -> ML classifier
- **Shannon entropy calculation** for detecting encrypted/compressed content
- **File hash computation** (MD5, SHA-256)

### Machine Learning Classification
- **RandomForest ML classifier** trained on 31 file types with 99.7% accuracy
- **340-feature extraction**: byte frequency histogram, entropy, bigram frequencies, header bytes, statistical features
- **Auto-update**: App checks GitHub Releases for newer models on startup
- **Model validation**: Validates any `.pkl` model has correct 340-feature structure before loading
- **Local model registry**: Remembers all loaded/trained models across sessions
- **Correction learning**: Record misidentifications to improve future models

### GUI (PyQt5)
- **5-tab interface**: Single File Analysis, Batch Processing, Signature Database, ML Insights, File Comparison
- **Drag-and-drop** file support
- **Batch processing** with cancel support and progress tracking
- **Side-by-side hex comparison** of two files
- **Confidence gauge** and entropy display
- **Dark/light theme** via Fusion style

### Model Management
- **Train Model**: Train new models from labeled file directories
- **Load Model**: Import pre-trained `.pkl` model files (validates 340-feature compatibility)
- **Export Model**: Save the current model to share with others
- **Check for Updates**: Download latest model from GitHub Releases
- **Upload to GitHub**: Publish trained models as GitHub Release assets

## Supported File Types

### ML Classifier (31 types)
| Category | Types |
|----------|-------|
| Images | JPEG, PNG, GIF, BMP, TIFF, WebP, SVG |
| Documents | PDF, DOCX, XLSX, PPTX, EPUB, HTML, XML, JSON, TXT |
| Audio | MP3, WAV, FLAC, OGG |
| Video | MP4, AVI, MKV |
| Archives | ZIP, RAR, 7-Zip |
| Executables | EXE (PE), ELF |
| Source Code | Python, JavaScript |
| Databases | SQLite |

### Signature Database (600+)
The signature database (`resources/file_sigs.json`) covers additional formats beyond the ML classifier including Office legacy formats, ISO images, firmware files, and more.

## Installation

### Requirements
- Python 3.8+
- PyQt5
- scikit-learn
- numpy

### Install Dependencies
```bash
pip install PyQt5 scikit-learn numpy
```

### Optional Dependencies
```bash
pip install matplotlib    # For charts and visualizations
pip install Pillow        # For image metadata extraction
pip install rarfile       # For RAR archive inspection
pip install py7zr         # For 7-Zip archive inspection
```

### Run the App
```bash
python main.py
```

### Pre-built Executables
Download pre-built binaries from [GitHub Releases](https://github.com/prashanth-7861/file-signature-analyzer/releases):
- **Windows**: `File.Signature.Analyzer.exe` (standalone, no Python needed)

## ML Model Guide

### How the ML Model Works
The classifier extracts 340 numerical features from each file:
- **Byte frequency** (256 features): Normalized count of each byte value (0x00-0xFF)
- **Shannon entropy** (1 feature): Randomness measure of the file content
- **Bigram frequencies** (64 features): Most common two-byte sequences
- **File size** (1 feature): Log-scaled file size
- **Header bytes** (16 features): First 16 bytes as normalized integers
- **Statistics** (2 features): Mean and standard deviation of byte values

These features are fed into a RandomForest classifier (100 estimators, max depth 20) that outputs probability scores for each file type.

### Using the Pre-trained Model
The app ships with a pre-trained model at `resources/ml_model.pkl` and auto-checks for updates from GitHub Releases on startup. No setup needed.

### Training a Custom Model

#### Step 1: Organize Training Data
Create a directory with subdirectories named by file type, each containing sample files:
```
training_data/
    JPEG Image/
        photo1.jpg
        photo2.jpg
        ...
    PNG Image/
        image1.png
        ...
    PDF Document/
        doc1.pdf
        ...
```

**Requirements:**
- Minimum 10 files total
- At least 2 file type categories
- More samples per type = better accuracy (20+ recommended)
- Use real files for best results

#### Step 2: Train
**Option A - GUI:**
1. Open the app
2. Go to **Tools -> ML Model -> Train Model**
3. Select your training data directory
4. Wait for training to complete

**Option B - Command line:**
```bash
# Generate synthetic training data (620 files, 31 types)
python generate_training_data.py

# Train the model
python train_model.py
```

#### Step 3: Verify
The trained model is saved to `resources/ml_model.pkl` and automatically loaded on next startup. Check the ML Insights tab to see model status and predictions.

### Training Data Generator
The included `generate_training_data.py` creates synthetic files with proper binary headers for all 31 supported types. This is useful for:
- Initial model training
- Testing the ML pipeline
- Benchmarking accuracy

```bash
python generate_training_data.py
# Creates training_data/ with 620 files across 31 types
```

### Model File Format
Models are Python pickle files (`.pkl`) containing:
```python
{
    "model": RandomForestClassifier,      # Trained sklearn model
    "label_encoder": LabelEncoder,         # Maps class indices to names
    "feature_names": [...],                # List of 340 feature names
    "training_info": {
        "num_samples": 620,
        "num_classes": 31,
        "cv_accuracy": 99.7,
        "classes": ["JPEG Image", "PNG Image", ...],
        "skipped_files": 0
    }
}
```

### Loading External Models
1. Go to **Tools -> ML Model -> Load Model**
2. Select a `.pkl` file
3. The app validates it accepts 340-feature input before loading
4. Valid models are automatically registered and remembered

### Model Update System
- On startup, the app checks GitHub Releases for newer models
- Users can manually check via **Tools -> ML Model -> Check for Updates**
- Downloaded models are validated before activation
- All models are tracked in a local registry (`resources/model_registry.json`)

## Project Structure
```
file-signature-analyzer/
    main.py                      # GUI application (PyQt5)
    core/
        file_analyzer.py         # Signature matching + deep inspection
        ml_classifier.py         # ML classification engine
        model_registry.py        # Model registry + GitHub integration
        metadata_extractor.py    # File metadata extraction
        batch_processor.py       # Batch file processing
        token_store.py           # Encrypted credential storage
    ui/
        hex_viewer.py            # Hex dump viewer
        about_dialog.py          # About dialog
        signature_editor.py      # Signature database editor
        metadata_viewer.py       # Metadata viewer
        convert_dialog.py        # File conversion dialog
    resources/
        file_sigs.json           # Signature database (600+ signatures)
        ml_model.pkl             # Pre-trained ML model
        model_registry.json      # Local model registry
        models/                  # Stored model versions
        icons/                   # Application icons
    generate_training_data.py    # Synthetic training data generator
    train_model.py               # Model training script
```

## Building from Source

### Windows EXE
```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name "File Signature Analyzer" \
    --add-data "resources/file_sigs.json;resources" \
    --add-data "resources/ml_model.pkl;resources" \
    --add-data "resources/icons;resources/icons" \
    --hidden-import sklearn --hidden-import sklearn.ensemble \
    --hidden-import sklearn.ensemble._forest \
    --hidden-import sklearn.tree --hidden-import sklearn.tree._classes \
    --hidden-import sklearn.preprocessing --hidden-import sklearn.preprocessing._label \
    --hidden-import numpy \
    main.py
```
Output: `dist/File Signature Analyzer.exe`

## Contributing

### Contributing Models
If you've trained a better model:
1. Fork this repository
2. Add your trained model to `resources/ml_model.pkl`
3. Include your training data or describe your dataset
4. Submit a Pull Request with accuracy metrics

### Bug Reports
Open an issue on [GitHub Issues](https://github.com/prashanth-7861/file-signature-analyzer/issues).

## License

This project is open source. See the repository for license details.

## Changelog

### v2.0.0
- Fixed 14+ bugs in signature matching (SVG/XML ordering, JSON validation, MP4 ftyp detection, ZIP extension pollution, etc.)
- Added ML classification engine with RandomForest (31 types, 99.7% accuracy)
- Added 5-tab GUI with ML Insights and File Comparison tabs
- Added model registry with GitHub Releases integration
- Added drag-and-drop, entropy calculation, file hashing (MD5/SHA-256)
- Added batch processing with cancel support
- Added model validation (340-feature compatibility check)
- Added training data generator for 31 file types
- Added encrypted GitHub API integration for model distribution

### v1.0.0
- Initial release with signature-based file type detection
- Basic GUI with single file and batch analysis
- Signature database with 600+ file types
