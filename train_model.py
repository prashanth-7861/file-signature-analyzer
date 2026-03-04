"""
Train the ML model using the generated training data.
"""

import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.ml_classifier import MLFileClassifier

TRAINING_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "training_data")
MODEL_OUTPUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "resources", "ml_model.pkl")


def main():
    print("=" * 60)
    print("ML File Type Classifier - Training")
    print("=" * 60)
    print(f"\nTraining data: {TRAINING_DATA_DIR}")
    print(f"Model output:  {MODEL_OUTPUT}")

    # Create classifier instance (no model loaded yet is fine)
    classifier = MLFileClassifier()

    print("\nStarting training...")
    result = classifier.train(TRAINING_DATA_DIR, save_path=MODEL_OUTPUT)

    if result.get("success"):
        print(f"\nTraining SUCCESSFUL!")
        print(f"  Samples:          {result['num_samples']}")
        print(f"  Classes:          {result['num_classes']}")
        print(f"  Cross-val acc:    {result['cv_accuracy']}%")
        print(f"  Skipped files:    {result['skipped_files']}")
        print(f"  Model saved to:   {result['model_path']}")
        print(f"\n  File types trained:")
        for cls in sorted(result['classes']):
            print(f"    - {cls}")
    else:
        print(f"\nTraining FAILED: {result.get('error', 'Unknown error')}")
        return 1

    # Verify the model loads correctly
    print("\n" + "=" * 60)
    print("Verifying model loads correctly...")
    test_classifier = MLFileClassifier(model_path=MODEL_OUTPUT)
    info = test_classifier.get_model_info()
    if info.get("loaded"):
        print(f"  Model loaded successfully!")
        print(f"  Classes: {info['num_classes']}")
    else:
        print(f"  WARNING: Model failed to reload!")
        return 1

    # Run predictions on a few sample files
    print("\n" + "=" * 60)
    print("Running sample predictions...")
    test_files = [
        ("training_data/JPEG Image/sample_0.jpg", "JPEG Image"),
        ("training_data/PNG Image/sample_0.png", "PNG Image"),
        ("training_data/PDF Document/sample_0.pdf", "PDF Document"),
        ("training_data/MP4 Video/sample_0.mp4", "MP4 Video"),
        ("training_data/HTML Document/sample_0.html", "HTML Document"),
        ("training_data/JSON Data/sample_0.json", "JSON Data"),
        ("training_data/Python Source/sample_0.py", "Python Source"),
        ("training_data/EXE Executable/sample_0.exe", "EXE Executable"),
        ("training_data/SQLite Database/sample_0.sqlite", "SQLite Database"),
        ("training_data/SVG Image/sample_0.svg", "SVG Image"),
    ]

    correct = 0
    total = 0
    for rel_path, expected in test_files:
        abs_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), rel_path)
        if not os.path.exists(abs_path):
            print(f"  SKIP: {rel_path} (not found)")
            continue
        predictions = test_classifier.predict(abs_path)
        total += 1
        if predictions:
            top_type, top_conf, top_ext = predictions[0]
            match = "OK" if top_type == expected else "MISS"
            if top_type == expected:
                correct += 1
            print(f"  {match}: {rel_path}")
            print(f"       Expected: {expected}")
            print(f"       Got:      {top_type} ({top_conf}%)")
        else:
            print(f"  FAIL: {rel_path} - no predictions returned")

    if total > 0:
        print(f"\nPrediction accuracy on test samples: {correct}/{total} ({correct/total*100:.0f}%)")

    print("\nDone!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
