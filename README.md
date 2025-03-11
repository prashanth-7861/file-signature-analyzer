# File Signature Analyzer

A Python tool for identifying file types based on their binary signatures, regardless of their extensions. This tool performs deep content inspection to accurately identify files that share common signatures.

## Features

- Analyzes files using binary signatures and deep content inspection
- Identifies files that share common signatures (ZIP, EPUB, DOCX, etc.)
- Handles files with incorrect or missing extensions
- Creates multiple copies for ambiguous file types
- Generates detailed analysis report

## Requirements

- Python 3.6 or higher

## Usage

1. Clone this repository
2. Place your `file_sigs.json` in the same directory as the script (or use the included one)
3. Create a folder named `Files` in the same directory
4. Place files to analyze in the `Files` folder
5. Run the script:

```bash
python file-signature-analyzer.py
