# File Signature Analyzer

A Python tool for identifying file types based on their binary signatures, regardless of their extensions. This tool performs deep content inspection to accurately identify files that share common signatures.

## Features

- Analyzes files using binary signatures and deep content inspection
- Identifies files that share common signatures (ZIP, EPUB, DOCX, etc.)
- Handles files with incorrect or missing extensions
- Creates multiple copies for ambiguous file types
- Generates detailed analysis report

**Keywords**: file-analysis, file-signatures, binary-analysis, file-identification, digital-forensics, magic-bytes, file-type-detection, file-extensions

## Technologies Used

This tool is built using Python with a focus on standard library modules to ensure maximum compatibility without external dependencies:

- **os**: For file and directory operations
- **json**: For parsing the signature database and generating reports
- **shutil**: For file copying operations
- **binascii**: For binary to hexadecimal conversion

No external dependencies are required - the script uses only Python standard library modules.

## Requirements

- Python 3.6 or higher

## Usage

1. Clone this repository
2. Place your `file_sigs.json` in the same directory as the script (or use the included one)
3. Create a folder named `Files` in the same directory
4. Place files to analyze in the `Files` folder
5. Run the script: python file-signature-analyzer.py
6. A folder named 'Analyzed_then_saved' will be created in which the files will be saved

```bash
python file-signature-analyzer.py
