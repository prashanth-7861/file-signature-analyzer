import os
import shutil
from PyQt5.QtCore import QThread, pyqtSignal
from core.file_analyzer import identify_file_type

class BatchFileProcessor(QThread):
    """
    Worker thread for batch processing files.
    """
    progress_signal = pyqtSignal(int)
    file_processed_signal = pyqtSignal(dict)
    current_file_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(list)

    def __init__(self, input_dir, output_dir, signatures, recursive=False, rename_files=True):
        """
        Initialize the batch processor.

        Args:
            input_dir: Directory containing the files to process
            output_dir: Directory to save the processed files
            signatures: List of signature dictionaries
            recursive: Whether to process subdirectories
            rename_files: Whether to rename files with correct extensions
        """
        super().__init__()
        self.input_dir = input_dir
        self.output_dir = output_dir
        self.signatures = signatures
        self.recursive = recursive
        self.rename_files = rename_files
        self._stop_flag = False

    def stop(self):
        """Signal the processor to stop after the current file."""
        self._stop_flag = True

    def run(self):
        """
        Process all files in the input directory.
        """
        results = []

        # Get list of files to process
        files = []
        if self.recursive:
            for root, _, filenames in os.walk(self.input_dir):
                for filename in filenames:
                    files.append((os.path.join(root, filename), filename, root))
        else:
            files = [(os.path.join(self.input_dir, f), f, self.input_dir)
                    for f in os.listdir(self.input_dir)
                    if os.path.isfile(os.path.join(self.input_dir, f))]

        total_files = len(files)
        if total_files == 0:
            self.finished_signal.emit([])
            return

        for i, (file_path, filename, file_dir) in enumerate(files):
            # Check stop flag
            if self._stop_flag:
                break

            try:
                # Emit current file being processed
                self.current_file_signal.emit(filename)

                # Get base filename (without extension)
                base_name = os.path.splitext(filename)[0]

                # Identify the file type
                file_type, primary_ext, all_extensions, matches = identify_file_type(file_path, self.signatures)

                # Get confidence from best match
                confidence = 0
                if matches:
                    confidence = matches[0].get("confidence", 0)

                # Determine if extension should be changed
                current_ext = os.path.splitext(filename)[1][1:].lower() if os.path.splitext(filename)[1] else ""
                should_change = False

                if self.rename_files:
                    if not current_ext and primary_ext:
                        # File has no extension but we detected one
                        should_change = True
                    elif current_ext and primary_ext and current_ext.lower() != primary_ext.lower():
                        # Extension doesn't match detected type
                        should_change = True

                # Create new filename
                if should_change and primary_ext:
                    new_filename = f"{base_name}.{primary_ext}"
                else:
                    new_filename = filename

                # Create output path
                if self.recursive:
                    rel_path = os.path.relpath(file_dir, self.input_dir)
                    output_subdir = os.path.join(self.output_dir, rel_path)
                else:
                    output_subdir = self.output_dir

                # Create output subdirectory if needed
                if not os.path.exists(output_subdir):
                    os.makedirs(output_subdir)

                # Copy file to output directory
                output_path = os.path.join(output_subdir, new_filename)
                shutil.copy2(file_path, output_path)

                # Create result
                result = {
                    "original_file": filename,
                    "full_path": file_path,
                    "identified_type": file_type,
                    "primary_extension": primary_ext,
                    "all_extensions": all_extensions,
                    "new_filename": new_filename,
                    "output_path": output_path,
                    "extension_changed": should_change,
                    "confidence": confidence
                }

            except Exception as e:
                result = {
                    "original_file": filename,
                    "full_path": file_path,
                    "error": str(e)
                }

            # Add result to list
            results.append(result)

            # Emit the result for real-time updates
            self.file_processed_signal.emit(result)

            # Update progress
            self.progress_signal.emit(int((i + 1) / total_files * 100))

        # Emit all results when done
        self.finished_signal.emit(results)
