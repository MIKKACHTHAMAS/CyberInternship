import hashlib
import os
import json
from datetime import datetime

class FileIntegrityChecker:
    def __init__(self, baseline_file='file_hashes.json'):
        """
        Initialize the File Integrity Checker.
        
        Args:
            baseline_file (str): File to store baseline hashes
        """
        self.baseline_file = baseline_file
        self.baseline_hashes = self._load_baseline()

    def _load_baseline(self):
        """
        Load the baseline hashes from file.
        
        Returns:
            dict: Dictionary of file paths and their hashes
        """
        if os.path.exists(self.baseline_file):
            with open(self.baseline_file, 'r') as f:
                return json.load(f)
        return {}

    def _save_baseline(self):
        """
        Save the current baseline hashes to file.
        """
        with open(self.baseline_file, 'w') as f:
            json.dump(self.baseline_hashes, f, indent=4)

    def calculate_hash(self, file_path, algorithm='sha256'):
        """
        Calculate the hash of a file.
        
        Args:
            file_path (str): Path to the file
            algorithm (str): Hash algorithm to use (sha256, md5, sha1)
            
        Returns:
            str: Hexadecimal digest of the file's hash
        """
        hash_func = hashlib.new(algorithm)
        
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        except IOError as e:
            print(f"Error reading file {file_path}: {e}")
            return None

    def create_baseline(self, directory, extensions=None):
        """
        Create a baseline of file hashes for all files in a directory.
        
        Args:
            directory (str): Directory to scan
            extensions (list): Optional list of file extensions to include
        """
        if not os.path.isdir(directory):
            print(f"Error: {directory} is not a valid directory")
            return

        print(f"Creating baseline for {directory}...")
        
        for root, _, files in os.walk(directory):
            for file in files:
                if extensions:
                    if not any(file.endswith(ext) for ext in extensions):
                        continue
                
                file_path = os.path.join(root, file)
                file_hash = self.calculate_hash(file_path)
                
                if file_hash:
                    self.baseline_hashes[file_path] = {
                        'hash': file_hash,
                        'timestamp': datetime.now().isoformat(),
                        'algorithm': 'sha256'
                    }
        
        self._save_baseline()
        print(f"Baseline created with {len(self.baseline_hashes)} files.")

    def verify_integrity(self):
        """
        Verify the integrity of files against the baseline.
        
        Returns:
            dict: Dictionary with verification results
        """
        results = {
            'changed': [],
            'added': [],
            'removed': [],
            'unchanged': []
        }
        
        current_files = set()
        
        # Check files in baseline
        for file_path, file_data in self.baseline_hashes.items():
            if not os.path.exists(file_path):
                results['removed'].append(file_path)
                continue
                
            current_files.add(file_path)
            current_hash = self.calculate_hash(file_path, file_data['algorithm'])
            
            if current_hash == file_data['hash']:
                results['unchanged'].append(file_path)
            else:
                results['changed'].append(file_path)
        
        # Check for new files (not in baseline)
        for file_path in self._get_all_files():
            if file_path not in current_files and file_path not in self.baseline_hashes:
                results['added'].append(file_path)
        
        return results

    def _get_all_files(self):
        """
        Get all files that were included in the baseline.
        
        Returns:
            set: Set of all file paths in the baseline
        """
        all_files = set()
        for file_path in self.baseline_hashes.keys():
            dir_path = os.path.dirname(file_path)
            if os.path.isdir(dir_path):
                for root, _, files in os.walk(dir_path):
                    for file in files:
                        all_files.add(os.path.join(root, file))
        return all_files

    def print_results(self, results):
        """
        Print the verification results in a readable format.
        """
        print("\nFile Integrity Check Results:")
        print(f"Unchanged files: {len(results['unchanged'])}")
        print(f"Changed files: {len(results['changed'])}")
        print(f"Added files: {len(results['added'])}")
        print(f"Removed files: {len(results['removed'])}")
        
        if results['changed']:
            print("\nChanged files:")
            for file in results['changed']:
                print(f" - {file}")
        
        if results['added']:
            print("\nAdded files (not in baseline):")
            for file in results['added']:
                print(f" - {file}")
        
        if results['removed']:
            print("\nRemoved files:")
            for file in results['removed']:
                print(f" - {file}")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="File Integrity Checker")
    subparsers = parser.add_subparsers(dest='command', required=True)
    
    # Create baseline command
    create_parser = subparsers.add_parser('create', help='Create a new baseline')
    create_parser.add_argument('directory', help='Directory to create baseline for')
    create_parser.add_argument('-e', '--extensions', nargs='+', 
                             help='File extensions to include (e.g., .py .txt)')
    
    # Verify command
    verify_parser = subparsers.add_parser('verify', help='Verify file integrity')
    
    args = parser.parse_args()
    
    checker = FileIntegrityChecker()
    
    if args.command == 'create':
        checker.create_baseline(args.directory, args.extensions)
    elif args.command == 'verify':
        results = checker.verify_integrity()
        checker.print_results(results)

if __name__ == "__main__":
    main()