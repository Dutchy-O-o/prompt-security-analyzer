import os


class FileLoader:
    def __init__(self, base_path="test_files"):
        self.base_path = base_path
        if not os.path.exists(self.base_path):
            os.makedirs(self.base_path)
            print(f"✓ [System] Directory created: {self.base_path}")

    def load_file(self, filename):
        """Reads the content of a code file."""
        file_path = os.path.join(self.base_path, filename)
        if not os.path.exists(file_path):
            print(f"❌ [Error] File not found: {file_path}")
            return None
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            print(f"✓ [IO] File loaded: {filename} ({len(content)} characters)")
            return content
        except Exception as e:
            print(f"❌ [Error] Failed to read file: {e}")
            return None

    def list_files(self):
        """Lists all files in the test directory."""
        return [
            f for f in os.listdir(self.base_path)
            if os.path.isfile(os.path.join(self.base_path, f))
        ]
