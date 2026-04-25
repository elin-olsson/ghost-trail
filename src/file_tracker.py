import os
import time
from pathlib import Path
from datetime import datetime

class GhostFileTracker:
    def __init__(self):
        # Focus on critical areas where attackers pivot or persist
        self.sensitive_dirs = [
            "/tmp",
            "/var/tmp",
            "/dev/shm",
            "/etc",
            os.path.expanduser("~/.ssh"),
            os.path.expanduser("~") # We will filter the noise inside home
        ]
        
        # Directories to skip (The Forensic Noise)
        self.exclude_patterns = [
            "/.cache/",
            "/.mozilla/",
            "/.local/share/",
            "/.cargo/",
            "/.npm/",
            "/__pycache__/",
            "/.git/",
            "/node_modules/"
        ]

    def _is_noisy(self, file_path):
        """Checks if a file path belongs to a known noisy directory."""
        path_str = str(file_path)
        for pattern in self.exclude_patterns:
            if pattern in path_str:
                return True
        return False

    def scan_recent_changes(self, hours=24):
        """Scans sensitive directories for relevant changes, filtering out noise."""
        changes = []
        now = time.time()
        threshold = now - (hours * 3600)

        for s_dir in self.sensitive_dirs:
            if not os.path.exists(s_dir):
                continue
            
            try:
                p = Path(s_dir)
                for path in p.rglob("*"):
                    try:
                        # Skip directories and noisy paths
                        if not path.is_file() or self._is_noisy(path):
                            continue
                            
                        stat = path.stat()
                        if stat.st_mtime > threshold:
                            # Highlight hidden files (often used by attackers)
                            name = path.name
                            is_hidden = name.startswith(".")
                            
                            changes.append({
                                "path": str(path),
                                "modified": datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                                "size": stat.st_size,
                                "owner": path.owner(),
                                "is_hidden": is_hidden
                            })
                    except (PermissionError, FileNotFoundError):
                        continue
            except Exception:
                continue

        # Sort by most recent
        changes.sort(key=lambda x: x['modified'], reverse=True)
        return changes

if __name__ == "__main__":
    tracker = GhostFileTracker()
    print(f"--- Ghost-Trail: Scanning for HIGH SIGNAL changes ---")
    recent = tracker.scan_recent_changes(hours=1)
    for f in recent[:20]:
        marker = "[!HIDDEN]" if f['is_hidden'] else ""
        print(f"[{f['modified']}] {f['path']} {marker}")
