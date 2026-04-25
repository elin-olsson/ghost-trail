import os
import time
from pathlib import Path
from datetime import datetime

class GhostFileTracker:
    def __init__(self):
        self.sensitive_dirs = [
            "/tmp",
            "/var/tmp",
            "/dev/shm",
            "/etc",
            os.path.expanduser("~/.ssh"),
            os.path.expanduser("~")
        ]

    def scan_recent_changes(self, hours=24):
        """Scans sensitive directories for files modified in the last X hours."""
        changes = []
        now = time.time()
        threshold = now - (hours * 3600)

        for s_dir in self.sensitive_dirs:
            if not os.path.exists(s_dir):
                continue
            
            try:
                p = Path(s_dir)
                # We limit depth to 2 to avoid huge scans, but enough to find hidden files
                for path in p.rglob("*"):
                    try:
                        if path.is_file():
                            stat = path.stat()
                            if stat.st_mtime > threshold:
                                changes.append({
                                    "path": str(path),
                                    "modified": datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                                    "size": stat.st_size,
                                    "owner": path.owner()
                                })
                    except (PermissionError, FileNotFoundError):
                        continue
            except Exception as e:
                print(f"Error scanning {s_dir}: {e}")

        # Sort by most recent first
        changes.sort(key=lambda x: x['modified'], reverse=True)
        return changes

if __name__ == "__main__":
    tracker = GhostFileTracker()
    print(f"--- Ghost-Trail: Scanning for file changes (last 24h) ---")
    recent_files = tracker.scan_recent_changes(hours=24)
    
    for f in recent_files[:15]: # Show top 15
        print(f"[{f['modified']}] {f['path']} ({f['size']} bytes) - Owner: {f['owner']}")
