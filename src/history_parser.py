import os
from pathlib import Path

class GhostHistoryParser:
    def __init__(self):
        self.history_files = [
            ".bash_history",
            ".zsh_history",
            ".python_history"
        ]

    def scan_histories(self):
        """Scans home directories for command history files."""
        all_commands = []
        home_base = "/home"
        
        # Include current user's home and root
        user_homes = [os.path.expanduser("~"), "/root"]
        
        # Add other users if we have permission
        if os.path.exists(home_base):
            try:
                for user_dir in os.listdir(home_base):
                    full_path = os.path.join(home_base, user_dir)
                    if os.path.isdir(full_path) and full_path not in user_homes:
                        user_homes.append(full_path)
            except PermissionError:
                pass

        for home in user_homes:
            for h_file in self.history_files:
                path = Path(home) / h_file
                if path.exists():
                    try:
                        # Extract last 50 commands from each file
                        with open(path, "r", errors="ignore") as f:
                            lines = f.readlines()
                            for line in lines[-50:]:
                                line = line.strip()
                                if line and not line.startswith("#"): # Skip timestamps for now
                                    all_commands.append({
                                        "user": Path(home).name,
                                        "source": h_file,
                                        "command": line
                                    })
                    except PermissionError:
                        continue
        
        return all_commands

if __name__ == "__main__":
    parser = GhostHistoryParser()
    print("--- Ghost-Trail: Extracting Recent Command History ---")
    commands = parser.scan_histories()
    for cmd in commands[-15:]:
        print(f"[{cmd['user']}] ({cmd['source']}) {cmd['command']}")
