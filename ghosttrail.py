import sys
import os
import argparse
import re
from datetime import datetime

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), "src"))

from binary_parser import GhostBinaryParser
from file_tracker import GhostFileTracker
from history_parser import GhostHistoryParser

class GhostTrail:
    def __init__(self):
        self.parser = GhostBinaryParser()
        self.tracker = GhostFileTracker()
        self.history = GhostHistoryParser()
        
        # Suspicious patterns to flag in command history
        self.danger_patterns = [
            r"rm\s+.*log", r"history\s+-c", r"unset\s+HISTFILE", # Trace deletion
            r"chmod\s+777", r"chown\s+root",                   # Privilege escalation
            r"curl.*\|\s*bash", r"wget.*\|\s*sh",              # Remote execution
            r"useradd", r"usermod\s+-aG\s+sudo",               # Backdoor creation
            r"nc\s+-e", r"bash\s+-i\s+>\s*&"                   # Reverse shell
        ]

    def _is_suspicious(self, command):
        """Checks if a command matches any dangerous patterns."""
        for pattern in self.danger_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return True
        return False

    def generate_timeline(self, hours=24):
        timeline = []

        # 1. Logins (wtmp)
        logins = self.parser.parse_wtmp()
        for log in logins:
            if "error" in log: continue
            log_time = datetime.strptime(log['timestamp'], '%Y-%m-%d %H:%M:%S')
            if (datetime.now() - log_time).total_seconds() < (hours * 3600):
                timeline.append({
                    "time": log['timestamp'],
                    "type": "LOGIN",
                    "msg": f"User '{log['user']}' session from {log['host']}",
                    "level": "INFO"
                })

        # 2. File Changes
        files = self.tracker.scan_recent_changes(hours=hours)
        for f in files:
            timeline.append({
                "time": f['modified'],
                "type": "FILE",
                "msg": f"Modified: {f['path']} ({f['size']} bytes)",
                "level": "INFO"
            })

        # 3. Command History (Note: history usually lacks precise timestamps, 
        # so we place them at the end of the timeline as 'Recent Activity')
        recent_cmds = self.history.scan_histories()
        for cmd in recent_cmds:
            if self._is_suspicious(cmd['command']):
                timeline.append({
                    "time": "RECENT",
                    "type": "ALERT",
                    "msg": f"CRITICAL: User '{cmd['user']}' ran suspicious command: {cmd['command']}",
                    "level": "CRITICAL"
                })

        # Sort timeline (RECENT items will stay at bottom if sort is stable or handled)
        timeline.sort(key=lambda x: x['time'])
        return timeline

    def run(self, hours=24):
        print(f"\033[90m══════════════════════════════════════════════════════════════\033[0m")
        print(f"  \033[1mGHOST-TRAIL\033[0m  —  Forensic Timeline Reconstructor")
        print(f"\033[90m══════════════════════════════════════════════════════════════\033[0m")
        print(f"  Target:     \033[96mLocal System\033[0m")
        print(f"  Window:     \033[96mLast {hours} hours\033[0m")
        print(f"  Generated:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"\033[90m══════════════════════════════════════════════════════════════\033[0m\n")

        events = self.generate_timeline(hours=hours)
        
        if not events:
            print("  [!] No activity found in the given window.")
        else:
            for e in events:
                color = "\033[94m" # Blue for Login
                if e['type'] == "FILE": color = "\033[92m" # Green for File
                if e['type'] == "ALERT": color = "\033[91m" # Red for Alert
                
                reset = "\033[0m"
                print(f"  {e['time']:<19}  {color}{e['type']:<8}{reset}  {e['msg']}")

        print(f"\n\033[90m══════════════════════════════════════════════════════════════\033[0m")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ghost-Trail: Forensic Reconstructor")
    parser.add_argument("--hours", type=int, default=24, help="Timeline window in hours")
    args = parser.parse_args()

    ghost = GhostTrail()
    ghost.run(hours=args.hours)
