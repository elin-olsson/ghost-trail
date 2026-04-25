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
from evidence_collector import GhostEvidenceCollector
from gap_detector import GhostGapDetector

class GhostTrail:
    def __init__(self):
        self.parser = GhostBinaryParser()
        self.tracker = GhostFileTracker()
        self.history = GhostHistoryParser()
        self.collector = GhostEvidenceCollector()
        self.gaps = GhostGapDetector()
        
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
        artifacts = set() # To track file paths for collection

        # 1. Logins (wtmp)
        wtmp_path = "/var/log/wtmp"
        logins = self.parser.parse_wtmp(wtmp_path)
        if os.path.exists(wtmp_path): artifacts.add(wtmp_path)
        
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

        # 2. Log Gaps (Inconsistency detection)
        log_gaps = self.gaps.find_gaps(threshold_minutes=120)
        for gap in log_gaps:
            if "error" in gap: continue
            # Only show gaps within our window
            gap_end_time = datetime.strptime(gap['end'], '%Y-%m-%d %H:%M:%S')
            if (datetime.now() - gap_end_time).total_seconds() < (hours * 3600):
                timeline.append({
                    "time": gap['start'],
                    "type": "ALERT",
                    "msg": f"INCONSISTENCY: Large time gap detected in logs ({gap['gap_minutes']} min)",
                    "level": "WARN"
                })

        # 3. File Changes
        files = self.tracker.scan_recent_changes(hours=hours)
        for f in files:
            artifacts.add(f['path'])
            timeline.append({
                "time": f['modified'],
                "type": "FILE",
                "msg": f"Modified: {f['path']} ({f['size']} bytes)",
                "level": "INFO"
            })

        # 4. Command History
        recent_cmds = self.history.scan_histories()
        for cmd in recent_cmds:
            if self._is_suspicious(cmd['command']):
                timeline.append({
                    "time": "RECENT",
                    "type": "ALERT",
                    "msg": f"CRITICAL: User '{cmd['user']}' ran suspicious command: {cmd['command']}",
                    "level": "CRITICAL"
                })

        # Sort timeline
        timeline.sort(key=lambda x: x['time'])
        return timeline, list(artifacts)

    def run(self, hours=24, collect=False):
        print(f"\033[90m══════════════════════════════════════════════════════════════\033[0m")
        print(f"  \033[1mGHOST-TRAIL\033[0m  —  Forensic Timeline Reconstructor")
        print(f"\033[90m══════════════════════════════════════════════════════════════\033[0m")
        print(f"  Target:     \033[96mLocal System\033[0m")
        print(f"  Window:     \033[96mLast {hours} hours\033[0m")
        print(f"  Generated:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"\033[90m══════════════════════════════════════════════════════════════\033[0m\n")

        events, artifact_paths = self.generate_timeline(hours=hours)
        
        if not events:
            print("  [!] No activity found in the given window.")
        else:
            for e in events:
                color = "\033[94m" # Blue for Login
                if e['type'] == "FILE": color = "\033[92m" # Green for File
                if e['type'] == "ALERT": color = "\033[91m" # Red for Alert
                
                reset = "\033[0m"
                print(f"  {e['time']:<19}  {color}{e['type']:<8}{reset}  {e['msg']}")

        if collect:
            print(f"\n\033[1m--- Forensic Evidence Collection ---\033[0m")
            # Also add history files to collection
            histories = self.history.get_history_paths()
            self.collector.collect_artifacts(artifact_paths + histories)

        print(f"\n\033[90m══════════════════════════════════════════════════════════════\033[0m")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ghost-Trail: Forensic Reconstructor")
    parser.add_argument("--hours", type=int, default=24, help="Timeline window in hours")
    parser.add_argument("--collect", action="store_true", help="Package all identified artifacts into a secure ZIP")
    args = parser.parse_args()

    ghost = GhostTrail()
    ghost.run(hours=args.hours, collect=args.collect)
