import sys
import os
import argparse
import re
import json
from datetime import datetime

# Add src to path - using absolute path of the script's directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(BASE_DIR, "src"))

from binary_parser import GhostBinaryParser
from file_tracker import GhostFileTracker
from history_parser import GhostHistoryParser
from evidence_collector import GhostEvidenceCollector
from gap_detector import GhostGapDetector

class GhostTrail:
    def __init__(self, base_output_dir=None):
        self.base_output_dir = base_output_dir or os.path.join(BASE_DIR, "data")
        os.makedirs(self.base_output_dir, exist_ok=True)
        
        self.parser = GhostBinaryParser()
        self.tracker = GhostFileTracker()
        self.history = GhostHistoryParser()
        self.collector = GhostEvidenceCollector(output_dir=os.path.join(self.base_output_dir, "evidence"))
        self.gaps = GhostGapDetector()
        
        self.danger_patterns = [
            r"rm\s+.*log", r"history\s+-c", r"unset\s+HISTFILE",
            r"chmod\s+777", r"chown\s+root",
            r"curl.*\|\s*bash", r"wget.*\|\s*sh",
            r"useradd", r"usermod\s+-aG\s+sudo",
            r"nc\s+-e", r"bash\s+-i\s+>\s*&"
        ]

    def _detect_deleted_executables(self):
        alerts = []
        try:
            for pid in os.listdir('/proc'):
                if pid.isdigit():
                    try:
                        exe_path = os.readlink(f'/proc/{pid}/exe')
                        if " (deleted)" in exe_path:
                            alerts.append({
                                "time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                "type": "ALERT",
                                "msg": f"PROCESS GHOSTING: PID {pid} is running from a deleted file: {exe_path}",
                                "level": "CRITICAL"
                            })
                    except (OSError, FileNotFoundError): continue
        except Exception: pass
        return alerts

    def generate_timeline(self, hours=24):
        timeline = []
        artifacts = set()
        
        # 1. Forensic Checks
        timeline.extend(self._detect_deleted_executables())

        # 2. Logins
        wtmp_path = "/var/log/wtmp"
        logins = self.parser.parse_wtmp(wtmp_path)
        if os.path.exists(wtmp_path): artifacts.add(wtmp_path)
        for log in logins:
            if "error" in log: continue
            log_time = datetime.strptime(log['timestamp'], '%Y-%m-%d %H:%M:%S')
            if (datetime.now() - log_time).total_seconds() < (hours * 3600):
                timeline.append({"time": log['timestamp'], "type": "LOGIN", "msg": f"User '{log['user']}' session from {log['host']}", "level": "INFO"})

        # 3. Log Gaps
        for gap in self.gaps.find_gaps(threshold_minutes=120):
            if "error" in gap: continue
            gap_end_time = datetime.strptime(gap['end'], '%Y-%m-%d %H:%M:%S')
            if (datetime.now() - gap_end_time).total_seconds() < (hours * 3600):
                timeline.append({"time": gap['start'], "type": "ALERT", "msg": f"INCONSISTENCY: Time gap in logs ({gap['gap_minutes']} min)", "level": "WARN"})

        # 4. File Changes
        files = self.tracker.scan_recent_changes(hours=hours)
        for f in files:
            artifacts.add(f['path'])
            timeline.append({"time": f['modified'], "type": "FILE", "msg": f"Modified: {f['path']} ({f['size']} bytes)", "level": "INFO"})

        # 5. History
        for cmd in self.history.scan_histories():
            if self._is_suspicious(cmd['command']):
                timeline.append({"time": "RECENT", "type": "ALERT", "msg": f"CRITICAL: User '{cmd['user']}' suspicious command: {cmd['command']}", "level": "CRITICAL"})

        timeline.sort(key=lambda x: x['time'])
        return timeline, list(artifacts)

    def _is_suspicious(self, command):
        for pattern in self.danger_patterns:
            if re.search(pattern, command, re.IGNORECASE): return True
        return False

    def calculate_risk(self, timeline):
        """Analyzes the timeline and assigns a forensic risk score."""
        score = 0
        critical_findings = []
        
        stats = {"LOGIN": 0, "FILE": 0, "ALERT": 0}
        
        for e in timeline:
            stats[e['type']] = stats.get(e['type'], 0) + 1
            if e['level'] == "CRITICAL":
                score += 10
                critical_findings.append(e['msg'])
            elif e['level'] == "WARN":
                score += 3
        
        grade = "A"
        if score > 20: grade = "F"
        elif score > 10: grade = "D"
        elif score > 5: grade = "C"
        elif score > 0: grade = "B"
        
        return grade, stats, critical_findings

    def run(self, hours=24, collect=False, json_file=None, html_file=None):
        events, artifact_paths = self.generate_timeline(hours=hours)
        grade, stats, criticals = self.calculate_risk(events)
        
        # Display Timeline
        print(f"\n  [+] Reconstructed {len(events)} forensic events.")
        for e in events:
            color = "\033[94m" if e['type'] == "LOGIN" else "\033[92m"
            if e['type'] == "ALERT": color = "\033[91m"
            print(f"  {e['time']:<19}  {color}{e['type']:<8}\033[0m  {e['msg']}")

        # Display Summary Box (Similar to Auditor)
        print(f"\n\033[90m╔══════════════════════════════════════════════════════════════╗\033[0m")
        print(f"  \033[1mFORENSIC SUMMARY\033[0m — Result Grade: \033[1m{grade}\033[0m")
        print(f"\033[90m╚══════════════════════════════════════════════════════════════╝\033[0m")
        print(f"  Alerts: {stats.get('ALERT', 0)} | Logins: {stats.get('LOGIN', 0)} | Files: {stats.get('FILE', 0)}")
        
        if criticals:
            print(f"\n  \033[91m\033[1m[!] THE SMOKING GUN (Critical Findings):\033[0m")
            for c in list(set(criticals)): # Unique findings
                print(f"  • {c}")
        elif grade == "A":
            print(f"\n  \033[92m[✓] No suspicious forensic artifacts identified.\033[0m")
        
        if json_file:
            with open(json_file, "w") as f: json.dump({"grade": grade, "stats": stats, "events": events}, f, indent=4)
            print(f"\n  [SUCCESS] JSON report saved: {json_file}")

        if html_file:
            self.export_html(events, html_file, grade, stats)
            print(f"  [SUCCESS] HTML report saved: {html_file}")

        if collect:
            print(f"\n--- Forensic Evidence Collection ---")
            histories = self.history.get_history_paths()
            self.collector.collect_artifacts(artifact_paths + histories)

    def export_html(self, timeline, output_file, grade, stats):
        # (HTML export remains largely same but with summary header added)
        template = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Ghost-Trail Forensic Report</title>
    <style>
        body {{ background-color: #050a0f; color: #e0e0e0; font-family: 'Segoe UI', Tahoma, sans-serif; margin: 0; padding: 40px; }}
        .header {{ border-bottom: 1px solid #1a2a3a; padding-bottom: 20px; margin-bottom: 30px; }}
        .summary-box {{ background: #0d141b; border: 1px solid #1a2a3a; padding: 20px; border-radius: 8px; margin-bottom: 30px; display: flex; gap: 40px; }}
        .grade-box {{ font-size: 3em; font-weight: bold; color: #00d4ff; display: flex; align-items: center; justify-content: center; border-right: 1px solid #1a2a3a; padding-right: 40px; }}
        h1 {{ color: #00d4ff; font-family: 'Courier New', monospace; letter-spacing: 2px; margin: 0; }}
        .entry {{ display: flex; padding: 10px; border-bottom: 1px solid #0d141b; font-size: 0.9em; }}
        .time {{ width: 180px; color: #5a6b7a; font-family: 'Courier New', monospace; }}
        .type {{ width: 80px; font-weight: bold; }}
        .LOGIN {{ color: #00d4ff; }}
        .FILE {{ color: #40ffaa; }}
        .ALERT {{ color: #ff4d4d; }}
        .msg {{ flex: 1; }}
        .footer {{ margin-top: 40px; font-size: 0.8em; color: #5a6b7a; text-align: center; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>GHOST-TRAIL // FORENSIC TIMELINE</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    <div class="summary-box">
        <div class="grade-box">{grade}</div>
        <div>
            <h3>Forensic Artifact Summary</h3>
            <p>Critical Alerts: {stats.get('ALERT', 0)}</p>
            <p>User Sessions: {stats.get('LOGIN', 0)}</p>
            <p>File Activities: {stats.get('FILE', 0)}</p>
        </div>
    </div>
    {" ".join([f'<div class="entry"><div class="time">{e["time"]}</div><div class="type {e["type"]}">{e["type"]}</div><div class="msg">{e["msg"]}</div></div>' for e in timeline])}
    <div class="footer">&copy; 2026 shadowfox.se</div>
</body>
</html>"""
        with open(output_file, "w") as f: f.write(template)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ghost-Trail: Forensic Reconstructor")
    parser.add_argument("--hours", type=int, default=24, help="Timeline window in hours")
    parser.add_argument("--collect", action="store_true", help="Package artifacts into ZIP")
    parser.add_argument("--json", help="Export timeline to JSON file")
    parser.add_argument("--html", help="Export timeline to HTML report")
    args = parser.parse_args()

    ghost = GhostTrail()
    ghost.run(hours=args.hours, collect=args.collect, json_file=args.json, html_file=args.html)
