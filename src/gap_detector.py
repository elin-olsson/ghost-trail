import os
import re
from datetime import datetime

class GhostGapDetector:
    def __init__(self, log_path="/var/log/auth.log"):
        # Detect Fedora/RedHat vs Debian/Ubuntu paths
        if not os.path.exists(log_path) and os.path.exists("/var/log/secure"):
            log_path = "/var/log/secure"
        self.log_path = log_path

    def find_gaps(self, threshold_minutes=120):
        """Identifies large time gaps between log entries."""
        gaps = []
        if not os.path.exists(self.log_path):
            return [{"error": f"Log file {self.log_path} not found."}]

        last_time = None
        
        try:
            with open(self.log_path, "r", errors="ignore") as f:
                for line in f:
                    match = re.search(r'^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|20\d{2}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', line)
                    if match:
                        ts_str = match.group(1)
                        try:
                            if "T" in ts_str:
                                current_time = datetime.strptime(ts_str[:19], '%Y-%m-%dT%H:%M:%S')
                            else:
                                current_time = datetime.strptime(ts_str, '%b %d %H:%M:%S')
                                current_time = current_time.replace(year=datetime.now().year)
                            
                            if last_time:
                                diff = (current_time - last_time).total_seconds() / 60
                                if diff > threshold_minutes:
                                    gaps.append({
                                        "start": last_time.strftime('%Y-%m-%d %H:%M:%S'),
                                        "end": current_time.strftime('%Y-%m-%d %H:%M:%S'),
                                        "gap_minutes": int(diff)
                                    })
                            last_time = current_time
                        except ValueError:
                            continue
        except Exception as e:
            gaps.append({"error": str(e)})

        return gaps

if __name__ == "__main__":
    # Test block is now path-agnostic
    detector = GhostGapDetector()
    print(f"--- Ghost-Trail: Scanning {detector.log_path} ---")
    for g in detector.find_gaps(threshold_minutes=60):
        print(f"  [ALERT] Log gap: {g.get('gap_minutes', 'ERR')} min")
