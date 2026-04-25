import struct
import os
from datetime import datetime

# Linux utmp struct format (simplified for common 64-bit systems)
# i: int (4 bytes), 32s: string (32 bytes), etc.
# Format: type, pid, line, id, user, host, exit_status, session, sec, usec
UTMP_FORMAT = "hi32s4s32s256shhiii4i20x"
UTMP_SIZE = struct.calcsize(UTMP_FORMAT)

class GhostBinaryParser:
    def __init__(self):
        self.entry_types = {
            1: "BOOT_TIME",
            2: "NEW_TIME",
            5: "INIT_PROCESS",
            6: "LOGIN_PROCESS",
            7: "USER_PROCESS", # Actual login
            8: "DEAD_PROCESS"
        }

    def parse_wtmp(self, file_path="/var/log/wtmp"):
        """Parses binary wtmp/btmp files and returns list of events."""
        events = []
        if not os.path.exists(file_path):
            return [{"error": f"File {file_path} not found."}]

        try:
            with open(file_path, "rb") as f:
                while True:
                    data = f.read(UTMP_SIZE)
                    if len(data) < UTMP_SIZE:
                        break
                    
                    # Unpack the binary data
                    entry = struct.unpack(UTMP_FORMAT, data)
                    type_id = entry[0]
                    
                    # We only care about user logins and boot times for the trail
                    if type_id in [1, 7]:
                        user = entry[4].translate(None, b'\x00').decode('utf-8', 'ignore')
                        host = entry[5].translate(None, b'\x00').decode('utf-8', 'ignore')
                        line = entry[2].translate(None, b'\x00').decode('utf-8', 'ignore')
                        timestamp = datetime.fromtimestamp(entry[9])
                        
                        events.append({
                            "timestamp": timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                            "type": self.entry_types.get(type_id, "UNKNOWN"),
                            "user": user if user else "system",
                            "host": host if host else "localhost",
                            "line": line
                        })
        except Exception as e:
            events.append({"error": str(e)})

        return events

if __name__ == "__main__":
    parser = GhostBinaryParser()
    print("--- Ghost-Trail: Analyzing Login History (wtmp) ---")
    logins = parser.parse_wtmp()
    for log in logins[-10:]: # Show last 10 entries
        print(f"[{log['timestamp']}] {log['type']}: {log['user']} from {log['host']}")
