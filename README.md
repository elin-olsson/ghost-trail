# Ghost-Trail 🦊👻
**Linux Post-Intrusion Forensic Reconstructor**

Ghost-Trail is a specialized digital forensics tool designed to reconstruct a chronological timeline of events following a security incident. It uncovers hidden activity by correlating binary system records, filesystem artifacts, and shell command histories.

---

## Prerequisites

- Python 3.10 or later
- Root privileges (recommended for full system forensics)
- No external runtime dependencies

## Installation

```bash
git clone https://github.com/elin-olsson/ghost-trail.git
cd ghost-trail
```

## Usage

```bash
python3 ghosttrail.py [options]
```

```bash
# Generate a forensic timeline for the last 24 hours (default)
python3 ghosttrail.py

# Specify a custom time window (e.g., last 48 hours)
python3 ghosttrail.py --hours 48
```

## Forensic Capabilities

Ghost-Trail performs a multi-stage investigation to identify traces of compromise:

| Module | Method | Purpose |
|---|---|---|
| **Binary Parser** | Direct `utmp/wtmp` decoding | Authenticates sessions directly from system structures. |
| **File Tracker** | MAC timeline analysis | Identifies files modified in sensitive directories (`/tmp`, `/etc`). |
| **History Engine** | Multi-shell aggregation | Collects command history from all local users. |
| **Alert Engine** | Regex pattern matching | Flags evidence of log wiping, backdoor creation, and data exfiltration. |

## Example output

```
══════════════════════════════════════════════════════════════
  GHOST-TRAIL  —  Forensic Timeline Reconstructor
══════════════════════════════════════════════════════════════
  Target:     Local System
  Window:     Last 24 hours
  Generated:  2026-04-25 16:45:00
══════════════════════════════════════════════════════════════

  2026-04-25 09:12:04  LOGIN     User 'fox' session from 192.168.1.50
  2026-04-25 09:14:22  FILE      Modified: /tmp/.hidden_payload (1240 bytes)
  2026-04-25 09:15:10  ALERT     CRITICAL: User 'fox' ran suspicious command: rm -rf /var/log/auth.log
  2026-04-25 09:18:33  LOGIN     User 'root' session from localhost

══════════════════════════════════════════════════════════════
```

## Roadmap

- [x] Binary wtmp/btmp parsing
- [x] MAC Timeline reconstruction
- [x] Shell history aggregation
- [x] Automated danger pattern flagging
- [ ] Log gap detection (Inconsistency checking)
- [ ] Forensic evidence packaging (ZIP export)

---

&copy; 2026 shadowfox.se
