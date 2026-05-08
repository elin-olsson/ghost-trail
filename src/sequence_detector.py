import re
from datetime import datetime, timedelta

_USER_RE = re.compile(r"User '([^']+)'")
_TS_FMT = "%Y-%m-%d %H:%M:%S"


def _parse(s):
    return datetime.strptime(s, _TS_FMT)


def _extract_user(msg):
    m = _USER_RE.search(msg)
    return m.group(1) if m else None


class SequenceDetector:
    """Correlate LOGIN → suspicious-ALERT → FILE events into attack sequences."""

    def detect(self, timeline: list, window_minutes: int = 10) -> list:
        window = timedelta(minutes=window_minutes)

        logins = [e for e in timeline if e["type"] == "LOGIN"]
        alerts = [
            e for e in timeline
            if e["type"] == "ALERT" and "suspicious command" in e.get("msg", "")
        ]
        files = [e for e in timeline if e["type"] == "FILE"]

        seen = set()
        sequences = []

        for login in logins:
            login_user = _extract_user(login["msg"])
            if not login_user:
                continue
            login_time = _parse(login["time"])

            matching_alert = next(
                (
                    a for a in alerts
                    if _extract_user(a["msg"]) == login_user
                    and login_time <= _parse(a["time"]) <= login_time + window
                ),
                None,
            )
            if matching_alert is None:
                continue

            matching_file = next(
                (
                    f for f in files
                    if login_time <= _parse(f["time"]) <= login_time + window
                ),
                None,
            )
            if matching_file is None:
                continue

            key = (login_user, login["time"])
            if key in seen:
                continue
            seen.add(key)

            end_time = max(
                _parse(matching_alert["time"]),
                _parse(matching_file["time"]),
            ).strftime(_TS_FMT)

            sequences.append({
                "time": login["time"],
                "type": "SEQUENCE",
                "msg": (
                    f"Attack sequence: '{login_user}' login → suspicious command"
                    f" → file modification (window: {window_minutes}min)"
                ),
                "level": "CRITICAL",
                "steps": [login, matching_alert, matching_file],
                "end_time": end_time,
                "user": login_user,
            })

        return sequences
