#!/usr/bin/env python3
import sys
import os
import argparse
import re
import json
from datetime import datetime

__version__ = "1.4.0"

# Add src to path - using absolute path of the script's directory
BASE_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(BASE_DIR, "src"))

from binary_parser import GhostBinaryParser
from file_tracker import GhostFileTracker
from history_parser import GhostHistoryParser
from evidence_collector import GhostEvidenceCollector
from gap_detector import GhostGapDetector
from sequence_detector import SequenceDetector

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Ghost-Trail Forensic Report</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: #050a0f; color: #e0e0e0; font-family: 'Segoe UI', Tahoma, sans-serif; padding: 40px; }
h1 { color: #00d4ff; font-family: 'Courier New', monospace; letter-spacing: 2px; }
h2 { color: #5a8fa8; font-size: 13px; font-family: 'Courier New', monospace; letter-spacing: 1px;
     text-transform: uppercase; margin: 28px 0 10px; border-bottom: 1px solid #1a2a3a; padding-bottom: 6px; }
.header { border-bottom: 1px solid #1a2a3a; padding-bottom: 20px; margin-bottom: 30px; }
.subtitle { color: #5a6b7a; font-size: 13px; margin-top: 6px; }
.summary-box { background: #0d141b; border: 1px solid #1a2a3a; padding: 20px; border-radius: 8px;
               margin-bottom: 30px; display: flex; gap: 40px; align-items: center; }
.grade-box { font-size: 3em; font-weight: bold; color: #00d4ff;
             border-right: 1px solid #1a2a3a; padding-right: 40px; }
.stat-item { color: #a0b0c0; font-size: 14px; line-height: 2.2; }
.stat-item strong { color: #e0e0e0; }
#tl-controls { margin-bottom: 10px; display: flex; align-items: center; gap: 16px; }
#tl-reset { background: #0d141b; color: #00d4ff; border: 1px solid #1a2a3a;
            padding: 4px 12px; cursor: pointer; font-size: 12px; border-radius: 3px; }
#tl-reset:hover { background: #1a2a3a; }
.tl-filter { font-size: 12px; color: #a0b0c0; display: flex; align-items: center; gap: 5px; cursor: pointer; }
#tl-wrap { position: relative; background: #07101a; border: 1px solid #1a2a3a;
           border-radius: 6px; overflow: hidden; margin-bottom: 30px; }
#tl-tip { display: none; position: absolute; background: #0d141b; border: 1px solid #1a2a3a;
          color: #e0e0e0; font-size: 12px; padding: 8px 12px; border-radius: 4px;
          pointer-events: none; max-width: 380px; line-height: 1.6; z-index: 10; }
.entry { display: flex; padding: 7px 4px; border-bottom: 1px solid #0a141e; font-size: 12px; }
.entry:hover { background: #0a1520; }
.etime { width: 190px; color: #5a6b7a; font-family: 'Courier New', monospace; flex-shrink: 0; }
.etype { width: 60px; font-weight: bold; font-family: 'Courier New', monospace; flex-shrink: 0; }
.etype.LOGIN     { color: #00d4ff; }
.etype.FILE      { color: #40ffaa; }
.etype.ALERT     { color: #ff4d4d; }
.etype.SEQUENCE  { color: #ff0055; font-weight: bold; }
.emsg { flex: 1; color: #c0c0c0; }
.seq-card { background: #0d0a14; border: 1px solid #3a1a2a; border-left: 3px solid #ff0055;
            padding: 14px 18px; margin-bottom: 12px; border-radius: 4px; }
.seq-card .seq-title { color: #ff0055; font-family: 'Courier New', monospace; font-size: 13px;
                       font-weight: bold; margin-bottom: 8px; }
.seq-card .seq-step  { font-size: 12px; color: #a0b0c0; padding: 2px 0 2px 12px;
                       border-left: 2px solid #2a1a2a; margin: 3px 0; }
.seq-card .seq-step span { font-weight: bold; }
.seq-none { color: #3a4a5a; font-size: 13px; font-style: italic; padding: 10px 0; }
.footer { margin-top: 40px; font-size: 11px; color: #3a4a5a; text-align: center; }
</style>
</head>
<body>
<div class="header">
  <h1>GHOST-TRAIL // FORENSIC TIMELINE</h1>
  <p class="subtitle">Generated: __GENERATED__</p>
</div>
<div class="summary-box">
  <div class="grade-box">__GRADE__</div>
  <div>
    <div class="stat-item"><strong>Attack Sequences</strong>: __SEQUENCE_COUNT__</div>
    <div class="stat-item"><strong>Critical Alerts</strong>: __ALERT_COUNT__</div>
    <div class="stat-item"><strong>User Sessions</strong>: __LOGIN_COUNT__</div>
    <div class="stat-item"><strong>File Activities</strong>: __FILE_COUNT__</div>
  </div>
</div>
<h2>Interactive Timeline</h2>
<div id="tl-controls">
  <button id="tl-reset">Reset Zoom</button>
  <label class="tl-filter"><input type="checkbox" data-type="SEQUENCE" checked> <span style="color:#ff0055">SEQUENCE</span></label>
  <label class="tl-filter"><input type="checkbox" data-type="ALERT" checked> <span style="color:#ff4d4d">ALERT</span></label>
  <label class="tl-filter"><input type="checkbox" data-type="LOGIN" checked> <span style="color:#00d4ff">LOGIN</span></label>
  <label class="tl-filter"><input type="checkbox" data-type="FILE"  checked> <span style="color:#40ffaa">FILE</span></label>
</div>
<div id="tl-wrap"><svg id="tl" style="display:block"></svg><div id="tl-tip"></div></div>
<h2>Attack Sequences</h2>
<div id="seq-list">__SEQUENCE_ROWS__</div>
<h2>Event Log</h2>
<div id="event-list">__EVENT_ROWS__</div>
<div class="footer">&copy; 2026 shadowfox.se &mdash; ghost-trail</div>
<script src="https://d3js.org/d3.v7.min.js"></script>
<script>
(function () {
  var EVENTS  = __EVENTS_JSON__;
  var LANES   = ["SEQUENCE", "ALERT", "LOGIN", "FILE"];
  var COLORS  = { SEQUENCE: "#ff0055", ALERT: "#ff4d4d", LOGIN: "#00d4ff", FILE: "#40ffaa" };
  var LANE_H  = 62;
  var M       = { top: 16, right: 30, bottom: 36, left: 72 };
  var wrap    = document.getElementById("tl-wrap");
  var W       = wrap.clientWidth || 900;
  var IW      = W - M.left - M.right;
  var IH      = LANES.length * LANE_H;
  var H       = IH + M.top + M.bottom;
  var parseFn = d3.timeParse("%Y-%m-%d %H:%M:%S");
  var evs = EVENTS.map(function (e) {
    return { type: e.type, msg: e.msg, time: e.time, date: parseFn(e.time) };
  }).filter(function (e) { return e.date; });
  var svg = d3.select("#tl").attr("width", W).attr("height", H);
  if (!evs.length) {
    svg.append("text").attr("x", W / 2).attr("y", H / 2)
       .attr("text-anchor", "middle").attr("fill", "#5a6b7a").attr("font-size", 13)
       .text("No events to display.");
    return;
  }
  var ext = d3.extent(evs, function (e) { return e.date; });
  var pad = Math.max((ext[1] - ext[0]) * 0.04, 5000);
  var x0  = d3.scaleTime()
    .domain([new Date(ext[0].getTime() - pad), new Date(ext[1].getTime() + pad)])
    .range([0, IW]);
  svg.append("defs").append("clipPath").attr("id", "gt-clip")
     .append("rect").attr("width", IW).attr("height", IH + 4);
  var g     = svg.append("g").attr("transform", "translate(" + M.left + "," + M.top + ")");
  var dotsG = g.append("g").attr("clip-path", "url(#gt-clip)");
  LANES.forEach(function (lane, i) {
    g.append("rect").attr("x", 0).attr("y", i * LANE_H)
     .attr("width", IW).attr("height", LANE_H)
     .attr("fill", i % 2 === 0 ? "#08141f" : "#0d141b");
    g.append("line").attr("x1", 0).attr("x2", IW)
     .attr("y1", (i + 1) * LANE_H).attr("y2", (i + 1) * LANE_H)
     .attr("stroke", "#1a2a3a");
    g.append("text").attr("x", -8).attr("y", i * LANE_H + LANE_H / 2 + 4)
     .attr("text-anchor", "end").attr("fill", COLORS[lane])
     .attr("font-size", 11).attr("font-family", "monospace").text(lane);
  });
  var xAxisG  = g.append("g").attr("transform", "translate(0," + IH + ")");
  var xAxisFn = d3.axisBottom(x0).ticks(6).tickFormat(d3.timeFormat("%H:%M:%S"));
  function styleAxis(ag, scale) {
    ag.call(xAxisFn.scale(scale));
    ag.selectAll("text").attr("fill", "#5a6b7a").attr("font-size", 10);
    ag.selectAll(".domain, line").attr("stroke", "#1a2a3a");
  }
  styleAxis(xAxisG, x0);
  var tip    = d3.select("#tl-tip");
  var active = new Set(LANES);
  function render(xScale) {
    var visible = evs.filter(function (e) { return active.has(e.type); });
    var dots = dotsG.selectAll(".gt-dot").data(visible, function (e) { return e.time + e.msg; });
    dots.enter().append("circle").attr("class", "gt-dot")
      .attr("r", 5).attr("stroke", "#050a0f").attr("stroke-width", 1).attr("opacity", 0.82)
      .attr("fill", function (e) { return COLORS[e.type]; })
      .attr("cy", function (e) { return LANES.indexOf(e.type) * LANE_H + LANE_H / 2; })
      .on("mouseover", function (event, e) {
        tip.style("display", "block")
           .html("<strong>" + e.type + "</strong><br>" + e.time + "<br>" + e.msg);
        d3.select(this).attr("r", 8).attr("opacity", 1);
      })
      .on("mousemove", function (event) {
        tip.style("left", (event.offsetX + 14) + "px").style("top", (event.offsetY - 14) + "px");
      })
      .on("mouseout", function () {
        tip.style("display", "none");
        d3.select(this).attr("r", 5).attr("opacity", 0.82);
      });
    dotsG.selectAll(".gt-dot").attr("cx", function (e) { return xScale(e.date); });
    dots.exit().remove();
    styleAxis(xAxisG, xScale);
  }
  var zoom = d3.zoom().scaleExtent([1, 200]).translateExtent([[0, 0], [IW, IH]])
    .on("zoom", function (ev) { render(ev.transform.rescaleX(x0)); });
  svg.call(zoom);
  render(x0);
  document.getElementById("tl-reset").addEventListener("click", function () {
    svg.transition().duration(300).call(zoom.transform, d3.zoomIdentity);
  });
  document.querySelectorAll("[data-type]").forEach(function (cb) {
    cb.addEventListener("change", function () {
      if (cb.checked) active.add(cb.dataset.type); else active.delete(cb.dataset.type);
      render(x0);
    });
  });
})();
</script>
</body>
</html>"""

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
        scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        for cmd in self.history.scan_histories():
            if self._is_suspicious(cmd['command']):
                timeline.append({"time": scan_time, "type": "ALERT", "msg": f"CRITICAL: User '{cmd['user']}' suspicious command: {cmd['command']}", "level": "CRITICAL"})

        timeline.sort(key=lambda x: x['time'])

        sequences = SequenceDetector().detect(timeline)
        timeline.extend(sequences)
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
        
        stats = {"LOGIN": 0, "FILE": 0, "ALERT": 0, "SEQUENCE": 0}

        for e in timeline:
            if e['type'] != "SEQUENCE":
                stats[e['type']] = stats.get(e['type'], 0) + 1
            else:
                stats["SEQUENCE"] += 1
                score += 20
                critical_findings.append(e['msg'])
                continue
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
            if e['type'] == "LOGIN":      color = "\033[94m"
            elif e['type'] == "ALERT":    color = "\033[91m"
            elif e['type'] == "SEQUENCE": color = "\033[95m"
            else:                         color = "\033[92m"
            print(f"  {e['time']:<19}  {color}{e['type']:<8}\033[0m  {e['msg']}")

        # Display Summary Box (Similar to Auditor)
        print(f"\n\033[90m╔══════════════════════════════════════════════════════════════╗\033[0m")
        print(f"  \033[1mFORENSIC SUMMARY\033[0m — Result Grade: \033[1m{grade}\033[0m")
        print(f"\033[90m╚══════════════════════════════════════════════════════════════╝\033[0m")
        print(f"  Sequences: {stats.get('SEQUENCE', 0)} | Alerts: {stats.get('ALERT', 0)} | Logins: {stats.get('LOGIN', 0)} | Files: {stats.get('FILE', 0)}")
        
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
        sequences = [e for e in timeline if e["type"] == "SEQUENCE"]
        base_events = [e for e in timeline if e["type"] != "SEQUENCE"]

        rows = "\n".join(
            f'<div class="entry">'
            f'<div class="etime">{e["time"]}</div>'
            f'<div class="etype {e["type"]}">{e["type"]}</div>'
            f'<div class="emsg">{e["msg"]}</div>'
            f'</div>'
            for e in base_events
        )

        if sequences:
            seq_rows = "\n".join(
                f'<div class="seq-card">'
                f'<div class="seq-title">&#x26A0; {s["msg"]}</div>'
                f'<div class="seq-step"><span>LOGIN</span> &mdash; {s["steps"][0]["time"]} &mdash; {s["steps"][0]["msg"]}</div>'
                f'<div class="seq-step"><span>ALERT</span> &mdash; {s["steps"][1]["time"]} &mdash; {s["steps"][1]["msg"]}</div>'
                f'<div class="seq-step"><span>FILE</span> &mdash; {s["steps"][2]["time"]} &mdash; {s["steps"][2]["msg"]}</div>'
                f'</div>'
                for s in sequences
            )
        else:
            seq_rows = '<div class="seq-none">No correlated attack sequences detected.</div>'

        html = (
            _HTML_TEMPLATE
            .replace("__EVENTS_JSON__", json.dumps([
                {"time": e["time"], "type": e["type"], "msg": e["msg"]}
                for e in timeline
            ]))
            .replace("__GENERATED__", datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            .replace("__GRADE__", str(grade))
            .replace("__SEQUENCE_COUNT__", str(stats.get('SEQUENCE', 0)))
            .replace("__ALERT_COUNT__", str(stats.get('ALERT', 0)))
            .replace("__LOGIN_COUNT__", str(stats.get('LOGIN', 0)))
            .replace("__FILE_COUNT__", str(stats.get('FILE', 0)))
            .replace("__SEQUENCE_ROWS__", seq_rows)
            .replace("__EVENT_ROWS__", rows)
        )
        with open(output_file, "w") as f:
            f.write(html)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ghost-Trail: Forensic Reconstructor")
    parser.add_argument("--hours", type=int, default=24, help="Timeline window in hours")
    parser.add_argument("--collect", action="store_true", help="Package artifacts into ZIP")
    parser.add_argument("--json", help="Export timeline to JSON file")
    parser.add_argument("--html", help="Export timeline to HTML report")
    args = parser.parse_args()

    ghost = GhostTrail()
    ghost.run(hours=args.hours, collect=args.collect, json_file=args.json, html_file=args.html)
