#!/usr/bin/python3
# WHMADDON:thorwatch:Thor Watch - Load Investigator:thorwatch.png
# ACLS:all
"""Root-only WHM report interface for Thor Watch."""

from __future__ import print_function

import csv
import html
import io
import json
import os
import socket
import sqlite3
import sys
import time
from urllib.parse import parse_qs


LIB_DIR = "/usr/local/thorwatch/lib"
if os.path.isdir(LIB_DIR):
    sys.path.insert(0, LIB_DIR)
else:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from thorwatch_common import (  # noqa: E402
    VERSION,
    connect_database,
    event_report_data,
    human_duration,
    load_settings,
    local_time,
    render_text_report,
    report_json,
)


def e(value):
    return html.escape(str(value if value is not None else ""), quote=True)


def headers(content_type="text/html; charset=UTF-8", status=None, filename=None):
    if status:
        print("Status: {}".format(status))
    print("Content-Type: {}".format(content_type))
    print("Cache-Control: no-store")
    print("X-Content-Type-Options: nosniff")
    print("X-Frame-Options: SAMEORIGIN")
    print(
        "Content-Security-Policy: default-src 'self'; style-src 'unsafe-inline'; "
        "script-src 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'self'"
    )
    if filename:
        print('Content-Disposition: attachment; filename="{}"'.format(filename))
    print("")


def require_root():
    user = os.environ.get("REMOTE_USER", "")
    if user == "root":
        return
    headers(status="403 Forbidden")
    print("<!doctype html><title>Forbidden</title><h1>Root WHM access required</h1>")
    raise SystemExit(0)


def parse_event_id(query):
    raw = query.get("event", query.get("id", [""]))[0]
    try:
        value = int(raw)
        return value if value > 0 else None
    except (TypeError, ValueError):
        return None


def svg_sparkline(samples, key, color, ceiling=None):
    if not samples:
        return '<div class="empty-chart">No event samples</div>'
    width = 760.0
    height = 150.0
    padding = 8.0
    values = [max(0.0, float(row.get(key, 0))) for row in samples]
    top = float(ceiling or max(max(values), 1.0))
    if ceiling is None:
        top *= 1.1
    count = max(1, len(values) - 1)
    points = []
    for index, value in enumerate(values):
        x = padding + index * (width - 2 * padding) / count
        y = height - padding - min(value, top) * (height - 2 * padding) / top
        points.append("{:.1f},{:.1f}".format(x, y))
    return (
        '<svg class="chart" viewBox="0 0 760 150" role="img" '
        'aria-label="{label} over time">'
        '<line x1="8" y1="142" x2="752" y2="142" class="axis" />'
        '<polyline points="{points}" fill="none" stroke="{color}" '
        'stroke-width="3" vector-effect="non-scaling-stroke" />'
        '<text x="10" y="18" class="chart-label">peak {peak:.1f}</text>'
        '</svg>'
    ).format(label=e(key), points=" ".join(points), color=color, peak=max(values))


CSS = r"""
:root{--bg:#f3f6fa;--panel:#fff;--ink:#172033;--muted:#67738a;--line:#dce3ed;
--blue:#1769e0;--cyan:#0d91a8;--orange:#e57a18;--red:#c9364a;--green:#16845b}
html{scroll-behavior:smooth}*{box-sizing:border-box}a,button,summary{cursor:pointer}body{margin:0;padding:126px 0 48px;background:var(--bg);color:var(--ink);font:14px/1.45 -apple-system,
BlinkMacSystemFont,"Segoe UI",sans-serif}.wrap{max-width:1440px;margin:0 auto;padding:22px}.site-header{position:fixed;top:0;left:0;right:0;
z-index:1000;background:rgba(255,255,255,.97);border-bottom:1px solid var(--line);box-shadow:0 2px 12px rgba(23,32,51,.08);backdrop-filter:blur(8px)}
.top{max-width:1440px;margin:0 auto;padding:12px 22px;display:flex;align-items:center;justify-content:space-between;gap:20px}.brand{display:flex;align-items:center;gap:12px}
.logo{width:42px;height:42px;border-radius:12px;background:linear-gradient(145deg,#1c70ed,#0c425e);color:white;
display:grid;place-items:center;font-weight:800}.brand h1{font-size:24px;margin:0}.brand p{margin:1px 0;color:var(--muted)}
.actions{display:flex;gap:8px;flex-wrap:wrap}.button{display:inline-block;padding:8px 12px;border-radius:8px;border:1px solid var(--line);white-space:nowrap;
background:#fff;color:var(--ink);text-decoration:none;font-weight:600}.button.primary{background:var(--blue);border-color:var(--blue);color:#fff}
.button:disabled{cursor:pointer;opacity:.58}.button.track{border:0;background:linear-gradient(135deg,#16845b,#0d91a8);color:#fff;box-shadow:0 4px 12px rgba(13,145,168,.18)}
.subnav-shell{border-top:1px solid var(--line);background:#f8faff}.subnav{max-width:1440px;margin:0 auto;padding:5px 22px;display:flex;align-items:center;gap:4px}
.subnav a,.log-menu summary{display:flex;align-items:center;min-height:30px;padding:5px 10px;border-radius:7px;color:var(--ink);font-size:13px;font-weight:650;text-decoration:none;cursor:pointer}
.subnav>a:hover,.subnav>a:focus-visible,.subnav>a.active,.log-menu summary:hover,.log-menu summary:focus-visible,.log-menu[open] summary,.log-menu.active summary{background:#e8f0fd;color:#1557ad;outline:none}
.subnav-live{flex:0 0 auto;margin-left:auto;white-space:nowrap}
.log-menu{position:relative}.log-menu summary{list-style:none}.log-menu summary::-webkit-details-marker{display:none}.menu-caret{margin-left:6px;color:var(--muted);font-size:10px;transition:transform .15s}
.log-menu[open] .menu-caret{transform:rotate(180deg)}.logs-dropdown{position:absolute;top:calc(100% + 7px);left:0;width:285px;padding:6px;background:#fff;border:1px solid var(--line);border-radius:10px;
box-shadow:0 12px 28px rgba(23,32,51,.16)}.logs-dropdown a{display:block;padding:9px 10px}.logs-dropdown a:hover,.logs-dropdown a:focus-visible,.logs-dropdown a.active{background:#f0f5fc;color:#1557ad;outline:none}
.logs-dropdown strong{display:block;font-size:13px}.logs-dropdown span{display:block;margin-top:1px;color:var(--muted);font-size:11px;font-weight:400}.section-anchor{scroll-margin-top:136px}
.cards{display:grid;grid-template-columns:repeat(6,minmax(130px,1fr));gap:12px;margin-bottom:16px}.card,.panel{background:var(--panel);
border:1px solid var(--line);border-radius:12px;box-shadow:0 1px 2px rgba(23,32,51,.04)}.card{padding:14px}.card .label{color:var(--muted);
font-size:12px;text-transform:uppercase;letter-spacing:.04em}.card .value{font-size:25px;font-weight:750;margin-top:3px}.card .sub{color:var(--muted);font-size:12px}
.panel{padding:17px;margin-bottom:16px}.panel h2{font-size:17px;margin:0 0 13px}.panel h3{font-size:14px;margin:18px 0 8px}.grid2{display:grid;
grid-template-columns:1fr 1fr;gap:16px}.status{display:inline-block;padding:3px 8px;border-radius:999px;font-size:12px;font-weight:700;background:#e7edf5}
.status.open{background:#ffe3e6;color:#a20f29}.status.closed{background:#daf4e9;color:#0c6847}.status.test{background:#e2ecff;color:#164f9d}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:9px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);
font-size:12px;text-transform:uppercase;letter-spacing:.035em}tr:last-child td{border-bottom:0}.num{text-align:right;font-variant-numeric:tabular-nums}.mono{font-family:
ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;word-break:break-all}.muted{color:var(--muted)}.warning{border-left:4px solid var(--orange)}
.chart{width:100%;height:150px;background:linear-gradient(#fff,#f8fbff);border:1px solid var(--line);border-radius:8px}.axis{stroke:#cfd8e5;stroke-width:1}
.chart-label{font-size:12px;fill:#68758a}.empty-chart{height:150px;display:grid;place-items:center;background:#f8fafc;color:var(--muted);border-radius:8px}
.bar{height:8px;background:#e7edf5;border-radius:999px;overflow:hidden;min-width:100px}.bar span{display:block;height:100%;background:var(--blue);border-radius:inherit}
.live-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:12px}.live-pill{display:inline-flex;align-items:center;gap:7px;
padding:5px 10px;border-radius:999px;background:#e4f6ef;color:#08704c;font-size:12px;font-weight:750}.live-pill.stale{background:#fff0d9;color:#92530a}
.live-pill.error{background:#ffe4e8;color:#a5162d}.live-dot{width:8px;height:8px;border-radius:50%;background:#19a66f;box-shadow:0 0 0 0 rgba(25,166,111,.5);
animation:pulse 1.8s infinite}.stale .live-dot{background:#e28a20;animation:none}.error .live-dot{background:#d53b51;animation:none}@keyframes pulse{70%{box-shadow:0 0 0 7px rgba(25,166,111,0)}100%{box-shadow:0 0 0 0 rgba(25,166,111,0)}}
.canvas-chart{display:block;width:100%;height:245px;border:1px solid var(--line);border-radius:10px;background:linear-gradient(180deg,#fff,#f7faff)}
.legend{display:flex;flex-wrap:wrap;gap:14px;margin-top:10px;color:var(--muted);font-size:12px}.legend span{display:flex;align-items:center;gap:6px}
.legend i{width:16px;height:3px;border-radius:3px;display:inline-block}.live-processes td{transition:background .2s}.cpu-warm{color:#b35c09;font-weight:750}.cpu-hot{color:var(--red);font-weight:800}
.truncate{max-width:620px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.ajax-note{font-size:12px;color:var(--muted)}
.mysql-track-summary{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap}.mysql-track-copy{max-width:850px}.mysql-track-copy p{margin:5px 0 0;color:var(--muted)}
.track-progress{height:8px;margin:14px 0;background:#e7edf5;border-radius:999px;overflow:hidden}.track-progress span{display:block;width:0;height:100%;border-radius:inherit;background:linear-gradient(90deg,#16845b,#0d91a8);transition:width .5s}
.mysql-status{margin:12px 0;color:var(--muted)}.mysql-status strong{color:var(--ink)}.mysql-error{color:var(--red);font-weight:650}.mysql-results{margin-top:10px}
.hidden{display:none!important}
.site-footer{position:fixed;left:0;right:0;bottom:0;z-index:1000;min-height:40px;padding:10px 18px;background:rgba(255,255,255,.97);
border-top:1px solid var(--line);box-shadow:0 -2px 12px rgba(23,32,51,.06);color:var(--muted);text-align:center;font-size:12px;backdrop-filter:blur(8px)}
.site-footer a{color:var(--blue);font-weight:700;text-decoration:none}.site-footer a:hover{text-decoration:underline}@media(max-width:1050px){.cards{grid-template-columns:repeat(3,1fr)}
.grid2{grid-template-columns:1fr}}@media(max-width:650px){.wrap{padding:12px}.top{align-items:flex-start;flex-direction:column}.cards{grid-template-columns:repeat(2,1fr)}
.panel{overflow:auto}.card .value{font-size:21px}.canvas-chart{height:205px}.truncate{max-width:280px}body{padding-top:164px}.top{padding:10px 12px;gap:8px}
.brand h1{font-size:20px}.brand p{font-size:12px}.logo{width:38px;height:38px}.actions{width:100%;overflow-x:auto;flex-wrap:nowrap;padding-bottom:2px}.button{padding:7px 10px}
.subnav{padding:5px 12px}.logs-dropdown{position:fixed;top:148px;left:12px;right:12px;width:auto}.section-anchor{scroll-margin-top:174px}}
"""


def page_start(title, open_event=False, active="overview", refresh_href="?", live_status=False):
    headers()
    refresh = "true" if open_event else "false"
    print("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
    print('<meta name="viewport" content="width=device-width,initial-scale=1">')
    print("<title>{}</title><style>{}</style></head>".format(e(title), CSS))
    print('<body data-open="{}"><header class="site-header">'.format(refresh))
    overview_attr = ' class="active" aria-current="page"' if active == "overview" else ""
    process_attr = ' class="active" aria-current="page"' if active == "processes" else ""
    mysql_attr = ' class="active" aria-current="page"' if active == "mysql" else ""
    events_attr = ' class="active" aria-current="page"' if active == "events" else ""
    logs_class = " active" if active in ("processes", "mysql", "events") else ""
    live_status_html = (
        '<span class="live-pill subnav-live" id="live-status"><span class="live-dot"></span>'
        '<span id="live-status-text">Connecting…</span></span>'
        if live_status else ""
    )
    print(
        '<div class="top"><div class="brand"><div class="logo">TW</div><div>'
        '<h1>Thor Watch</h1><p>WHM Load Investigator</p></div></div>'
        '<div class="actions"><a class="button" href="../../" target="_top">← Back to WHM</a>'
        '<a class="button" href="?">Thor Watch Dashboard</a>'
        '<a class="button" href="?action=export-latest&amp;format=txt">Latest report</a>'
        '<a class="button primary" href="{}">Refresh</a></div></div>'
        '<div class="subnav-shell"><nav class="subnav" aria-label="Thor Watch sections">'
        '<a{} href="?">Overview</a><a href="?#load-trends">Trends</a>'
        '<details class="log-menu{}"><summary>Logs <span class="menu-caret" aria-hidden="true">&#9662;</span></summary>'
        '<div class="logs-dropdown">'
        '<a{} href="?view=processes"><strong>Realtime high-CPU processes</strong>'
        '<span>Current process activity</span></a>'
        '<a{} href="?view=mysql"><strong>Top MySQL users</strong>'
        '<span>On-demand activity tracker</span></a>'
        '<a{} href="?view=events"><strong>Load event history</strong>'
        '<span>Captured threshold events</span></a>'
        '</div></details>{}</nav></div></header><main class="wrap">'
        .format(e(refresh_href), overview_attr, logs_class, process_attr, mysql_attr, events_attr, live_status_html)
    )


def page_end():
    print(
        '</main><footer class="site-footer">Thor Watch {} · root-only diagnostic reporting · '
        'Developed by <a href="https://www.peekhosting.com" target="_blank" '
        'rel="noopener noreferrer">PEEK Hosting</a></footer>'.format(e(VERSION))
    )
    print(
        "<script>if(document.body.dataset.open==='true'){setTimeout(function(){location.reload()},15000)}</script>"
    )
    print("</body></html>")


def card(label, value, sub="", value_id=None, sub_id=None):
    value_attr = ' id="{}"'.format(e(value_id)) if value_id else ""
    sub_attr = ' id="{}"'.format(e(sub_id)) if sub_id else ""
    return (
        '<div class="card"><div class="label">{}</div><div class="value"{}>{}</div>'
        '<div class="sub"{}>{}</div></div>'
    ).format(e(label), value_attr, e(value), sub_attr, e(sub))


def live_data(conn, settings):
    now = time.time()
    latest = conn.execute("SELECT * FROM samples ORDER BY ts DESC LIMIT 1").fetchone()
    open_event = conn.execute(
        "SELECT * FROM events WHERE status='open' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    processes = conn.execute(
        "SELECT * FROM live_processes ORDER BY rank LIMIT 30"
    ).fetchall()
    series_rows = conn.execute(
        """
        SELECT ts, load1, load5, load15, cpu_busy, cpu_iowait, cpu_steal
        FROM samples WHERE ts >= ? ORDER BY ts
        """,
        (now - 1800,),
    ).fetchall()
    raw_series = [dict(row) for row in series_rows]
    if len(raw_series) > 360:
        series = [
            raw_series[int(index * (len(raw_series) - 1) / 359.0)]
            for index in range(360)
        ]
    else:
        series = raw_series
    latest_dict = dict(latest) if latest else None
    return {
        "version": VERSION,
        "hostname": socket.gethostname(),
        "server_ts": now,
        "collector_lag": (now - latest["ts"]) if latest else None,
        "latest": latest_dict,
        "active_event": dict(open_event) if open_event else None,
        "processes": [dict(row) for row in processes],
        "series": series,
        "mysql_tracking": mysql_tracking_data(conn),
        "thresholds": {
            "load": settings.floating("load_threshold"),
            "cpu": settings.floating("cpu_busy_threshold"),
        },
    }


def mysql_tracking_data(conn):
    run = conn.execute(
        """
        SELECT id, requested_ts, started_ts, finished_ts, status,
               duration_seconds, original_userstat, error_message
        FROM mysql_tracking_runs ORDER BY id DESC LIMIT 1
        """
    ).fetchone()
    if not run:
        return {"run": None, "results": []}
    results = conn.execute(
        """
        SELECT rank, mysql_user, total_queries, select_commands, update_commands,
               other_commands, busy_time, cpu_time
        FROM mysql_tracking_results WHERE run_id = ? ORDER BY rank
        """,
        (run["id"],),
    ).fetchall()
    return {"run": dict(run), "results": [dict(row) for row in results]}


def start_mysql_tracking(settings):
    if os.environ.get("REQUEST_METHOD", "GET").upper() != "POST":
        headers("application/json; charset=UTF-8", status="405 Method Not Allowed")
        print(json.dumps({"ok": False, "error": "POST required"}))
        return
    if os.environ.get("HTTP_X_THORWATCH_REQUEST", "") != "1":
        headers("application/json; charset=UTF-8", status="403 Forbidden")
        print(json.dumps({"ok": False, "error": "Invalid Thor Watch request"}))
        return
    conn = None
    try:
        conn = connect_database(settings.get("database"))
        conn.execute("BEGIN IMMEDIATE")
        active = conn.execute(
            """
            SELECT id FROM mysql_tracking_runs
            WHERE status IN ('pending', 'running') ORDER BY id LIMIT 1
            """
        ).fetchone()
        accepted = not bool(active)
        if accepted:
            cursor = conn.execute(
                """
                INSERT INTO mysql_tracking_runs(requested_ts, status, duration_seconds)
                VALUES(?, 'pending', ?)
                """,
                (time.time(), settings.integer("mysql_tracking_duration")),
            )
            run_id = cursor.lastrowid
        else:
            run_id = active["id"]
        conn.commit()
        payload = mysql_tracking_data(conn)
        payload.update({"ok": True, "accepted": accepted, "run_id": run_id})
        headers("application/json; charset=UTF-8", status="202 Accepted" if accepted else None)
        print(json.dumps(payload, separators=(",", ":")))
    except (OSError, ValueError, sqlite3.Error) as exc:
        if conn is not None:
            conn.rollback()
        headers("application/json; charset=UTF-8", status="500 Internal Server Error")
        print(json.dumps({"ok": False, "error": "Unable to queue MySQL tracking: {}".format(exc)}))
    finally:
        if conn is not None:
            conn.close()


def serve_live_api(conn, settings):
    headers("application/json; charset=UTF-8")
    print(json.dumps(live_data(conn, settings), separators=(",", ":")))


def process_rows(rows):
    if not rows:
        return '<tr><td colspan="8" class="muted">Waiting for the collector process snapshot…</td></tr>'
    output = []
    for row in rows:
        cpu_class = "cpu-hot" if row["cpu_pct"] >= 100 else ("cpu-warm" if row["cpu_pct"] >= 50 else "")
        output.append(
            '<tr><td class="mono">{}</td><td class="num">{}</td><td class="num {}">{:.1f}%</td>'
            '<td class="num">{:.2f}%</td><td>{}</td><td>{}</td><td>{}</td>'
            '<td class="mono truncate" title="{}">{}</td></tr>'.format(
                e(row["username"]), row["pid"], cpu_class, row["cpu_pct"], row["mem_pct"],
                e(human_duration(row["elapsed"])), e(row["state"]), e(row["category"]),
                e(row["args"]), e(row["args"]),
            )
        )
    return "".join(output)


def mysql_result_rows(rows):
    if not rows:
        return '<tr><td colspan="7" class="muted">Results will appear here when tracking completes.</td></tr>'
    return "".join(
        '<tr><td class="mono">{}</td><td class="num">{}</td><td class="num">{}</td>'
        '<td class="num">{}</td><td class="num">{}</td><td class="num">{:.4f}s</td>'
        '<td class="num">{:.4f}s</td></tr>'.format(
            e(row["mysql_user"]),
            row["total_queries"],
            row["select_commands"],
            row["update_commands"],
            row["other_commands"],
            row["busy_time"],
            row["cpu_time"],
        )
        for row in rows
    )


LIVE_JS = r"""
(function(){
  'use strict';
  var byId=function(id){return document.getElementById(id)};
  var inFlight=false, lastPayload=null, lastSuccess=0, mysqlStarting=false, mysqlServerOffset=0;
  var loadDefs=[
    {key:'load1',label:'Load 1',color:'#1769e0'},
    {key:'load5',label:'Load 5',color:'#0d91a8'},
    {key:'load15',label:'Load 15',color:'#e57a18'}
  ];
  var cpuDefs=[
    {key:'cpu_busy',label:'CPU busy',color:'#c9364a'},
    {key:'cpu_iowait',label:'I/O wait',color:'#7559d9'},
    {key:'cpu_steal',label:'Steal',color:'#d59b15'}
  ];

  function setText(id,value){var node=byId(id);if(node){node.textContent=value}}
  function oneDecimal(value){return Number(value||0).toFixed(1)}
  function duration(seconds){
    seconds=Math.max(0,Math.floor(Number(seconds)||0));
    var d=Math.floor(seconds/86400);seconds%=86400;
    var h=Math.floor(seconds/3600);seconds%=3600;
    var m=Math.floor(seconds/60),s=seconds%60;
    var clock=[h,m,s].map(function(v){return String(v).padStart(2,'0')}).join(':');
    return d?d+'d '+clock:clock;
  }
  function localClock(ts){return ts?new Date(ts*1000).toLocaleTimeString():'—'}

  function drawChart(canvas,rows,defs,options){
    if(!canvas){return}
    var rect=canvas.getBoundingClientRect(),w=Math.max(320,rect.width),h=Math.max(180,rect.height);
    var dpr=Math.min(window.devicePixelRatio||1,2);
    canvas.width=Math.round(w*dpr);canvas.height=Math.round(h*dpr);
    var ctx=canvas.getContext('2d');ctx.setTransform(dpr,0,0,dpr,0,0);ctx.clearRect(0,0,w,h);
    var left=48,right=16,top=24,bottom=30,pw=w-left-right,ph=h-top-bottom;
    var values=[];rows.forEach(function(row){defs.forEach(function(def){values.push(Number(row[def.key])||0)})});
    var maxValue=options.fixedMax||Math.max.apply(null,values.concat([1]));
    if(options.threshold){maxValue=Math.max(maxValue,Number(options.threshold)*1.12)}
    if(!options.fixedMax){maxValue*=1.12}
    ctx.font='11px -apple-system,BlinkMacSystemFont,Segoe UI,sans-serif';ctx.textBaseline='middle';
    for(var i=0;i<=4;i++){
      var y=top+ph*i/4,value=maxValue*(1-i/4);
      ctx.strokeStyle='#dfe6f0';ctx.lineWidth=1;ctx.beginPath();ctx.moveTo(left,y);ctx.lineTo(w-right,y);ctx.stroke();
      ctx.fillStyle='#758197';ctx.textAlign='right';ctx.fillText(value.toFixed(value>=10?0:1),left-8,y);
    }
    if(options.threshold&&Number(options.threshold)<=maxValue){
      var ty=top+ph*(1-Number(options.threshold)/maxValue);ctx.save();ctx.setLineDash([5,5]);
      ctx.strokeStyle='#df7b20';ctx.beginPath();ctx.moveTo(left,ty);ctx.lineTo(w-right,ty);ctx.stroke();ctx.restore();
      ctx.fillStyle='#b66013';ctx.textAlign='left';ctx.fillText('trigger '+options.threshold,left+6,Math.max(10,ty-9));
    }
    function point(index,key){
      var count=Math.max(1,rows.length-1);
      return [left+pw*index/count,top+ph*(1-Math.min(maxValue,Number(rows[index][key])||0)/maxValue)];
    }
    if(rows.length>1){
      var fillDef=defs[0],gradient=ctx.createLinearGradient(0,top,0,top+ph);
      gradient.addColorStop(0,fillDef.color+'28');gradient.addColorStop(1,fillDef.color+'00');
      ctx.beginPath();var first=point(0,fillDef.key);ctx.moveTo(first[0],top+ph);ctx.lineTo(first[0],first[1]);
      for(var f=1;f<rows.length;f++){var fp=point(f,fillDef.key);ctx.lineTo(fp[0],fp[1])}
      ctx.lineTo(w-right,top+ph);ctx.closePath();ctx.fillStyle=gradient;ctx.fill();
      defs.forEach(function(def){
        ctx.beginPath();rows.forEach(function(row,index){var p=point(index,def.key);if(index){ctx.lineTo(p[0],p[1])}else{ctx.moveTo(p[0],p[1])}});
        ctx.strokeStyle=def.color;ctx.lineWidth=2.4;ctx.lineJoin='round';ctx.lineCap='round';ctx.stroke();
      });
      var labels=[0,Math.floor((rows.length-1)/2),rows.length-1];ctx.fillStyle='#758197';ctx.textBaseline='top';
      labels.forEach(function(index,pos){var p=point(index,defs[0].key);ctx.textAlign=pos===0?'left':(pos===2?'right':'center');ctx.fillText(localClock(rows[index].ts),p[0],top+ph+8)});
    }else{
      ctx.fillStyle='#758197';ctx.textAlign='center';ctx.fillText('Collecting chart samples…',left+pw/2,top+ph/2);
    }
  }

  function addCell(row,text,className,title){
    var cell=document.createElement('td');cell.textContent=text;
    if(className){cell.className=className}if(title){cell.title=title}row.appendChild(cell);
  }
  function renderProcesses(processes){
    var body=byId('live-process-body');if(!body){return}while(body.firstChild){body.removeChild(body.firstChild)}
    if(!processes.length){var empty=document.createElement('tr');addCell(empty,'No process snapshot available yet.','muted');empty.firstChild.colSpan=8;body.appendChild(empty);return}
    processes.forEach(function(proc){
      var row=document.createElement('tr'),cpu=Number(proc.cpu_pct)||0,cpuClass='num '+(cpu>=100?'cpu-hot':(cpu>=50?'cpu-warm':''));
      addCell(row,proc.username,'mono');addCell(row,String(proc.pid),'num');addCell(row,cpu.toFixed(1)+'%',cpuClass);
      addCell(row,oneDecimal(proc.mem_pct)+'%','num');addCell(row,duration(proc.elapsed));addCell(row,proc.state);
      addCell(row,proc.category);addCell(row,proc.args,'mono truncate',proc.args);body.appendChild(row);
    });
    setText('process-snapshot-time','snapshot '+localClock(processes[0].updated_ts));
  }
  function renderEvent(event){
    var panel=byId('active-event');if(!panel){return}
    if(!event){panel.classList.add('hidden');return}
    panel.classList.remove('hidden');setText('active-event-title','Active load event #'+event.id);
    setText('active-event-info',event.trigger_reason+' · started '+localClock(event.start_ts)+' · peak load '+oneDecimal(event.peak_load1));
    var link=byId('active-event-link');if(link){link.href='?event='+encodeURIComponent(event.id)}
  }
  function renderMysqlTracking(tracker,serverNow){
    var button=byId('mysql-track-button'),status=byId('mysql-track-status'),progress=byId('mysql-track-progress');
    var body=byId('mysql-result-body');if(!button||!status||!progress||!body){return}
    tracker=tracker||{run:null,results:[]};var run=tracker.run,results=tracker.results||[],active=false,percent=0;
    status.className='mysql-status';
    if(!run){
      status.textContent='Ready · click Track MySQL Users to measure a 60-second activity window.';button.textContent='Track MySQL Users';
    }else if(run.status==='pending'){
      active=true;status.innerHTML='<strong>Queued</strong> · waiting for the collector to enable MariaDB user statistics…';button.textContent='Starting…';
    }else if(run.status==='running'){
      active=true;var elapsed=Math.max(0,serverNow-Number(run.started_ts||serverNow));var remaining=Math.max(0,Math.ceil(Number(run.duration_seconds)-elapsed));
      percent=Math.min(100,elapsed/Math.max(1,Number(run.duration_seconds))*100);status.innerHTML='<strong>Tracking now</strong> · '+remaining+' seconds remaining · userstat will be restored automatically.';button.textContent='Tracking '+remaining+'s';
    }else if(run.status==='completed'){
      percent=100;var restoreText=Number(run.original_userstat)===1?'userstat was already ON and remains ON':'userstat restored to OFF';
      status.innerHTML='<strong>Completed</strong> · '+duration(Number(run.finished_ts)-Number(run.started_ts))+' window · '+restoreText+'.';button.textContent='Track Again';
    }else{
      status.className='mysql-status mysql-error';status.textContent=(run.status==='interrupted'?'Interrupted: ':'Failed: ')+(run.error_message||'Unknown tracking error');button.textContent='Try Again';
    }
    progress.style.width=percent.toFixed(1)+'%';button.disabled=active||mysqlStarting;
    while(body.firstChild){body.removeChild(body.firstChild)}
    if(!results.length){
      var empty=document.createElement('tr'),message=run&&run.status==='completed'?'No user query activity was recorded during this window.':'Results will appear here when tracking completes.';
      addCell(empty,message,'muted');empty.firstChild.colSpan=7;body.appendChild(empty);
    }else{
      results.forEach(function(item){
        var row=document.createElement('tr');addCell(row,item.mysql_user,'mono');addCell(row,String(item.total_queries),'num');
        addCell(row,String(item.select_commands),'num');addCell(row,String(item.update_commands),'num');addCell(row,String(item.other_commands),'num');
        addCell(row,Number(item.busy_time||0).toFixed(4)+'s','num');addCell(row,Number(item.cpu_time||0).toFixed(4)+'s','num');body.appendChild(row);
      });
    }
  }
  async function startMysqlTracking(){
    if(mysqlStarting){return}mysqlStarting=true;var button=byId('mysql-track-button');if(button){button.disabled=true;button.textContent='Queuing…'}
    try{
      var response=await fetch('?action=mysql-track-start',{method:'POST',credentials:'same-origin',cache:'no-store',headers:{'X-ThorWatch-Request':'1'}});
      var payload=await response.json();if(!response.ok){throw new Error(payload.error||('HTTP '+response.status))}
      if(!lastPayload){lastPayload={server_ts:Date.now()/1000}}lastPayload.mysql_tracking={run:payload.run,results:payload.results||[]};
      mysqlServerOffset=Number(lastPayload.server_ts||Date.now()/1000)-Date.now()/1000;renderMysqlTracking(lastPayload.mysql_tracking,Date.now()/1000+mysqlServerOffset);
    }catch(error){var status=byId('mysql-track-status');if(status){status.className='mysql-status mysql-error';status.textContent='Unable to start tracking: '+error.message}}
    finally{mysqlStarting=false;if(button&&!(lastPayload&&lastPayload.mysql_tracking&&lastPayload.mysql_tracking.run&&['pending','running'].indexOf(lastPayload.mysql_tracking.run.status)>=0)){button.disabled=false}}
  }
  function render(payload){
    var row=payload.latest;if(row){
      setText('metric-load',oneDecimal(row.load1)+' / '+oneDecimal(row.load5)+' / '+oneDecimal(row.load15));
      setText('metric-updated','sample '+localClock(row.ts));setText('metric-cpu',oneDecimal(row.cpu_busy)+'%');
      setText('metric-cpu-sub','user '+oneDecimal(row.cpu_user)+'% · system '+oneDecimal(row.cpu_system)+'%');
      setText('metric-io',oneDecimal(row.cpu_iowait)+'%');setText('metric-io-sub','steal '+oneDecimal(row.cpu_steal)+'%');
      setText('metric-run',String(row.running));setText('metric-run-sub',row.total_processes+' total processes');
      setText('metric-memory',oneDecimal(row.mem_used_pct)+'%');setText('metric-memory-sub','swap '+oneDecimal(row.swap_used_pct)+'%');
      setText('metric-http',String(row.http_established));setText('metric-http-sub',row.http_syn_recv+' SYN_RECV');
    }
    renderProcesses(payload.processes||[]);renderEvent(payload.active_event);lastPayload=payload;mysqlServerOffset=Number(payload.server_ts||Date.now()/1000)-Date.now()/1000;
    renderMysqlTracking(payload.mysql_tracking,Date.now()/1000+mysqlServerOffset);
    drawChart(byId('load-chart'),payload.series||[],loadDefs,{threshold:payload.thresholds.load});
    drawChart(byId('cpu-chart'),payload.series||[],cpuDefs,{fixedMax:100,threshold:payload.thresholds.cpu});
    lastSuccess=Date.now();updateStatus();
  }
  function updateStatus(error){
    var pill=byId('live-status');if(!pill){return}pill.classList.remove('stale','error');
    if(error){pill.classList.add('error');setText('live-status-text','Connection error · retrying');return}
    var age=lastPayload&&lastPayload.collector_lag!=null?lastPayload.collector_lag+(Date.now()-lastSuccess)/1000:999;
    if(age>20){pill.classList.add('stale');setText('live-status-text','Collector delayed · '+Math.round(age)+'s')}else{setText('live-status-text','Live · updated '+Math.max(0,Math.round((Date.now()-lastSuccess)/1000))+'s ago')}
  }
  async function poll(){
    if(inFlight||document.hidden){return}inFlight=true;
    try{var response=await fetch('?action=api-live&_='+Date.now(),{credentials:'same-origin',cache:'no-store'});if(!response.ok){throw new Error('HTTP '+response.status)}render(await response.json())}
    catch(error){updateStatus(error)}finally{inFlight=false}
  }
  window.addEventListener('resize',function(){if(lastPayload){drawChart(byId('load-chart'),lastPayload.series||[],loadDefs,{threshold:lastPayload.thresholds.load});drawChart(byId('cpu-chart'),lastPayload.series||[],cpuDefs,{fixedMax:100,threshold:lastPayload.thresholds.cpu})}});
  document.addEventListener('visibilitychange',function(){if(!document.hidden){poll()}});
  var mysqlButton=byId('mysql-track-button');if(mysqlButton){mysqlButton.addEventListener('click',startMysqlTracking)}
  poll();setInterval(poll,3000);setInterval(function(){updateStatus();if(lastPayload){renderMysqlTracking(lastPayload.mysql_tracking,Date.now()/1000+mysqlServerOffset)}},1000);
})();
"""


def render_dashboard(conn, settings):
    payload = live_data(conn, settings)
    latest = payload["latest"]
    open_event = payload["active_event"]
    page_start("Thor Watch - Load Investigator", False, live_status=True)
    collector_interval = min(
        settings.integer("normal_interval"), settings.integer("live_process_interval")
    )
    print(
        '<div class="live-head"><div><strong>Realtime server health</strong>'
        '<div class="ajax-note">AJAX refresh every 3 seconds · collector snapshot every {} seconds</div></div>'
        '</div>'.format(collector_interval)
    )
    if latest:
        print('<div class="cards">')
        print(card("Load 1 / 5 / 15", "{:.1f} / {:.1f} / {:.1f}".format(latest["load1"], latest["load5"], latest["load15"]), local_time(latest["ts"]), "metric-load", "metric-updated"))
        print(card("CPU busy", "{:.1f}%".format(latest["cpu_busy"]), "user {:.1f}% · system {:.1f}%".format(latest["cpu_user"], latest["cpu_system"]), "metric-cpu", "metric-cpu-sub"))
        print(card("I/O wait", "{:.1f}%".format(latest["cpu_iowait"]), "steal {:.1f}%".format(latest["cpu_steal"]), "metric-io", "metric-io-sub"))
        print(card("Run queue", latest["running"], "{} total processes".format(latest["total_processes"]), "metric-run", "metric-run-sub"))
        print(card("Memory", "{:.1f}%".format(latest["mem_used_pct"]), "swap {:.1f}%".format(latest["swap_used_pct"]), "metric-memory", "metric-memory-sub"))
        print(card("HTTP sockets", latest["http_established"], "{} SYN_RECV".format(latest["http_syn_recv"]), "metric-http", "metric-http-sub"))
        print("</div>")
    else:
        print('<div class="cards">')
        print(card("Load 1 / 5 / 15", "—", "waiting", "metric-load", "metric-updated"))
        print(card("CPU busy", "—", "waiting", "metric-cpu", "metric-cpu-sub"))
        print(card("I/O wait", "—", "waiting", "metric-io", "metric-io-sub"))
        print(card("Run queue", "—", "waiting", "metric-run", "metric-run-sub"))
        print(card("Memory", "—", "waiting", "metric-memory", "metric-memory-sub"))
        print(card("HTTP sockets", "—", "waiting", "metric-http", "metric-http-sub"))
        print("</div>")
        print('<div class="panel warning"><h2>Collector has not written a sample yet</h2><p>Check <span class="mono">systemctl status thorwatch</span>.</p></div>')
    hidden = "" if open_event else " hidden"
    title = "Active load event #{}".format(open_event["id"]) if open_event else "Active load event"
    info = "{} · started {} · peak load {:.2f}".format(open_event["trigger_reason"], local_time(open_event["start_ts"]), open_event["peak_load1"]) if open_event else ""
    href = "?event={}".format(open_event["id"]) if open_event else "?"
    print('<div class="panel warning{}" id="active-event"><h2 id="active-event-title">{}</h2>'.format(hidden, e(title)))
    print('<p><span class="status open">LIVE</span> <span id="active-event-info">{}</span></p>'.format(e(info)))
    print('<a class="button primary" id="active-event-link" href="{}">Open live report</a></div>'.format(e(href)))
    print(
        '<div class="grid2 section-anchor" id="load-trends"><div class="panel"><h2>Realtime load trend · last 30 minutes</h2>'
        '<canvas class="canvas-chart" id="load-chart" aria-label="Load average chart"></canvas>'
        '<div class="legend"><span><i style="background:#1769e0"></i>Load 1</span>'
        '<span><i style="background:#0d91a8"></i>Load 5</span><span><i style="background:#e57a18"></i>Load 15</span></div></div>'
        '<div class="panel"><h2>Realtime CPU trend · last 30 minutes</h2>'
        '<canvas class="canvas-chart" id="cpu-chart" aria-label="CPU usage chart"></canvas>'
        '<div class="legend"><span><i style="background:#c9364a"></i>CPU busy</span>'
        '<span><i style="background:#7559d9"></i>I/O wait</span><span><i style="background:#d59b15"></i>Steal</span></div></div></div>'
    )
    print("<script>{}</script>".format(LIVE_JS))
    page_end()


def render_processes(conn, settings):
    payload = live_data(conn, settings)
    live_processes = payload["processes"]
    collector_interval = min(
        settings.integer("normal_interval"), settings.integer("live_process_interval")
    )
    process_time = local_time(live_processes[0]["updated_ts"]) if live_processes else "waiting"
    page_start(
        "Thor Watch - Realtime high-CPU processes",
        False,
        active="processes",
        refresh_href="?view=processes",
        live_status=True,
    )
    print(
        '<div class="live-head"><div><strong>Realtime high-CPU processes</strong>'
        '<div class="ajax-note">AJAX refresh every 3 seconds · collector snapshot every {} seconds</div></div>'
        '</div>'.format(collector_interval)
    )
    print('<div class="panel" id="realtime-processes"><div class="live-head"><h2>Current process activity</h2><span class="ajax-note" id="process-snapshot-time">snapshot {}</span></div>'.format(e(process_time)))
    print('<table class="live-processes"><thead><tr><th>User</th><th class="num">PID</th><th class="num">CPU</th><th class="num">Memory</th><th>Elapsed</th><th>State</th><th>Category</th><th>Command / PHP script</th></tr></thead>')
    print('<tbody id="live-process-body">{}</tbody></table></div>'.format(process_rows(live_processes)))
    print("<script>{}</script>".format(LIVE_JS))
    page_end()


def render_mysql_tracker(conn, settings):
    mysql_tracking = mysql_tracking_data(conn)
    mysql_run = mysql_tracking["run"]
    mysql_active = bool(mysql_run and mysql_run["status"] in ("pending", "running"))
    mysql_button = "Tracking…" if mysql_active else ("Track Again" if mysql_run else "Track MySQL Users")
    if not mysql_run:
        mysql_status = "Ready · click Track MySQL Users to measure a 60-second activity window."
    elif mysql_run["status"] == "pending":
        mysql_status = "Queued · waiting for the collector to start MariaDB user statistics."
    elif mysql_run["status"] == "running":
        mysql_status = "Tracking now · userstat will be restored automatically."
    elif mysql_run["status"] == "completed":
        mysql_status = "Completed · results from the latest tracking window."
    else:
        mysql_status = "{}: {}".format(mysql_run["status"].title(), mysql_run["error_message"] or "Unknown tracking error")
    page_start(
        "Thor Watch - Top MySQL users",
        False,
        active="mysql",
        refresh_href="?view=mysql",
        live_status=True,
    )
    print(
        '<div class="panel" id="mysql-tracker"><div class="mysql-track-summary">'
        '<div class="mysql-track-copy"><h2>Top MySQL users · on-demand tracker</h2>'
        '<p>Measures per-user MariaDB query, busy-time, and CPU-time deltas for an isolated '
        '{}-second window. Existing counters are not flushed.</p></div>'
        '<button class="button track" id="mysql-track-button" type="button"{}>{}</button>'
        '</div><div class="track-progress"><span id="mysql-track-progress"></span></div>'
        '<div class="mysql-status" id="mysql-track-status">{}</div>'
        '<div class="mysql-results"><table><thead><tr><th>MySQL User</th>'
        '<th class="num">Total Queries</th><th class="num">SELECT</th>'
        '<th class="num">UPDATE</th><th class="num">OTHER</th>'
        '<th class="num">Busy Time</th><th class="num">CPU Time</th>'
        '</tr></thead><tbody id="mysql-result-body">{}</tbody></table></div></div>'.format(
            settings.integer("mysql_tracking_duration"),
            " disabled" if mysql_active else "",
            e(mysql_button),
            e(mysql_status),
            mysql_result_rows(mysql_tracking["results"]),
        )
    )
    print("<script>{}</script>".format(LIVE_JS))
    page_end()


def render_event_history(conn):
    events = conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT 50").fetchall()
    latest = conn.execute("SELECT ts FROM samples ORDER BY ts DESC LIMIT 1").fetchone()
    page_start(
        "Thor Watch - Load event history",
        False,
        active="events",
        refresh_href="?view=events",
    )
    print('<div class="panel" id="load-event-history"><h2>Load event history</h2>')
    if not events:
        print('<p class="muted">No threshold events have been captured yet.</p>')
    else:
        print('<table><thead><tr><th>Event</th><th>Started</th><th>Duration</th><th>Trigger</th><th class="num">Peak load</th><th class="num">Peak CPU</th><th>Status</th></tr></thead><tbody>')
        for row in events:
            end = row["end_ts"] or (latest["ts"] if latest else row["start_ts"])
            print(
                '<tr><td><a href="?event={}">#{}</a></td><td>{}</td><td>{}</td><td>{}</td>'
                '<td class="num">{:.2f}</td><td class="num">{:.1f}%</td><td><span class="status {}">{}</span></td></tr>'.format(
                    row["id"], row["id"], e(local_time(row["start_ts"])), e(human_duration(end - row["start_ts"])),
                    e(row["trigger_reason"]), row["peak_load1"], row["peak_cpu_busy"], e(row["status"]), e(row["status"])
                )
            )
        print("</tbody></table>")
    print("</div>")
    page_end()


def render_event(data):
    event = data["event"]
    samples = data["samples"]
    end = event.get("end_ts") or (samples[-1]["ts"] if samples else event["start_ts"])
    page_start(
        "Thor Watch event #{}".format(event["id"]),
        event["status"] == "open",
        active="events",
        refresh_href="?event={}".format(event["id"]),
    )
    print('<div class="actions" style="margin-bottom:14px">')
    print('<a class="button" href="?action=export&amp;format=txt&amp;id={}">TXT report</a>'.format(event["id"]))
    print('<a class="button" href="?action=export&amp;format=json&amp;id={}">JSON report</a>'.format(event["id"]))
    print('<a class="button" href="?action=export&amp;format=csv&amp;id={}">Process CSV</a>'.format(event["id"]))
    print("</div><div class=\"cards\">")
    print(card("Event", "#{}".format(event["id"]), event["status"]))
    print(card("Peak load1", "{:.2f}".format(event["peak_load1"]), event["trigger_reason"]))
    print(card("Peak CPU busy", "{:.1f}%".format(event["peak_cpu_busy"]), "system-wide"))
    print(card("Peak run queue", event["peak_running"], "runnable processes"))
    print(card("Duration", human_duration(end - event["start_ts"]), local_time(event["start_ts"])))
    print(card("Samples", event["sample_count"], "adaptive burst capture"))
    print("</div>")
    print('<div class="grid2"><div class="panel"><h2>Load 1-minute</h2>{}</div>'.format(svg_sparkline(samples, "load1", "#1769e0")))
    print('<div class="panel"><h2>CPU busy %</h2>{}</div></div>'.format(svg_sparkline(samples, "cpu_busy", "#c9364a", 100)))
    print('<div class="grid2"><div class="panel"><h2>CPU by service</h2>')
    if data["categories"]:
        print('<table><thead><tr><th>Category</th><th class="num">Peak CPU</th><th class="num">Average CPU</th></tr></thead><tbody>')
        for row in data["categories"]:
            print('<tr><td>{}</td><td class="num">{:.1f}%</td><td class="num">{:.1f}%</td></tr>'.format(e(row["category"]), row["peak_cpu"], row["avg_cpu"]))
        print("</tbody></table>")
    else:
        print('<p class="muted">No detailed process samples.</p>')
    print('</div><div class="panel"><h2>CPU by cPanel/system user</h2>')
    if data["users"]:
        print('<table><thead><tr><th>User</th><th class="num">Peak CPU</th><th class="num">Average CPU</th></tr></thead><tbody>')
        for row in data["users"][:20]:
            print('<tr><td class="mono">{}</td><td class="num">{:.1f}%</td><td class="num">{:.1f}%</td></tr>'.format(e(row["username"]), row["peak_cpu"], row["avg_cpu"]))
        print("</tbody></table>")
    print("</div></div>")
    print('<div class="panel"><h2>Top process commands</h2><table><thead><tr><th>User</th><th>Category</th><th class="num">Peak CPU</th><th>Max elapsed</th><th>Command</th></tr></thead><tbody>')
    for row in data["commands"]:
        print('<tr><td class="mono">{}</td><td>{}</td><td class="num">{:.1f}%</td><td>{}</td><td class="mono">{}</td></tr>'.format(e(row["username"]), e(row["category"]), row["peak_cpu"], e(human_duration(row["max_elapsed"])), e(row["args"])))
    print("</tbody></table></div>")
    print('<div class="grid2"><div class="panel"><h2>Top HTTP source IPs</h2>')
    if data["top_ips"]:
        print('<table><thead><tr><th>Source IP</th><th class="num">Hits</th><th class="num">Accounts</th></tr></thead><tbody>')
        for row in data["top_ips"]:
            print('<tr><td class="mono">{}</td><td class="num">{}</td><td class="num">{}</td></tr>'.format(e(row["source_ip"]), row["hits"], row["accounts"]))
        print("</tbody></table>")
    else:
        print('<p class="muted">No correlated access-log records. Confirm cPanel domlog paths and permissions.</p>')
    print('</div><div class="panel"><h2>Top User-Agents</h2>')
    if data["top_agents"]:
        print('<table><thead><tr><th>User-Agent</th><th class="num">Hits</th></tr></thead><tbody>')
        for row in data["top_agents"]:
            print('<tr><td class="mono">{}</td><td class="num">{}</td></tr>'.format(e(row["user_agent"]), row["hits"]))
        print("</tbody></table>")
    print("</div></div>")
    print('<div class="panel"><h2>Top HTTP routes</h2><table><thead><tr><th>Account</th><th>Domain/log</th><th>Method</th><th>URI</th><th class="num">Hits</th></tr></thead><tbody>')
    for row in data["top_routes"]:
        print('<tr><td class="mono">{}</td><td>{}</td><td>{}</td><td class="mono">{}</td><td class="num">{}</td></tr>'.format(e(row["cpanel_user"]), e(row["domain"]), e(row["method"]), e(row["uri"]), row["hits"]))
    print("</tbody></table></div>")
    page_end()


def export_event(conn, event_id, fmt):
    data = event_report_data(conn, event_id)
    if not data:
        headers(status="404 Not Found")
        print("Event not found")
        return
    if fmt == "json":
        headers("application/json; charset=UTF-8", filename="thorwatch-event-{}.json".format(event_id))
        print(report_json(data))
    elif fmt == "csv":
        def csv_safe(value):
            text = str(value if value is not None else "")
            return "'" + text if text.startswith(("=", "+", "-", "@")) else text

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(("user", "category", "peak_cpu_pct", "max_elapsed_seconds", "appearances", "command"))
        for row in data["commands"]:
            writer.writerow((csv_safe(row["username"]), csv_safe(row["category"]), row["peak_cpu"], row["max_elapsed"], row["appearances"], csv_safe(row["args"])))
        headers("text/csv; charset=UTF-8", filename="thorwatch-event-{}-processes.csv".format(event_id))
        print(output.getvalue(), end="")
    else:
        headers("text/plain; charset=UTF-8", filename="thorwatch-event-{}.txt".format(event_id))
        print(render_text_report(data), end="")


def render_database_error(message):
    page_start("Thor Watch database unavailable")
    print('<div class="panel warning"><h2>Thor Watch database unavailable</h2><p class="mono">{}</p>'.format(e(message)))
    print('<p>Run <span class="mono">systemctl status thorwatch</span> and <span class="mono">journalctl -u thorwatch -n 100</span>.</p></div>')
    page_end()


def main():
    require_root()
    query = parse_qs(os.environ.get("QUERY_STRING", ""), keep_blank_values=True)
    try:
        settings = load_settings()
        conn = connect_database(settings.get("database"), read_only=True)
    except (OSError, ValueError, sqlite3.Error) as exc:
        render_database_error(str(exc))
        return 0
    action = query.get("action", [""])[0]
    view = query.get("view", [""])[0]
    event_id = parse_event_id(query)
    if action == "api-live":
        serve_live_api(conn, settings)
    elif action == "mysql-track-start":
        start_mysql_tracking(settings)
    elif action == "export-latest":
        row = conn.execute("SELECT id FROM events ORDER BY id DESC LIMIT 1").fetchone()
        if not row:
            headers("text/plain; charset=UTF-8", status="404 Not Found")
            print("No Thor Watch events have been captured yet.")
        else:
            export_event(conn, row["id"], query.get("format", ["txt"])[0])
    elif action == "export" and event_id:
        export_event(conn, event_id, query.get("format", ["txt"])[0])
    elif event_id:
        data = event_report_data(conn, event_id)
        if data:
            render_event(data)
        else:
            headers(status="404 Not Found")
            print("<!doctype html><title>Not found</title><h1>Event not found</h1>")
    elif view == "processes":
        render_processes(conn, settings)
    elif view == "mysql":
        render_mysql_tracker(conn, settings)
    elif view == "events":
        render_event_history(conn)
    else:
        render_dashboard(conn, settings)
    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
