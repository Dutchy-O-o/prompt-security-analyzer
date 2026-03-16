import streamlit as st
import streamlit.components.v1 as components
import json
import time
import sqlite3
import pandas as pd
import zipfile
import uuid
import os
import hashlib
from datetime import datetime
from html.parser import HTMLParser

# ==============================
# CUSTOM MODULES
# ==============================
from modules.llm_gateway import LLMGateway
from modules.prompt_engineer import PromptEngineer
from modules.parser import ResponseParser

# ==============================
# DATABASE MANAGER (EMBEDDED)
# ==============================
class DBManager:
    def __init__(self, db_name="security_results.db"):
        self.db_path = os.path.join(os.getcwd(), db_name)
        self.init_db()

    def init_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        c.execute("""
        CREATE TABLE IF NOT EXISTS analysis_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT,
            file_name TEXT,
            model_name TEXT,
            vulnerability_detected TEXT,
            risk_level TEXT,
            raw_response TEXT,
            original_snippet TEXT,
            fixed_snippet TEXT,
            timestamp DATETIME
        )
        """)

        c.execute("""
        CREATE TABLE IF NOT EXISTS scan_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT,
            file_name TEXT,
            model_name TEXT,
            elapsed_sec REAL,
            findings_count INTEGER,
            timestamp DATETIME
        )
        """)

        c.execute("""
        CREATE TABLE IF NOT EXISTS scanned_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_name TEXT,
            file_hash TEXT,
            created_at DATETIME
        )
        """)

        c.execute("""
        CREATE TABLE IF NOT EXISTS file_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER,
            version INTEGER,
            scan_id TEXT,
            created_at DATETIME
        )
        """)

        c.execute("""
        CREATE TABLE IF NOT EXISTS file_versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER,
            version INTEGER,
            file_content TEXT,
            created_at DATETIME
        )
        """)

        conn.commit()
        conn.close()

    def save_result(self, scan_id, file_name, model, vuln, risk, raw_resp, original_code, fixed_code):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""
        INSERT INTO analysis_results
        (scan_id, file_name, model_name, vulnerability_detected,
         risk_level, raw_response, original_snippet, fixed_snippet, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_id, file_name, model, vuln, risk,
            raw_resp, original_code, fixed_code, datetime.now()
        ))
        conn.commit()
        conn.close()

    def save_run(self, scan_id, file_name, model, elapsed, findings):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""
        INSERT INTO scan_runs
        (scan_id, file_name, model_name, elapsed_sec, findings_count, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (
            scan_id, file_name, model, elapsed, findings, datetime.now()
        ))
        conn.commit()
        conn.close()

    def save_file_version(self, file_id, version, content):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""
            INSERT INTO file_versions (file_id, version, file_content, created_at)
            VALUES (?, ?, ?, ?)
        """, (file_id, version, content, datetime.now()))
        conn.commit()
        conn.close()


db = DBManager()

# ==============================
# PAGE CONFIG
# ==============================
st.set_page_config(
    page_title="Prompt-Based Security Analyzer",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Prompt-Based Security Analyzer")

# ==============================
# HELPERS
# ==============================
class HTMLStripper(HTMLParser):
    def __init__(self):
        super().__init__()
        self.data = []

    def handle_data(self, d):
        self.data.append(d)

    def get_data(self):
        return "".join(self.data)

def strip_html(text):
    if not text:
        return ""
    s = HTMLStripper()
    s.feed(text)
    return s.get_data()

def get_language(filename):
    if filename.endswith(".py"):
        return "python"
    if filename.endswith(".c"):
        return "c"
    if filename.endswith(".java"):
        return "java"
    return "text"

def compute_file_hash(content):
    return hashlib.sha256(content.encode()).hexdigest()

def register_file_and_version(file_name, content, scan_id):
    conn = sqlite3.connect(db.db_path)
    c = conn.cursor()

    file_hash = compute_file_hash(content)

    c.execute("SELECT id FROM scanned_files WHERE file_name=?", (file_name,))
    row = c.fetchone()

    if row:
        file_id = row[0]
    else:
        c.execute(
            "INSERT INTO scanned_files (file_name, file_hash, created_at) VALUES (?, ?, ?)",
            (file_name, file_hash, datetime.now())
        )
        file_id = c.lastrowid

    c.execute("SELECT MAX(version) FROM file_scans WHERE file_id=?", (file_id,))
    max_v = c.fetchone()[0]
    version = 1 if max_v is None else max_v + 1

    c.execute("""
        INSERT INTO file_scans (file_id, version, scan_id, created_at)
        VALUES (?, ?, ?, ?)
    """, (file_id, version, scan_id, datetime.now()))

    c.execute("""
        INSERT INTO file_versions (file_id, version, file_content, created_at)
        VALUES (?, ?, ?, ?)
    """, (file_id, version, content, datetime.now()))

    conn.commit()
    conn.close()

    return file_id, version


# ==============================
# ANALYSIS FUNCTION
# ==============================
def analyze_code_content(code, file_name, model, gateway, engineer, parser, scan_id):
    prompt = engineer.create_security_prompt(code, file_name=file_name)

    start = time.time()
    raw = gateway.send_prompt(prompt_text=prompt, model_key=model)
    elapsed = time.time() - start

    findings = parser.parse_report(raw) or []

    for item in findings:
        db.save_result(
            scan_id,
            file_name,
            model,
            item.get("vulnerability"),
            item.get("risk_level"),
            json.dumps(item),
            item.get("original_snippet"),
            item.get("fixed_snippet"),
        )

    db.save_run(scan_id, file_name, model, elapsed, len(findings))
    return findings, elapsed

# ==============================
# SIDEBAR – MODEL SELECTION
# ==============================
gateway = LLMGateway()
engineer = PromptEngineer()
parser = ResponseParser()

with st.sidebar:
    st.header("🤖 Model Selection")
    models = list(gateway.MODEL_REGISTRY.keys())
    # Pahalı modelleri filtreleyerek default'tan çıkar
    affordable_models = [m for m in models if m not in ["gpt-5.4-pro", "gemini-3.1-pro", "claude-opus-4-6"]]
    selected_models = st.multiselect(
        "Models to run",
        models,
        default=affordable_models[:1] if affordable_models else models[:1]
    )

# ==============================
# TABS
# ==============================
tab1, tab2 = st.tabs(["📂 Code Scanner", "📊 Benchmark & Dashboard"])

# ==============================
# TAB 1 – CODE SCANNER
# ==============================
with tab1:
    uploaded_file = st.file_uploader(
        "Upload code file or ZIP",
        type=["py", "c", "java", "txt", "zip"]
    )

    files = {}
    if uploaded_file:
        if uploaded_file.name.endswith(".zip"):
            with zipfile.ZipFile(uploaded_file, "r") as z:
                for f in z.namelist():
                    if f.endswith((".py", ".c", ".java", ".txt")):
                        files[f] = z.read(f).decode("utf-8", errors="ignore")
        else:
            files[uploaded_file.name] = uploaded_file.read().decode("utf-8", errors="ignore")

        st.subheader("📄 Uploaded File Content")
        for fname, content in files.items():
            with st.expander(fname, expanded=True):
                st.code(content, language=get_language(fname))

    if st.button("🚀 Start Scan") and files and selected_models:
        scan_id = str(uuid.uuid4())
        runtime_results = {}

        total_steps = len(files) * len(selected_models)
        progress = st.progress(0)
        status = st.empty()
        step = 0

        for fname, content in files.items():
            file_id, version = register_file_and_version(fname, content, scan_id)

            for model in selected_models:
                status.markdown(f"🔍 **Scanning `{fname}` with `{model}`**")

                findings, elapsed = analyze_code_content(
                    content, fname, model,
                    gateway, engineer, parser, scan_id
                )

                runtime_results.setdefault(model, []).append({
                    "file": fname,
                    "elapsed": elapsed,
                    "findings": findings
                })

                step += 1
                progress.progress(step / total_steps)

        status.empty()
        progress.empty()
        st.success("Scan completed!")

        st.header("🧪 Scan Results (Live View)")

        for model, runs in runtime_results.items():
            st.subheader(f"🤖 {model}")
            for run in runs:
                st.write(f"⏱ {run['elapsed']:.2f}s | 🚨 {len(run['findings'])} findings")

                with st.expander("Show details"):
                    for i, item in enumerate(run["findings"], 1):
                        st.markdown(f"### #{i} {item.get('vulnerability')}")
                        st.markdown(f"⚠️ **Risk Level:** `{item.get('risk_level')}`")

                        desc = strip_html(item.get("description"))
                        if desc:
                            st.info(desc)

                        col1, col2 = st.columns(2)
                        with col1:
                            st.markdown("❌ Insecure Code")
                            st.code(strip_html(item.get("original_snippet")),
                                    language=get_language(run["file"]))
                        with col2:
                            st.markdown("✅ Fixed Code")
                            st.code(strip_html(item.get("fixed_snippet")),
                                    language=get_language(run["file"]))

# ==============================
# TAB 2 – BENCHMARK DASHBOARD
# ==============================
with tab2:

    conn = sqlite3.connect(db.db_path)

    files_df = pd.read_sql(
        "SELECT DISTINCT file_name FROM scanned_files ORDER BY file_name", conn
    )

    if files_df.empty:
        st.info("No scans yet. Please scan a file from Tab 1 first.")
        conn.close()
    else:
        selected_file = st.selectbox("Select File", files_df["file_name"])

        versions_df = pd.read_sql("""
            SELECT fs.version, fs.scan_id, fs.file_id
            FROM file_scans fs
            JOIN scanned_files sf ON sf.id = fs.file_id
            WHERE sf.file_name = ?
            ORDER BY fs.version DESC
        """, conn, params=(selected_file,))

        selected_version = st.selectbox(
            "Select Version",
            versions_df["version"],
            format_func=lambda v: f"v{v}"
        )

        row     = versions_df[versions_df["version"] == selected_version].iloc[0]
        scan_id = row["scan_id"]
        
        # ── Model filtering for cleaner dashboard ─────────────────────────────
        # First, get all available models for this scan
        conn_temp = sqlite3.connect(db.db_path)
        available_models = pd.read_sql(
            "SELECT DISTINCT model_name FROM scan_runs WHERE scan_id = ? AND file_name = ?",
            conn_temp, params=(scan_id, selected_file)
        )
        conn_temp.close()
        available_models_list = sorted(available_models["model_name"].tolist())
        
        # Let user select which models to display
        selected_models_filter = st.multiselect(
            "📊 Select models to compare",
            available_models_list,
            default=available_models_list  # Show all by default
        )

        # ── Retrieve data ──────────────────────────────────────────────────────
        summary = pd.read_sql("""
        SELECT
            r.model_name   AS model,
            r.elapsed_sec  AS elapsed,
            r.findings_count AS total,
            COALESCE(SUM(CASE WHEN LOWER(a.risk_level) IN ('critical','kritik') THEN 1 ELSE 0 END),0) AS critical,
            COALESCE(SUM(CASE WHEN LOWER(a.risk_level) IN ('high','yüksek')     THEN 1 ELSE 0 END),0) AS high,
            COALESCE(SUM(CASE WHEN LOWER(a.risk_level) IN ('medium','orta')     THEN 1 ELSE 0 END),0) AS medium,
            COALESCE(SUM(CASE WHEN LOWER(a.risk_level) IN ('low','düşük')       THEN 1 ELSE 0 END),0) AS low
        FROM scan_runs r
        LEFT JOIN analysis_results a
          ON r.scan_id    = a.scan_id
         AND r.model_name = a.model_name
         AND r.file_name  = a.file_name
        WHERE r.scan_id  = ?
          AND r.file_name = ?
        GROUP BY r.model_name, r.elapsed_sec, r.findings_count
        ORDER BY r.elapsed_sec ASC
        """, conn, params=(scan_id, selected_file))

        details = pd.read_sql("""
        SELECT model_name, vulnerability_detected, risk_level, file_name, timestamp
        FROM analysis_results
        WHERE scan_id = ? AND file_name = ?
        ORDER BY model_name, risk_level
        """, conn, params=(scan_id, selected_file))

        vuln_matrix = pd.read_sql("""
        SELECT vulnerability_detected, model_name, COUNT(*) as cnt
        FROM analysis_results
        WHERE scan_id = ? AND file_name = ?
        GROUP BY vulnerability_detected, model_name
        """, conn, params=(scan_id, selected_file))

        conn.close()
        
        # ── Filter data by selected models ───────────────────────────────────
        summary = summary[summary["model"].isin(selected_models_filter)]
        details = details[details["model_name"].isin(selected_models_filter)]
        vuln_matrix = vuln_matrix[vuln_matrix["model_name"].isin(selected_models_filter)]

        # ── Convert to JSON → for JS injection ────────────────────────────────
        summary_json  = summary.to_dict(orient="records")
        details_json  = details.to_dict(orient="records")

        # Vulnerability matrix: {vuln: {model: 1/0}}
        all_vulns  = vuln_matrix["vulnerability_detected"].dropna().unique().tolist()
        all_models = summary["model"].tolist()
        vuln_map   = {}
        for _, r in vuln_matrix.iterrows():
            v = r["vulnerability_detected"]
            m = r["model_name"]
            if v not in vuln_map:
                vuln_map[v] = {}
            vuln_map[v][m] = int(r["cnt"])
        vuln_matrix_json = [
            {"vuln": v, "detections": vuln_map.get(v, {})}
            for v in all_vulns
        ]

        # Risk colors
        def risk_badge(r):
            r = (r or "").lower()
            if r in ("critical", "kritik"):  return "critical"
            if r in ("high", "yüksek"):      return "high"
            if r in ("medium", "orta"):      return "medium"
            return "low"

        details_list = [
            {
                "model": d["model_name"],
                "vuln":  d["vulnerability_detected"] or "—",
                "risk":  risk_badge(d["risk_level"]),
                "file":  d["file_name"],
                "ts":    str(d["timestamp"])[:16]
            }
            for _, d in details.iterrows()
        ]

        # ── Summary metrics ───────────────────────────────────────────────────
        total_findings  = int(summary["total"].sum())
        max_model       = summary.loc[summary["total"].idxmax(), "model"] if not summary.empty else "—"
        max_findings    = int(summary["total"].max()) if not summary.empty else 0
        fastest_model   = summary.loc[summary["elapsed"].idxmin(), "model"] if not summary.empty else "—"
        fastest_time    = round(float(summary["elapsed"].min()), 1) if not summary.empty else 0
        total_critical  = int(summary["critical"].sum())

        # ── Model color map (automatic: first 8 models) ─────────────────
        PALETTE = [
            {"border": "#534AB7", "bg": "rgba(83,74,183,0.12)",  "pill_bg": "#EEEDFE", "pill_fg": "#3C3489"},
            {"border": "#0F6E56", "bg": "rgba(15,110,86,0.10)",  "pill_bg": "#E1F5EE", "pill_fg": "#085041"},
            {"border": "#BA7517", "bg": "rgba(186,117,23,0.10)", "pill_bg": "#FAEEDA", "pill_fg": "#633806"},
            {"border": "#A32D2D", "bg": "rgba(163,45,45,0.10)",  "pill_bg": "#FCEBEB", "pill_fg": "#A32D2D"},
            {"border": "#185FA5", "bg": "rgba(24,95,165,0.10)",  "pill_bg": "#E6F1FB", "pill_fg": "#185FA5"},
            {"border": "#3B6D11", "bg": "rgba(59,109,17,0.10)",  "pill_bg": "#EAF3DE", "pill_fg": "#3B6D11"},
            {"border": "#854F0B", "bg": "rgba(133,79,11,0.10)",  "pill_bg": "#FAEEDA", "pill_fg": "#854F0B"},
            {"border": "#444441", "bg": "rgba(68,68,65,0.10)",   "pill_bg": "#F1EFE8", "pill_fg": "#444441"},
        ]
        model_colors = {m: PALETTE[i % len(PALETTE)] for i, m in enumerate(all_models)}
        model_colors_json = model_colors

        # ── Generate HTML ─────────────────────────────────────────────────────
        dashboard_html = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
*{{box-sizing:border-box;margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}}
body{{background:transparent;color:#1a1a1a;font-size:14px}}
.root{{padding:0 0 24px}}

/* Tabs */
.tabs{{display:flex;gap:2px;border-bottom:1px solid #e5e5e5;margin-bottom:20px}}
.tab-btn{{padding:8px 16px;border:none;background:none;font-size:13px;color:#666;cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-1px;transition:all .15s;border-radius:4px 4px 0 0}}
.tab-btn:hover:not(.active){{background:#f5f5f5;color:#333}}
.tab-btn.active{{color:#111;border-bottom-color:#111;font-weight:500}}
.tab-panel{{display:none}}.tab-panel.active{{display:block}}

/* Metric cards */
.metrics{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin-bottom:20px}}
.mcard{{background:#f7f7f5;border-radius:8px;padding:14px 16px}}
.mcard-lbl{{font-size:11px;color:#888;margin-bottom:5px;text-transform:uppercase;letter-spacing:.04em}}
.mcard-val{{font-size:22px;font-weight:500;color:#111;line-height:1.2}}
.mcard-sub{{font-size:11px;color:#aaa;margin-top:3px}}

/* Charts grid */
.cgrid{{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:16px}}
.cgrid-full{{grid-column:1/-1}}
.ccard{{background:#fff;border:1px solid #ebebeb;border-radius:10px;padding:16px}}
.ccard-title{{font-size:13px;font-weight:500;color:#222;margin-bottom:14px}}

/* Bar charts */
.bar-row{{display:flex;align-items:center;gap:10px;margin-bottom:8px}}
.bar-lbl{{font-size:12px;color:#666;width:130px;flex-shrink:0;text-align:right;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.bar-track{{flex:1;height:22px;background:#f0f0ee;border-radius:4px;overflow:hidden}}
.bar-fill{{height:100%;border-radius:4px;display:flex;align-items:center;justify-content:flex-end;padding-right:8px;transition:width .6s cubic-bezier(.4,0,.2,1)}}
.bar-val{{font-size:11px;font-weight:500;color:#fff}}

/* Stacked bars */
.sbar-row{{display:flex;align-items:center;gap:10px;margin-bottom:8px}}
.sbar{{flex:1;height:24px;display:flex;border-radius:4px;overflow:hidden}}
.sbar-seg{{height:100%;transition:width .6s cubic-bezier(.4,0,.2,1)}}

/* Legend */
.legend{{display:flex;flex-wrap:wrap;gap:10px;margin-top:12px}}
.leg-item{{display:flex;align-items:center;gap:5px;font-size:11px;color:#666}}
.leg-dot{{width:10px;height:10px;border-radius:2px;flex-shrink:0}}

/* Ranking */
.rank-row{{display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid #f0f0ee}}
.rank-row:last-child{{border-bottom:none}}
.rank-num{{width:24px;height:24px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:500;flex-shrink:0}}
.r1{{background:#FAEEDA;color:#633806}}.r2{{background:#F1EFE8;color:#444441}}.r3{{background:#FAEEDA;color:#854F0B}}
.rank-info{{flex:1}}
.rank-name{{font-size:13px;font-weight:500;color:#111;margin-bottom:2px}}
.rank-detail{{font-size:11px;color:#999}}
.rank-score{{font-size:16px;font-weight:500;color:#333}}

/* Model pill */
.mpill{{display:inline-block;padding:2px 10px;border-radius:20px;font-size:12px;font-weight:500}}

/* Badges */
.badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:500}}
.b-critical{{background:#FCEBEB;color:#A32D2D}}
.b-high{{background:#FAEEDA;color:#854F0B}}
.b-medium{{background:#E6F1FB;color:#185FA5}}
.b-low{{background:#EAF3DE;color:#3B6D11}}

/* Detection matrix */
.vuln-item{{padding:10px 0;border-bottom:1px solid #f0f0ee}}
.vuln-item:last-child{{border-bottom:none}}
.vuln-hdr{{display:flex;align-items:center;gap:8px;margin-bottom:6px}}
.vuln-name{{font-size:13px;font-weight:500;color:#111}}
.det-bars{{display:flex;gap:8px;margin-top:4px}}
.det-bar{{flex:1}}
.det-lbl{{font-size:10px;color:#999;margin-bottom:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
.det-track{{height:8px;background:#f0f0ee;border-radius:3px;overflow:hidden}}
.det-fill{{height:100%;border-radius:3px;transition:width .6s cubic-bezier(.4,0,.2,1)}}

/* Table */
.table-wrap{{overflow-x:auto}}
table{{width:100%;border-collapse:collapse;font-size:12px}}
th{{font-size:11px;font-weight:500;color:#888;text-align:left;padding:8px 10px;border-bottom:1px solid #ebebeb;white-space:nowrap}}
td{{padding:9px 10px;border-bottom:1px solid #f5f5f5;color:#222;vertical-align:middle}}
tr:last-child td{{border-bottom:none}}
tr:hover td{{background:#fafafa}}

/* Score display */
.score-wrap{{display:flex;align-items:center;justify-content:space-around;padding:8px 0}}
.score-item{{text-align:center}}
.score-big{{font-size:28px;font-weight:500;color:#111;line-height:1}}
.score-lbl{{font-size:11px;color:#999;margin-top:4px}}
</style>
</head>
<body>
<div class="root">

<div class="tabs">
  <button class="tab-btn active" onclick="switchTab('overview',this)">Overview</button>
  <button class="tab-btn" onclick="switchTab('detection',this)">Detection Analysis</button>
  <button class="tab-btn" onclick="switchTab('speed',this)">Speed & Efficiency</button>
  <button class="tab-btn" onclick="switchTab('detail',this)">Detail Table</button>
</div>

<!-- ========== TAB: OVERVIEW ========== -->
<div id="tab-overview" class="tab-panel active">

  <div class="metrics">
    <div class="mcard">
      <div class="mcard-lbl">Total Findings</div>
      <div class="mcard-val">{total_findings}</div>
      <div class="mcard-sub">{len(all_models)} models · {selected_file}</div>
    </div>
    <div class="mcard">
      <div class="mcard-lbl">Highest Detection</div>
      <div class="mcard-val">{max_findings}</div>
      <div class="mcard-sub">{max_model}</div>
    </div>
    <div class="mcard">
      <div class="mcard-lbl">Fastest Model</div>
      <div class="mcard-val">{fastest_time}s</div>
      <div class="mcard-sub">{fastest_model}</div>
    </div>
    <div class="mcard">
      <div class="mcard-lbl">Total Critical</div>
      <div class="mcard-val">{total_critical}</div>
      <div class="mcard-sub">all models</div>
    </div>
  </div>

  <div class="cgrid">

    <!-- Total Findings Bar -->
    <div class="ccard">
      <div class="ccard-title">Total findings per model</div>
      <div id="total-bars"></div>
      <div class="legend" id="total-legend"></div>
    </div>

    <!-- Stacked Risk -->
    <div class="ccard">
      <div class="ccard-title">Risk level distribution</div>
      <div id="stacked-bars"></div>
      <div class="legend">
        <span class="leg-item"><span class="leg-dot" style="background:#E24B4A"></span>Critical</span>
        <span class="leg-item"><span class="leg-dot" style="background:#EF9F27"></span>High</span>
        <span class="leg-item"><span class="leg-dot" style="background:#378ADD"></span>Medium</span>
        <span class="leg-item"><span class="leg-dot" style="background:#639922"></span>Low</span>
      </div>
    </div>

    <!-- Radar -->
    <div class="ccard">
      <div class="ccard-title">Multi-dimensional comparison</div>
      <div style="position:relative;height:200px"><canvas id="radarChart"></canvas></div>
      <div class="legend" id="radar-legend"></div>
    </div>

    <!-- Ranking -->
    <div class="ccard">
      <div class="ccard-title">Performance ranking</div>
      <div id="ranking-list"></div>
    </div>

  </div>
</div>

<!-- ========== TAB: DETECTION ========== -->
<div id="tab-detection" class="tab-panel">
  <div class="ccard cgrid-full">
    <div class="ccard-title">Vulnerability detection by type</div>
    <div id="vuln-list"></div>
  </div>
</div>

<!-- ========== TAB: SPEED ========== -->
<div id="tab-speed" class="tab-panel">
  <div class="cgrid">
    <div class="ccard">
      <div class="ccard-title">API response time (seconds)</div>
      <div id="speed-bars"></div>
    </div>
    <div class="ccard">
      <div class="ccard-title">Finding per second efficiency</div>
      <div id="eff-bars"></div>
      <div style="margin-top:8px;font-size:11px;color:#aaa">f/s = findings per second</div>
    </div>
    <div class="ccard cgrid-full">
      <div class="ccard-title">Time — findings tradeoff (bubble chart)</div>
      <div style="position:relative;height:220px"><canvas id="scatterChart"></canvas></div>
      <div class="legend" id="scatter-legend"></div>
    </div>
  </div>
</div>

<!-- ========== TAB: DETAIL ========== -->
<div id="tab-detail" class="tab-panel">
  <div class="ccard">
    <div class="ccard-title">Raw result table</div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Model</th><th>Vulnerability</th><th>Risk</th><th>File</th><th>Date</th>
          </tr>
        </thead>
        <tbody id="detail-tbody"></tbody>
      </table>
    </div>
  </div>
</div>

</div>

<script>
// ── Inject data ────────────────────────────────────────────────────────────────
const SUMMARY       = {json.dumps(summary_json, ensure_ascii=False)};
const DETAILS       = {json.dumps(details_list, ensure_ascii=False)};
const VULN_MATRIX   = {json.dumps(vuln_matrix_json, ensure_ascii=False)};
const MODEL_COLORS  = {json.dumps(model_colors_json, ensure_ascii=False)};
const ALL_MODELS    = {json.dumps(all_models, ensure_ascii=False)};

// ── Helpers ────────────────────────────────────────────────────────────────────
function clr(model) {{
  return MODEL_COLORS[model] || {{border:'#888',bg:'rgba(128,128,128,0.1)',pill_bg:'#eee',pill_fg:'#333'}};
}}

function mpill(model) {{
  const c = clr(model);
  return `<span class="mpill" style="background:${{c.pill_bg}};color:${{c.pill_fg}}">${{model}}</span>`;
}}

function badgeHtml(risk) {{
  const map = {{critical:'b-critical',high:'b-high',medium:'b-medium',low:'b-low'}};
  const cls = map[risk] || 'b-low';
  return `<span class="badge ${{cls}}">${{risk}}</span>`;
}}

// ── Tab switching ──────────────────────────────────────────────────────────────
function switchTab(id, btn) {{
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.getElementById('tab-' + id).classList.add('active');
  btn.classList.add('active');
  if (id === 'speed') initScatter();
}}

// ── Total findings bars ────────────────────────────────────────────────────────
function renderTotalBars() {{
  const el = document.getElementById('total-bars');
  const leg = document.getElementById('total-legend');
  if (!el || !SUMMARY.length) return;
  const maxV = Math.max(...SUMMARY.map(s => s.total || 0)) || 1;
  el.innerHTML = SUMMARY.map(s => {{
    const pct = ((s.total || 0) / maxV * 100).toFixed(1);
    const c = clr(s.model);
    return `<div class="bar-row">
      <div class="bar-lbl" title="${{s.model}}">${{s.model}}</div>
      <div class="bar-track">
        <div class="bar-fill" style="width:${{pct}}%;background:${{c.border}}">
          <span class="bar-val">${{s.total}}</span>
        </div>
      </div>
    </div>`;
  }}).join('');
  leg.innerHTML = SUMMARY.map(s => {{
    const c = clr(s.model);
    return `<span class="leg-item"><span class="leg-dot" style="background:${{c.border}}"></span>${{s.model}}</span>`;
  }}).join('');
}}

// ── Stacked risk bars ──────────────────────────────────────────────────────────
function renderStackedBars() {{
  const el = document.getElementById('stacked-bars');
  if (!el || !SUMMARY.length) return;
  const maxV = Math.max(...SUMMARY.map(s => (s.critical||0)+(s.high||0)+(s.medium||0)+(s.low||0))) || 1;
  el.innerHTML = SUMMARY.map(s => {{
    const tot = (s.critical||0)+(s.high||0)+(s.medium||0)+(s.low||0) || 1;
    const cp = ((s.critical||0)/tot*100).toFixed(1);
    const hp = ((s.high||0)/tot*100).toFixed(1);
    const mp = ((s.medium||0)/tot*100).toFixed(1);
    const lp = ((s.low||0)/tot*100).toFixed(1);
    return `<div class="sbar-row">
      <div class="bar-lbl" title="${{s.model}}">${{s.model}}</div>
      <div class="sbar">
        <div class="sbar-seg" style="width:${{cp}}%;background:#E24B4A" title="Critical: ${{s.critical||0}}"></div>
        <div class="sbar-seg" style="width:${{hp}}%;background:#EF9F27" title="High: ${{s.high||0}}"></div>
        <div class="sbar-seg" style="width:${{mp}}%;background:#378ADD" title="Medium: ${{s.medium||0}}"></div>
        <div class="sbar-seg" style="width:${{lp}}%;background:#639922" title="Low: ${{s.low||0}}"></div>
      </div>
      <span style="font-size:12px;color:#999;min-width:20px">${{s.total||0}}</span>
    </div>`;
  }}).join('');
}}

// ── Radar chart ────────────────────────────────────────────────────────────────
let radarChart = null;
function initRadar() {{
  const ctx = document.getElementById('radarChart');
  if (!ctx || !SUMMARY.length || radarChart) return;
  const maxTotal = Math.max(...SUMMARY.map(s=>s.total||0))||1;
  const maxCrit  = Math.max(...SUMMARY.map(s=>s.critical||0))||1;
  const maxElap  = Math.max(...SUMMARY.map(s=>s.elapsed||0))||1;
  const datasets = SUMMARY.map(s => {{
    const c = clr(s.model);
    const eff = s.elapsed > 0 ? (s.total/s.elapsed) : 0;
    const maxEff = Math.max(...SUMMARY.map(x => x.elapsed>0 ? x.total/x.elapsed : 0))||1;
    return {{
      label: s.model,
      data: [
        Math.round((s.total||0)/maxTotal*100),
        Math.round((s.critical||0)/maxCrit*100),
        Math.round((1 - (s.elapsed||0)/maxElap)*100),
        Math.round(eff/maxEff*100),
        Math.round(((s.high||0)+(s.medium||0))/(maxTotal)*100)
      ],
      borderColor: c.border,
      backgroundColor: c.bg,
      pointBackgroundColor: c.border,
      borderWidth: 1.5,
      pointRadius: 3
    }};
  }});
  radarChart = new Chart(ctx, {{
    type: 'radar',
    data: {{
      labels: ['Detection', 'Critical', 'Speed', 'Efficiency', 'Coverage'],
      datasets
    }},
    options: {{
      responsive: true, maintainAspectRatio: false,
      plugins: {{ legend: {{ display: false }} }},
      scales: {{
        r: {{
          min: 0, max: 100,
          ticks: {{ display: false, stepSize: 25 }},
          grid: {{ color: 'rgba(0,0,0,0.06)' }},
          pointLabels: {{ font: {{ size: 11 }}, color: '#888' }},
          angleLines: {{ color: 'rgba(0,0,0,0.06)' }}
        }}
      }}
    }}
  }});
  const leg = document.getElementById('radar-legend');
  if (leg) {{
    leg.innerHTML = SUMMARY.map(s => {{
      const c = clr(s.model);
      return `<span class="leg-item"><span class="leg-dot" style="background:${{c.border}}"></span>${{s.model}}</span>`;
    }}).join('');
  }}
}}

// ── Ranking ────────────────────────────────────────────────────────────────────
function renderRanking() {{
  const el = document.getElementById('ranking-list');
  if (!el || !SUMMARY.length) return;
  const sorted = [...SUMMARY].sort((a,b) => (b.total||0)-(a.total||0));
  const rankCls = ['r1','r2','r3'];
  el.innerHTML = sorted.map((s, i) => {{
    const score = Math.round(((s.total||0)/Math.max(...SUMMARY.map(x=>x.total||0)||[1]))*100);
    return `<div class="rank-row">
      <div class="rank-num ${{rankCls[i]||''}}">${{i+1}}</div>
      <div class="rank-info">
        <div class="rank-name">${{mpill(s.model)}}</div>
        <div class="rank-detail">${{s.total||0}} findings · ${{s.critical||0}} Critical · ${{(s.elapsed||0).toFixed(1)}}s</div>
      </div>
      <div class="rank-score">${{score}}</div>
    </div>`;
  }}).join('');
}}

// ── Detection matrix ───────────────────────────────────────────────────────────
function renderVulnMatrix() {{
  const el = document.getElementById('vuln-list');
  if (!el || !VULN_MATRIX.length) {{ if(el) el.innerHTML='<p style="color:#aaa;font-size:13px">No data.</p>'; return; }}
  el.innerHTML = VULN_MATRIX.map(v => {{
    const bars = ALL_MODELS.map(m => {{
      const cnt = v.detections[m] || 0;
      const c = clr(m);
      return `<div class="det-bar">
        <div class="det-lbl" title="${{m}}">${{m}}</div>
        <div class="det-track">
          <div class="det-fill" style="width:${{cnt>0?'100':'0'}}%;background:${{c.border}}"></div>
        </div>
      </div>`;
    }}).join('');
    return `<div class="vuln-item">
      <div class="vuln-hdr">
        <span class="vuln-name">${{v.vuln}}</span>
      </div>
      <div class="det-bars">${{bars}}</div>
    </div>`;
  }}).join('');
}}

// ── Speed bars ─────────────────────────────────────────────────────────────────
function renderSpeedBars() {{
  const el = document.getElementById('speed-bars');
  const el2 = document.getElementById('eff-bars');
  if (!el || !SUMMARY.length) return;
  const maxE = Math.max(...SUMMARY.map(s=>s.elapsed||0))||1;
  el.innerHTML = [...SUMMARY].sort((a,b)=>(a.elapsed||0)-(b.elapsed||0)).map(s => {{
    const pct = ((s.elapsed||0)/maxE*100).toFixed(1);
    const c = clr(s.model);
    return `<div class="bar-row">
      <div class="bar-lbl" title="${{s.model}}">${{s.model}}</div>
      <div class="bar-track">
        <div class="bar-fill" style="width:${{pct}}%;background:${{c.border}}">
          <span class="bar-val">${{(s.elapsed||0).toFixed(1)}}s</span>
        </div>
      </div>
    </div>`;
  }}).join('');
  const effs = SUMMARY.map(s => ({{...s, eff: s.elapsed>0 ? (s.total||0)/s.elapsed : 0}}));
  const maxEff = Math.max(...effs.map(s=>s.eff))||1;
  if (el2) {{
    el2.innerHTML = [...effs].sort((a,b)=>b.eff-a.eff).map(s => {{
      const pct = (s.eff/maxEff*100).toFixed(1);
      const c = clr(s.model);
      return `<div class="bar-row">
        <div class="bar-lbl" title="${{s.model}}">${{s.model}}</div>
        <div class="bar-track">
          <div class="bar-fill" style="width:${{pct}}%;background:${{c.border}}">
            <span class="bar-val">${{s.eff.toFixed(2)}} f/s</span>
          </div>
        </div>
      </div>`;
    }}).join('');
  }}
}}

// ── Bubble chart ───────────────────────────────────────────────────────────────
let scatterInit = false, scatterChart = null;
function initScatter() {{
  if (scatterInit) return; scatterInit = true;
  const ctx = document.getElementById('scatterChart');
  if (!ctx || !SUMMARY.length) return;
  const datasets = SUMMARY.map(s => {{
    const c = clr(s.model);
    return {{
      label: s.model,
      data: [{{x: +(s.elapsed||0).toFixed(2), y: s.total||0, r: Math.max(6, (s.total||0)*1.2)}}],
      backgroundColor: c.bg.replace('0.12','0.65').replace('0.10','0.65'),
      borderColor: c.border,
      borderWidth: 1.5
    }};
  }});
  scatterChart = new Chart(ctx, {{
    type: 'bubble',
    data: {{ datasets }},
    options: {{
      responsive: true, maintainAspectRatio: false,
      plugins: {{
        legend: {{ display: false }},
        tooltip: {{
          callbacks: {{
            label: ctx => `${{ctx.dataset.label}}: ${{ctx.raw.y}} findings, ${{ctx.raw.x}}s`
          }}
        }}
      }},
      scales: {{
        x: {{ title: {{ display:true, text:'Response time (s)', font:{{size:11}}, color:'#888' }}, min:0, grid:{{color:'rgba(0,0,0,0.05)'}} }},
        y: {{ title: {{ display:true, text:'Total findings', font:{{size:11}}, color:'#888'   }}, min:0, grid:{{color:'rgba(0,0,0,0.05)'}} }}
      }}
    }}
  }});
  const leg = document.getElementById('scatter-legend');
  if (leg) {{
    leg.innerHTML = SUMMARY.map(s => {{
      const c = clr(s.model);
      return `<span class="leg-item"><span class="leg-dot" style="background:${{c.border}}"></span>${{s.model}}</span>`;
    }}).join('');
  }}
}}

// ── Detail table ───────────────────────────────────────────────────────────────
function renderDetail() {{
  const el = document.getElementById('detail-tbody');
  if (!el) return;
  if (!DETAILS.length) {{ el.innerHTML='<tr><td colspan="5" style="color:#aaa;text-align:center">No data.</td></tr>'; return; }}
  el.innerHTML = DETAILS.map(d => `
    <tr>
      <td>${{mpill(d.model)}}</td>
      <td>${{d.vuln}}</td>
      <td>${{badgeHtml(d.risk)}}</td>
      <td style="color:#888;font-size:11px">${{d.file}}</td>
      <td style="color:#aaa;font-size:11px">${{d.ts}}</td>
    </tr>`).join('');
}}

// ── Boot ───────────────────────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', () => {{
  renderTotalBars();
  renderStackedBars();
  renderRanking();
  renderVulnMatrix();
  renderSpeedBars();
  renderDetail();
  setTimeout(initRadar, 200);
}});
</script>
</body>
</html>
"""

        # ── Load to Streamlit ──────────────────────────────────────────────
        components.html(dashboard_html, height=900, scrolling=True)
