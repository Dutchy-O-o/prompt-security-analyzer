import time
import json
import sqlite3
from datetime import datetime, timezone

from modules.llm_gateway import LLMGateway
from modules.prompt_engineer import PromptEngineer
from modules.parser import ResponseParser
from modules.db_manager import DBManager

# ─── TEST DATASET ─────────────────────────────────────────────────────────────
TEST_CASES = [
    {
        "id": "TC_001_SQLI_JAVA",
        "type": "SQL Injection",
        "code": """
        String query = "SELECT * FROM users WHERE username = '" + user + "'";
        Statement stmt = conn.createStatement();
        rs = stmt.executeQuery(query);
        """
    },
    {
        "id": "TC_002_XSS_PHP",
        "type": "Reflected XSS",
        "code": """
        <?php
        $name = $_GET['name'];
        echo "Hello, " . $name;
        ?>
        """
    },
    {
        "id": "TC_003_AUTH_PYTHON",
        "type": "Hardcoded Credentials",
        "code": """
        def get_db_connection():
            return mysql.connector.connect(
                host="localhost",
                user="admin",
                password="SuperSecretPassword123"
            )
        """
    },
]

# ─── MODELS TO TEST (March 2026) ──────────────────────────────────────
MODELS_TO_TEST = [
    "gemini-2.5-flash",    
    "gemini-3-flash",      
    "gemini-3.1-pro",        
    "gpt-5.4",              
    "gpt-5.3",
    "claude-opus-4-6",      
    "claude-sonnet-4-6",    
    "claude-haiku-4-5",
]

DB_PATH = "security_results.db"


def _ensure_metrics_table():
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS benchmark_metrics (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp           TEXT NOT NULL,
                model_key           TEXT NOT NULL,
                provider            TEXT NOT NULL,
                test_case_id        TEXT NOT NULL,
                test_case_type      TEXT,
                elapsed_sec         REAL NOT NULL,
                findings_count      INTEGER NOT NULL,
                top_risk_level      TEXT,
                vulnerabilities_json TEXT
            )
        """)
        conn.commit()
    finally:
        conn.close()


def _save_metrics(row: dict):
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("""
            INSERT INTO benchmark_metrics
            (timestamp, model_key, provider, test_case_id, test_case_type,
             elapsed_sec, findings_count, top_risk_level, vulnerabilities_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            row["timestamp"], row["model_key"], row["provider"],
            row["test_case_id"], row.get("test_case_type"),
            float(row["elapsed_sec"]), int(row["findings_count"]),
            row.get("top_risk_level"), row.get("vulnerabilities_json"),
        ))
        conn.commit()
    finally:
        conn.close()


def _risk_rank(risk: str) -> int:
    return {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}.get((risk or "").strip(), 0)


def run_benchmark():
    print("\n🚀 BENCHMARK STARTED (Multi-Model, March 2026)...")
    print("=" * 70)

    _ensure_metrics_table()

    gateway  = LLMGateway()
    engineer = PromptEngineer()
    parser   = ResponseParser()
    db       = DBManager()

    print(f"\n✅ Available models: {gateway.available_models()}\n")

    for case in TEST_CASES:
        print(f"\n📂 Test Case: {case['id']} ({case['type']})")
        print("-" * 50)

        for model_key in MODELS_TO_TEST:
            cfg = gateway.MODEL_REGISTRY.get(model_key)
            if not cfg:
                print(f"   ⏭️  {model_key}: [SKIPPED - Not in Registry]")
                continue

            provider = cfg["provider"]

            # Is provider ready?
            if provider == "openai" and not gateway.openai_client:
                print(f"   ⏭️  {model_key}: [SKIPPED - No OpenAI key]")
                continue
            if provider == "gemini" and not gateway.gemini_model:
                print(f"   ⏭️  {model_key}: [SKIPPED - No Gemini key]")
                continue
            if provider == "claude" and not gateway.anthropic_client:
                print(f"   ⏭️  {model_key}: [SKIPPED - No Anthropic key]")
                continue

            print(f"   🤖 Testing {model_key}...", end=" ", flush=True)

            try:
                prompt   = engineer.create_security_prompt(case["code"])
                t0       = time.time()
                response = gateway.send_prompt(prompt, model_key=model_key)
                elapsed  = time.time() - t0

                findings       = parser.parse_report(response) or []
                findings_count = len(findings)

                for item in findings:
                    db.save_result(
                        model=model_key,
                        test_id=case["id"],
                        vuln=item.get("vulnerability", "Unknown"),
                        risk=item.get("risk_level", "Unknown"),
                        raw_resp=json.dumps(item),
                    )

                top_risk = max(
                    (f.get("risk_level") for f in findings),
                    key=_risk_rank, default=None
                ) if findings else None

                _save_metrics({
                    "timestamp":           datetime.now(timezone.utc).isoformat(),
                    "model_key":           model_key,
                    "provider":            provider,
                    "test_case_id":        case["id"],
                    "test_case_type":      case["type"],
                    "elapsed_sec":         elapsed,
                    "findings_count":      findings_count,
                    "top_risk_level":      top_risk,
                    "vulnerabilities_json": json.dumps([
                        {"vulnerability": f.get("vulnerability"), "risk_level": f.get("risk_level")}
                        for f in findings
                    ]),
                })

                print(f"✅ {elapsed:.2f}s | {findings_count} findings | Highest: {top_risk or '-'}")

            except Exception as e:
                print(f"❌ ERROR: {e}")

            time.sleep(0.7)  # Rate limit protection

    print("\n" + "=" * 70)
    print("✅ BENCHMARK COMPLETED.")
    print(f"   Results: benchmark_metrics table → {DB_PATH}")
    print("=" * 70)


if __name__ == "__main__":
    run_benchmark()
