import sqlite3
import os
from datetime import datetime


class DBManager:
    def __init__(self, db_name="security_results.db"):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.db_path = os.path.join(base_dir, db_name)
        self.init_db()

    def init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS analysis_results (
                id                   INTEGER PRIMARY KEY AUTOINCREMENT,
                model_name           TEXT,
                test_case_id         TEXT,
                vulnerability_detected TEXT,
                risk_level           TEXT,
                raw_response         TEXT,
                original_snippet     TEXT,
                fixed_snippet        TEXT,
                timestamp            DATETIME
            )
        ''')

        # Migration: sütunlar eksikse ekle
        cursor.execute("PRAGMA table_info(analysis_results)")
        columns = [info[1] for info in cursor.fetchall()]
        if 'original_snippet' not in columns:
            print("   ⚙️  [DB] Adding 'original_snippet' column...")
            cursor.execute("ALTER TABLE analysis_results ADD COLUMN original_snippet TEXT")
        if 'fixed_snippet' not in columns:
            print("   ⚙️  [DB] Adding 'fixed_snippet' column...")
            cursor.execute("ALTER TABLE analysis_results ADD COLUMN fixed_snippet TEXT")

        conn.commit()
        conn.close()

    def save_result(self, model, test_id, vuln, risk, raw_resp,
                    original_code=None, fixed_code=None):
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute('''
                INSERT INTO analysis_results
                (model_name, test_case_id, vulnerability_detected, risk_level,
                 raw_response, original_snippet, fixed_snippet, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (model, test_id, vuln, risk, raw_resp,
                  original_code, fixed_code, datetime.now()))
            conn.commit()
            conn.close()
            print(f"   💾 [DB] Saved: {test_id}")
        except Exception as e:
            print(f"   ❌ [DB Error] Save failed: {e}")
