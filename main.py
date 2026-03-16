import json

from modules.llm_gateway import LLMGateway
from modules.prompt_engineer import PromptEngineer
from modules.parser import ResponseParser
from modules.file_loader import FileLoader
from modules.db_manager import DBManager


def main():
    print("\n🔍 SECURITY SCAN INITIATED...")
    print("=" * 70)

    loader   = FileLoader()
    gateway  = LLMGateway()
    engineer = PromptEngineer()
    parser   = ResponseParser()
    db       = DBManager()

    # Specify the file to scan
    target_filename = "vulnerable_app.py"

    print(f"\n📂 Loading file: {target_filename}")
    code_content = loader.load_file(target_filename)

    if not code_content:
        print("❌ File not found — check 'test_files' directory.")
        return

    # Default model: claude-sonnet-4-6 (quality/speed balance)
    # To change: model_key="gemini-3.1-pro" or "gpt-5.4"
    model_key = "claude-sonnet-4-6"

    print(f"🤖 Model: {model_key}")
    print("📡 Analyzing code...\n")

    prompt      = engineer.create_security_prompt(code_content, file_name=target_filename)
    raw_response = gateway.send_prompt(prompt, model_key=model_key)
    findings    = parser.parse_report(raw_response)

    if not findings:
        print("⚠️  No findings found or JSON parsing failed.")
        print("Raw response:", raw_response)
        return

    print(f"✅ SCAN COMPLETED — {len(findings)} security vulnerabilities found.")
    print("=" * 70)

    for i, item in enumerate(findings, 1):
        vuln_name     = item.get("vulnerability", "Unknown")
        risk          = item.get("risk_level", "Unknown")
        desc          = item.get("description", "")
        original_code = item.get("original_snippet", "")
        fixed_code    = item.get("fixed_snippet", "")

        print(f"\n🔸 FINDING #{i}: {vuln_name}")
        print(f"   Risk: {risk}")
        print(f"   Note:  {desc}")
        print("-" * 30 + " 🔴 VULNERABLE CODE " + "-" * 20)
        print(original_code.strip())
        print("-" * 30 + " 🟢 SECURE CODE " + "-" * 27)
        print(fixed_code.strip())
        print("=" * 70)

        db.save_result(
            model=model_key,
            test_id=f"{target_filename}_Vuln_{i}",
            vuln=vuln_name,
            risk=risk,
            raw_resp=json.dumps(item),
            original_code=original_code,
            fixed_code=fixed_code,
        )


if __name__ == "__main__":
    main()
