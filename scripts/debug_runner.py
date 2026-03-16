"""
Diagnoses which model returns 0 findings and why.
Run with:
python debug_runner.py
"""
import sys
sys.path.insert(0, '.')

from modules.llm_gateway import LLMGateway
from modules.prompt_engineer import PromptEngineer
from modules.parser import ResponseParser

TEST_CODE = """
String query = "SELECT * FROM users WHERE username = '" + user + "'";
Statement stmt = conn.createStatement();
rs = stmt.executeQuery(query);
"""

SUSPECT_MODELS = [
    "gpt-5.3",
    "gpt-5.4",
    "claude-sonnet-4-6",
    "claude-haiku-4-5",
    "claude-opus-4-6",
    "gemini-2.5-flash",
    "gemini-3-flash",
    "gemini-3.1-pro",
    "gemini-2.5-pro"
]

def diagnose():
    gateway  = LLMGateway()
    engineer = PromptEngineer()
    parser   = ResponseParser()

    prompt = engineer.create_security_prompt(TEST_CODE, file_name="test_sqli.java")

    print("\n" + "=" * 70)
    print("DIAGNOSIS REPORT")
    print("=" * 70)

    for model_key in SUSPECT_MODELS:
        print(f"\nModel: {model_key}")
        print("-" * 40)

        cfg = gateway.MODEL_REGISTRY.get(model_key)
        if not cfg:
            print("  MODEL_REGISTRY: NOT FOUND")
            continue

        provider = cfg["provider"]
        model_id = cfg["id"]
        print(f"  Provider : {provider}")
        print(f"  Model ID : {model_id}")

        # Check if provider client is ready
        if provider == "openai" and not gateway.openai_client:
            print("  OpenAI client NOT AVAILABLE (API key missing?)")
            continue
        if provider == "gemini" and not gateway.gemini_model:
            print("  Gemini client NOT AVAILABLE (API key missing?)")
            continue
        if provider == "claude" and not gateway.anthropic_client:
            print("  Anthropic client NOT AVAILABLE (API key missing?)")
            continue

        # Get raw API response
        raw = gateway.send_prompt(prompt, model_key=model_key)

        if raw is None:
            print("  send_prompt returned None (API error, check logs above)")
            continue

        print(f"  Raw response length : {len(raw)} characters")
        print(f"  First 300 characters:\n{raw[:300]}\n")

        # Try parsing the response
        findings = parser.parse_report(raw)
        if findings:
            print(f"  Parse successful → {len(findings)} findings")
        else:
            print("  Parse failed or no findings")
            print("  Last 200 characters:\n" + raw[-200:])

    print("\n" + "=" * 70)

if __name__ == "__main__":
    diagnose()