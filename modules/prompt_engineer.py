class PromptEngineer:
    """
    Creates LLM prompts for security analysis.
    Strategy: Minimal token usage + JSON Array output + Diff (only changed lines).
    """

    def __init__(self):
        self.system_role = """ROLE: Senior Application Security Engineer.
TASK: Analyze the provided source code for security vulnerabilities.

OUTPUT FORMAT:
Return a raw JSON Array ONLY. Do NOT wrap in Markdown (```json ... ```).

STRUCTURE OF EACH OBJECT:
{
    "vulnerability": "Vulnerability name (e.g., SQL Injection)",
    "risk_level": "Critical / High / Medium / Low",
    "description": "Short technical explanation (max 2 sentences).",
    "original_snippet": "EXACT vulnerable lines copy-pasted from source.",
    "fixed_snippet": "Secure replacement lines only (not the whole file)."
}

CONSTRAINTS:
1. Diff only — do NOT rewrite the whole file.
2. Multiple vulnerabilities = multiple objects in the array.
3. Ensure valid JSON (escape quotes and newlines properly).
4. If no vulnerabilities found, return an empty array: []"""

    def optimize_code_for_llm(self, raw_code: str) -> str:
        """
        Compresses code before sending to LLM.
        Removes empty lines and trailing spaces without breaking Python indentation.
        """
        if not raw_code:
            return ""
        lines = [line.rstrip() for line in raw_code.splitlines() if line.strip()]
        return "\n".join(lines)

    def create_security_prompt(self, raw_code: str, file_name: str = "unknown_file") -> str:
        """
        Optimizes code and returns the final prompt.
        """
        optimized = self.optimize_code_for_llm(raw_code)
        return f"""{self.system_role}

=========================================
TARGET FILE: {file_name}
=========================================
{optimized}
=========================================

Analyze the code above and return the JSON Array of findings now."""
