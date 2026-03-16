import json
import re


class ResponseParser:
    def parse_report(self, raw_text):
        """
        Parses raw text from LLM.
        Cleans Markdown code blocks (```json ... ```),
        Extracts JSON arrays from embedded text,
        returns a valid Python list.
        """
        if not raw_text:
            return []

        cleaned = raw_text.strip()

        # Extract content from Markdown code block if present
        if "```" in cleaned:
            match = re.search(r"```(?:json)?\s*(.*?)```", cleaned, re.DOTALL)
            if match:
                cleaned = match.group(1).strip()

        # Sadece köşeli parantez içindeki JSON dizisini (array) yakala
        # Bu, embedded JSON'u metnin neresinde olursa olsun çıkartır
        match = re.search(r"\[\s*\{.*?\}\s*\]", cleaned, re.DOTALL)
        if match:
            cleaned = match.group(0)

        try:
            findings = json.loads(cleaned)
            if isinstance(findings, dict):
                findings = [findings]
            return findings
        except json.JSONDecodeError as e:
            print(f"❌ [Parser] JSON parsing error: {e}")
            print(f"   Raw data start: {cleaned[:150]}...")
            return []
        except Exception as e:
            print(f"❌ [Parser] Unexpected error: {e}")
            return []
