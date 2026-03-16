import os
from openai import OpenAI
import anthropic
from dotenv import load_dotenv

try:
    from google import genai as google_genai
    GOOGLE_SDK = "new"
except ImportError:
    try:
        import google.generativeai as genai_legacy
        GOOGLE_SDK = "legacy"
    except ImportError:
        GOOGLE_SDK = "none"

current_dir = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(current_dir, '..', '.env'))

SYSTEM_PROMPT = "You are a senior code security analyst. Return ONLY a JSON array of findings, no markdown."


class LLMGateway:

    MODEL_REGISTRY = {
        # ── Google Gemini ──────────────────────────────────────────────────
        "gemini-2.5-flash":      {"provider": "gemini",            "id": "gemini-2.5-flash"},
        "gemini-2.5-pro":        {"provider": "gemini",            "id": "gemini-2.5-pro"},
        "gemini-3-flash":        {"provider": "gemini",            "id": "gemini-3-flash-preview"},
        "gemini-3.1-pro":        {"provider": "gemini",            "id": "gemini-3.1-pro-preview"},

        # ── OpenAI — Chat Completions (v1/chat/completions) ───────────────
        "gpt-4.1":               {"provider": "openai_chat",       "id": "gpt-4.1"},
        "gpt-4.1-mini":          {"provider": "openai_chat",       "id": "gpt-4.1-mini"},
        "gpt-5.2":               {"provider": "openai_chat",       "id": "gpt-5.2"},
        "gpt-5.3":               {"provider": "openai_chat",       "id": "gpt-5.3-chat-latest"},
        "gpt-5.4":               {"provider": "openai_chat",       "id": "gpt-5.4"},

        # ── Anthropic Claude ──────────────────────────────────────────────
        "claude-opus-4-6":       {"provider": "claude",            "id": "claude-opus-4-6"},
        "claude-sonnet-4-6":     {"provider": "claude",            "id": "claude-sonnet-4-6"},
        "claude-haiku-4-5":      {"provider": "claude",            "id": "claude-haiku-4-5-20251001"},
    }

    DEFAULT_MODEL_KEYS = {
        "gemini": "gemini-2.5-flash",
        "gpt":    "gpt-5.4",
        "claude": "claude-sonnet-4-6",
    }

    def __init__(self):
        # ── GEMINI ────────────────────────────────────────────────────────
        self.gemini_key     = os.getenv("GOOGLE_API_KEY")
        self._gemini_ready  = False
        self._gemini_client = None

        if self.gemini_key:
            if GOOGLE_SDK == "new":
                try:
                    self._gemini_client = google_genai.Client(api_key=self.gemini_key)
                    self._gemini_ready  = True
                    print("✓ [Gemini] google-genai SDK hazır.")
                except Exception as e:
                    print(f"❌ [Gemini] Başlatma hatası: {e}")
            elif GOOGLE_SDK == "legacy":
                try:
                    genai_legacy.configure(api_key=self.gemini_key)
                    self._gemini_ready = True
                    print("✓ [Gemini] Eski SDK hazır (öneri: pip install google-genai).")
                except Exception as e:
                    print(f"❌ [Gemini] Eski SDK hatası: {e}")
            else:
                print("❌ [Gemini] SDK yok. Çalıştır: pip install google-genai")
        else:
            print("⚠️  [Gemini] GOOGLE_API_KEY bulunamadı.")

        # ── OPENAI ────────────────────────────────────────────────────────
        self.openai_key    = os.getenv("OPENAI_API_KEY")
        self.openai_client = None

        if self.openai_key:
            try:
                self.openai_client = OpenAI(api_key=self.openai_key)
                print("✓ [OpenAI] Chat Completions + Responses API hazır.")
            except Exception as e:
                print(f"❌ [OpenAI] Başlatma hatası: {e}")
        else:
            print("⚠️  [OpenAI] OPENAI_API_KEY bulunamadı.")

        # ── ANTHROPIC CLAUDE ─────────────────────────────────────────────
        self.anthropic_key    = os.getenv("ANTHROPIC_API_KEY")
        self.anthropic_client = None

        if self.anthropic_key:
            try:
                self.anthropic_client = anthropic.Anthropic(api_key=self.anthropic_key)
                print("✓ [Claude] İstemci hazır.")
            except Exception as e:
                print(f"❌ [Claude] Başlatma hatası: {e}")
        else:
            print("⚠️  [Claude] ANTHROPIC_API_KEY bulunamadı.")

    # ─────────────────────────────────────────────────────────────────────

    def _resolve_model_key(self, model_key=None, model_type=None):
        if model_key:
            return model_key
        return self.DEFAULT_MODEL_KEYS.get(model_type)

    def send_prompt(self, prompt_text: str, model_type: str = None, model_key: str = None) -> str | None:
        resolved = self._resolve_model_key(model_key=model_key, model_type=model_type)
        if not resolved:
            print(f"❌ [Gateway] Model çözümlenemedi.")
            return None

        cfg = self.MODEL_REGISTRY.get(resolved)
        if not cfg:
            print(f"❌ [Gateway] '{resolved}' registry'de bulunamadı.")
            return None

        provider = cfg["provider"]
        model_id = cfg["id"]

        # ── GEMINI ────────────────────────────────────────────────────────
        if provider == "gemini":
            if not self._gemini_ready:
                print(f"⚠️  [Gemini] Hazır değil, {resolved} atlanıyor.")
                return None
            try:
                if GOOGLE_SDK == "new":
                    resp = self._gemini_client.models.generate_content(
                        model=model_id,
                        contents=prompt_text,
                        config={"max_output_tokens": 5000},
                    )
                    return resp.text
                else:
                    m = genai_legacy.GenerativeModel(model_id)
                    return m.generate_content(prompt_text, generation_config=genai_legacy.types.GenerationConfig(max_output_tokens=5000)).text
            except Exception as e:
                print(f"❌ [Gemini] {model_id} hata: {e}")
                return None

        # ── OPENAI CHAT COMPLETIONS ───────────────────────────────────────
        if provider == "openai_chat":
            if not self.openai_client:
                print(f"⚠️  [OpenAI] Client yok, {resolved} atlanıyor.")
                return None
            try:
                resp = self.openai_client.chat.completions.create(
                    model=model_id,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user",   "content": prompt_text},
                    ],
                    max_tokens=5000,
                    timeout=120,
                )
                return resp.choices[0].message.content
            except Exception as e:
                print(f"❌ [OpenAI Chat] {model_id} hata: {e}")
                return None

        # ── OPENAI RESPONSES API ────────────────────────────────────────── 
        if provider == "openai_responses":
            if not self.openai_client:
                print(f"⚠️  [OpenAI] Client yok, {resolved} atlanıyor.")
                return None
            try:
                resp = self.openai_client.responses.create(
                    model=model_id,
                    instructions=SYSTEM_PROMPT,
                    input=prompt_text,
                    max_tokens=5000,
                    timeout=300,
                )
                return resp.output_text
            except Exception as e:
                print(f"❌ [OpenAI Responses] {model_id} hata: {e}")
                return None

        # ── ANTHROPIC CLAUDE ─────────────────────────────────────────────
        if provider == "claude":
            if not self.anthropic_client:
                print(f"⚠️  [Claude] Client yok, {resolved} atlanıyor.")
                return None
            try:
                msg = self.anthropic_client.messages.create(
                    model=model_id,
                    max_tokens=5000,
                    system=SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": prompt_text}],
                )
                return msg.content[0].text
            except Exception as e:
                print(f"❌ [Claude] {model_id} hata: {e}")
                return None

        print(f"❌ [Gateway] Bilinmeyen provider: {provider}")
        return None

    @property
    def gemini_model(self):
        return self._gemini_ready

    def available_models(self) -> list[str]:
        out = []
        for key, cfg in self.MODEL_REGISTRY.items():
            p = cfg["provider"]
            if p == "gemini"            and self._gemini_ready:    out.append(key)
            elif p == "openai_chat"     and self.openai_client:    out.append(key)
            elif p == "openai_responses"and self.openai_client:    out.append(key)
            elif p == "claude"          and self.anthropic_client: out.append(key)
        return out