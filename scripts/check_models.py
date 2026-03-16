#!/usr/bin/env python3
"""Check available models and API connections"""
import warnings
warnings.filterwarnings('ignore', category=FutureWarning)

from modules.llm_gateway import LLMGateway

print("\n" + "="*70)
print("AVAILABLE MODELS AND CONNECTION STATUS")
print("="*70)

gw = LLMGateway()

print("\nGOOGLE GEMINI:")
if gw._gemini_ready:
    models = [m for m, c in gw.MODEL_REGISTRY.items() if c['provider'] == 'gemini']
    for model in models:
        print(f"    Available: {model}")
else:
    print("    Not available")

print("\nOPENAI GPT:")
if gw.openai_client:
    models = [m for m, c in gw.MODEL_REGISTRY.items() if c['provider'] == 'openai']
    for model in models:
        print(f"    Available: {model}")
else:
    print("    Not available")

print("\nANTHROPIC CLAUDE:")
if gw.anthropic_client:
    models = [m for m, c in gw.MODEL_REGISTRY.items() if c['provider'] == 'claude']
    for model in models:
        print(f"    Available: {model}")
else:
    print("    Not available")

print("\n" + "="*70 + "\n")