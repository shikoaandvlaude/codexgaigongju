"""
Multi-LLM backend for GPTLens smart contract auditing.

Supports:
  - DeepSeek (default, cheapest)
  - OpenAI (gpt-4o, gpt-4-turbo)
  - Anthropic Claude
  - Ollama (local)
  - Any OpenAI-compatible API

Configuration via environment variables:
  LLM_PROVIDER=deepseek|openai|anthropic|ollama  (default: auto-detect)
  LLM_API_KEY=sk-xxx           (or DEEPSEEK_API_KEY / OPENAI_API_KEY)
  LLM_BASE_URL=https://...     (override API endpoint)
  LLM_MODEL=deepseek-chat      (override model name)
"""

import time
import os
import json

# ── API Key resolution (priority order) ──
def _resolve_api_key():
    return (
        os.environ.get("LLM_API_KEY")
        or os.environ.get("DEEPSEEK_API_KEY")
        or os.environ.get("OPENAI_API_KEY")
        or ""
    )

def _resolve_provider():
    explicit = os.environ.get("LLM_PROVIDER", "").lower()
    if explicit:
        return explicit
    if os.environ.get("DEEPSEEK_API_KEY"):
        return "deepseek"
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    if os.environ.get("OLLAMA_HOST"):
        return "ollama"
    # Default to deepseek (cheapest)
    return "deepseek"

def _resolve_base_url(provider):
    explicit = os.environ.get("LLM_BASE_URL")
    if explicit:
        return explicit
    urls = {
        "deepseek": "https://api.deepseek.com/v1",
        "openai": "https://api.openai.com/v1",
        "ollama": os.environ.get("OLLAMA_HOST", "http://localhost:11434") + "/v1",
    }
    return urls.get(provider, "https://api.deepseek.com/v1")

def _resolve_model(provider, requested_model=None):
    if requested_model and requested_model not in ("gpt-4", "gpt-3.5-turbo", "gpt-4-turbo-preview"):
        return requested_model
    explicit = os.environ.get("LLM_MODEL")
    if explicit:
        return explicit
    defaults = {
        "deepseek": "deepseek-chat",
        "openai": "gpt-4o",
        "anthropic": "claude-sonnet-4-20250514",
        "ollama": "qwen2.5-coder:32b",
    }
    return defaults.get(provider, "deepseek-chat")


# ── Global state ──
PROVIDER = _resolve_provider()
API_KEY = _resolve_api_key()
BASE_URL = _resolve_base_url(PROVIDER)
MODEL = _resolve_model(PROVIDER)

# For backward compatibility
OPENAI_API_KEY = API_KEY

completion_tokens = 0
prompt_tokens = 0

# ── Initialize OpenAI client (works for DeepSeek/Ollama too) ──
try:
    from openai import OpenAI
    _client = OpenAI(api_key=API_KEY, base_url=BASE_URL)
except ImportError:
    _client = None
    print("[!] openai package not installed. Run: pip install openai")


def gpt(prompt, model=None, temperature=0.7, max_tokens=4000, n=1, stop=None) -> list:
    """Send a prompt to the LLM and return n responses."""
    resolved_model = _resolve_model(PROVIDER, model)
    messages = [{"role": "user", "content": prompt}]

    # Rate limit for expensive models
    if "gpt-4" in resolved_model and "turbo" not in resolved_model:
        time.sleep(5)

    return chatgpt(messages, model=resolved_model, temperature=temperature,
                   max_tokens=max_tokens, n=n, stop=stop)


def chatgpt(messages, model, temperature, max_tokens, n, stop) -> list:
    """Call the chat completion API (works with any OpenAI-compatible endpoint)."""
    global completion_tokens, prompt_tokens

    if _client is None:
        raise RuntimeError("OpenAI client not initialized. Install: pip install openai")

    outputs = []
    remaining = n

    while remaining > 0:
        cnt = min(remaining, 10)
        remaining -= cnt

        try:
            res = _client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                n=cnt,
                stop=stop,
            )
            outputs.extend([choice.message.content for choice in res.choices])

            if res.usage:
                completion_tokens += res.usage.completion_tokens
                prompt_tokens += res.usage.prompt_tokens

        except Exception as e:
            print(f"[LLM Error] {e}")
            # Retry once after short delay
            time.sleep(3)
            try:
                res = _client.chat.completions.create(
                    model=model,
                    messages=messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    n=cnt,
                    stop=stop,
                )
                outputs.extend([choice.message.content for choice in res.choices])
                if res.usage:
                    completion_tokens += res.usage.completion_tokens
                    prompt_tokens += res.usage.prompt_tokens
            except Exception as e2:
                print(f"[LLM Retry Failed] {e2}")
                outputs.append("")

    return outputs


def gpt_usage(backend=None):
    """Return token usage and estimated cost."""
    global completion_tokens, prompt_tokens
    model = backend or MODEL

    # Cost estimation per 1K tokens (input/output)
    costs = {
        "deepseek-chat": (0.0005, 0.002),
        "deepseek-reasoner": (0.001, 0.004),
        "gpt-4o": (0.005, 0.015),
        "gpt-4-turbo-preview": (0.01, 0.03),
        "gpt-4": (0.03, 0.06),
        "gpt-3.5-turbo": (0.0015, 0.002),
    }

    input_cost, output_cost = costs.get(model, (0.001, 0.003))
    cost = prompt_tokens / 1000 * input_cost + completion_tokens / 1000 * output_cost

    return {
        "provider": PROVIDER,
        "model": model,
        "completion_tokens": completion_tokens,
        "prompt_tokens": prompt_tokens,
        "cost_usd": round(cost, 4),
    }


def get_config_summary():
    """Print current LLM configuration."""
    return {
        "provider": PROVIDER,
        "model": MODEL,
        "base_url": BASE_URL,
        "api_key_set": bool(API_KEY),
    }
