import os
import time
from typing import Optional

import requests

from core.apr.config import DEFAULT_LLM_PROVIDER


DEFAULT_SYSTEM_PROMPT = "You are a precise coding assistant. Return only the requested content."


def _extract_chat_message_content(message) -> Optional[str]:
    if not isinstance(message, dict):
        return None

    content = message.get("content")
    if isinstance(content, str):
        return content

    if isinstance(content, list):
        text_parts = []
        for part in content:
            if isinstance(part, str):
                text_parts.append(part)
            elif isinstance(part, dict):
                part_text = part.get("text") or part.get("content")
                if isinstance(part_text, str):
                    text_parts.append(part_text)
        if text_parts:
            return "".join(text_parts)

    return None


def _is_transient_llm_error(code=None, metadata=None) -> bool:
    if code in (408, 409, 425, 429, 500, 502, 503, 504):
        return True
    error_type = ""
    if isinstance(metadata, dict):
        error_type = str(metadata.get("error_type") or "").lower()
    return error_type in {
        "provider_unavailable",
        "rate_limit_exceeded",
        "timeout",
        "server_error",
        "overloaded",
    }


def _call_openai(
    prompt: str,
    model: str = "gpt-4o-mini",
    system_prompt: str = DEFAULT_SYSTEM_PROMPT,
) -> Optional[str]:
    return _call_openai_compatible_chat(
        prompt,
        provider_label="OpenAI",
        api_key=os.getenv("OPENAI_API_KEY"),
        missing_key_message="OPENAI_API_KEY chưa được đặt trong .env.",
        base_url=os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"),
        model=model,
        system_prompt=system_prompt,
    )


def _call_openrouter(
    prompt: str,
    model: str = "qwen/qwen3-coder-30b-a3b-instruct",
    system_prompt: str = DEFAULT_SYSTEM_PROMPT,
) -> Optional[str]:
    return _call_openai_compatible_chat(
        prompt,
        provider_label="OpenRouter",
        api_key=os.getenv("OPENROUTER_API_KEY"),
        missing_key_message="Không tìm thấy OPENROUTER_API_KEY trong môi trường.",
        base_url=os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
        model=model,
        extra_headers={
            "HTTP-Referer": os.getenv("OPENROUTER_SITE_URL", "http://localhost:3000"),
            "X-Title": os.getenv("OPENROUTER_APP_NAME", "UET_APR_Research"),
        },
        system_prompt=system_prompt,
    )


def _call_openai_compatible_chat(
    prompt: str,
    *,
    provider_label: str,
    api_key: Optional[str],
    missing_key_message: str,
    base_url: str,
    model: str,
    extra_headers: Optional[dict] = None,
    system_prompt: str = DEFAULT_SYSTEM_PROMPT,
) -> Optional[str]:
    try:
        if not api_key:
            print(f"[LLM] LỖI: {missing_key_message}")
            return None

        url = f"{base_url.rstrip('/')}/chat/completions"

        headers = {
            "Authorization": f"Bearer {api_key.strip()}",
            "Content-Type": "application/json",
        }
        if extra_headers:
            headers.update(extra_headers)

        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.1,
            "max_tokens": int(os.getenv("LLM_MAX_OUTPUT_TOKENS", "12000")),
        }

        timeout = int(os.getenv("LLM_REQUEST_TIMEOUT", "120"))
        retries = int(os.getenv("LLM_RETRIES", "3"))
        for attempt in range(1, retries + 1):
            try:
                response = requests.post(url, headers=headers, json=payload, timeout=timeout)
            except requests.exceptions.RequestException as exc:
                if attempt >= retries:
                    raise
                sleep_s = min(2 ** attempt, 15)
                print(
                    f"[LLM] {provider_label} lỗi kết nối lần {attempt}/{retries}: {exc}. "
                    f"Thử lại sau {sleep_s}s..."
                )
                time.sleep(sleep_s)
                continue

            if response.status_code != 200:
                if _is_transient_llm_error(response.status_code) and attempt < retries:
                    sleep_s = min(2 ** attempt, 15)
                    print(
                        f"[LLM] {provider_label} HTTP {response.status_code} lần {attempt}/{retries}. "
                        f"Thử lại sau {sleep_s}s..."
                    )
                    time.sleep(sleep_s)
                    continue
                print(f"[LLM] Error {response.status_code}: {response.text[:1000]}")
                return None

            try:
                result = response.json()
            except ValueError as exc:
                print(f"[LLM] {provider_label} trả về JSON không hợp lệ: {exc}")
                return None

            choices = result.get("choices") or []
            if not choices:
                print(f"[LLM] {provider_label} response không có choices: {response.text[:1000]}")
                return None

            choice = choices[0] or {}
            choice_error = choice.get("error") or result.get("error")
            if choice_error:
                error_code = choice_error.get("code") if isinstance(choice_error, dict) else None
                try:
                    transient_code = int(error_code)
                except (TypeError, ValueError):
                    transient_code = None
                metadata = choice_error.get("metadata") if isinstance(choice_error, dict) else None
                message = choice_error.get("message") if isinstance(choice_error, dict) else str(choice_error)
                if _is_transient_llm_error(transient_code, metadata) and attempt < retries:
                    sleep_s = min(2 ** attempt, 15)
                    print(
                        f"[LLM] {provider_label} provider lỗi {error_code} lần {attempt}/{retries}: {message}. "
                        f"Thử lại sau {sleep_s}s..."
                    )
                    time.sleep(sleep_s)
                    continue
                print(f"[LLM] {provider_label} provider error {error_code}: {message}")
                return None

            message = choice.get("message") or {}
            raw_content = _extract_chat_message_content(message)
            if raw_content is None:
                finish_reason = choice.get("finish_reason")
                reasoning = message.get("reasoning")
                reasoning_len = len(reasoning) if isinstance(reasoning, str) else 0
                if attempt < retries:
                    sleep_s = min(2 ** attempt, 15)
                    print(
                        f"[LLM] {provider_label} trả về content=null lần {attempt}/{retries} "
                        f"(finish_reason={finish_reason}, reasoning_len={reasoning_len}). "
                        f"Thử lại sau {sleep_s}s..."
                    )
                    time.sleep(sleep_s)
                    continue
                print(
                    f"[LLM] {provider_label} không trả về code content "
                    f"(finish_reason={finish_reason}, reasoning_len={reasoning_len})."
                )
                return None

            if not raw_content.strip():
                if attempt < retries:
                    sleep_s = min(2 ** attempt, 15)
                    print(
                        f"[LLM] {provider_label} trả về content rỗng lần {attempt}/{retries}. "
                        f"Thử lại sau {sleep_s}s..."
                    )
                    time.sleep(sleep_s)
                    continue
                print(f"[LLM] {provider_label} trả về content rỗng.")
                return None

            return raw_content

        return None

    except Exception as e:
        print(f"[LLM] Exception khi gọi {provider_label}: {e}")
        return None


def call_llm(
    prompt: str,
    provider: Optional[str] = None,
    system_prompt: str = DEFAULT_SYSTEM_PROMPT,
) -> Optional[str]:
    """
    Gọi LLM cho một APR agent step.

    Args:
        prompt:        Nội dung prompt gửi đến LLM.
        provider:      'openai' | 'openrouter'.
                       Nếu None, đọc từ biến môi trường LLM_PROVIDER.
        system_prompt: System prompt cho agent step hiện tại.

    Returns:
        Chuỗi LLM trả về, hoặc None nếu lỗi.
    """
    chosen = (provider or DEFAULT_LLM_PROVIDER).strip().lower()

    if chosen == "openai":
        openai_model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        print(f"[LLM] Provider: OpenAI ({openai_model})")
        return _call_openai(prompt, model=openai_model, system_prompt=system_prompt)

    if chosen == "openrouter":
        openrouter_model = os.getenv("OPENROUTER_MODEL", "qwen/qwen3-coder-30b-a3b-instruct")
        print(f"[LLM] Provider: OpenRouter ({openrouter_model})")
        return _call_openrouter(prompt, model=openrouter_model, system_prompt=system_prompt)

    print(f"[LLM] Warning: Provider không hỗ trợ '{chosen}'. Chọn 'openai' hoặc 'openrouter'.")
    return None
