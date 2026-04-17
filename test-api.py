import json
import os
import subprocess
from pathlib import Path
from typing import Any
from dotenv import load_dotenv

def test_api_connection() -> None:
    print("=== BẮT ĐẦU TEST API ANTHROPIC ===")
    load_dotenv()  # Load biến môi trường từ file .env
    try:
        base_url = os.getenv("ANTHROPIC_BASE_URL", "https://claude.zunef.com/v1/ai").rstrip("/")
        api_key = os.getenv("ANTHROPIC_AUTH_TOKEN")
        if not base_url:
            raise ValueError("Missing ANTHROPIC_BASE_URL in .env")
        if not api_key:
            raise ValueError("Missing ANTHROPIC_AUTH_TOKEN in .env")
        
        limit_tokens = 1024
        
        payload = {
            "model": os.getenv("ANTHROPIC_MODEL", "anthropic/claude-sonnet-4.6"),
            "system": "You are an expert in fixing C/C++ program bugs. Return ONLY the fixed C function source code, with no explanation.",
            "max_tokens": limit_tokens,
            "temperature": 0.2,
            "stream": False,
            "messages": [
                {
                    "role": "user", 
                    "content": "Hi, this is a test connection. Please reply with exactly 'OK'."
                }
            ]
        }

        body = json.dumps(payload, ensure_ascii=False)

        result = subprocess.run(
            [
                "curl",
                "-sS",
                f"{base_url}/messages",
                "-H",
                "Content-Type: application/json",
                "-H",
                "Accept: application/json",
                "-H",
                f"x-api-key: {api_key}",
                "--data-binary",
                "@-",
            ],
            input=body,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
            timeout=500,
        )

        if result.returncode != 0:
            print(f"[LLM] Error calling Claude API: {result.stderr.strip()}")
            return None
        
        print("✅ KẾT QUẢ TỪ SERVER CLAUDE:")
        print(result.stdout)
    except Exception as e:
        print(f"[LLM] Exception khi gọi Claude: {e}")
        return None

if __name__ == "__main__":
    test_api_connection()