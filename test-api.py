import json
import os
import subprocess
from pathlib import Path
from typing import Any

def load_env(env_path: str = ".env") -> None:
    env_file = Path(env_path)
    if not env_file.exists():
        return

    for raw_line in env_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())

def get_api_config() -> tuple[str, str]:
    base_url = os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com/v1").rstrip("/")
    api_key = os.getenv("ANTHROPIC_AUTH_TOKEN") or os.getenv("ANTHROPIC_API_KEY", "")

    if not api_key:
        raise ValueError("LỖI: Không tìm thấy API Key trong file .env")

    return base_url, api_key

def build_test_payload() -> dict[str, Any]:
    model = os.getenv("ANTHROPIC_MODEL", "anthropic/claude-sonnet-4.6")
    prompt = "Hi, this is a test connection. Please reply with exactly 'OK'."

    return {
        "model": model,
        "max_tokens": 1024, # TĂNG LÊN 1024 ĐỂ ĐỦ TOKEN CHO QUÁ TRÌNH THINKING
        "stream": False,
        "messages": [
            {
                "role": "user",
                "content": prompt,
            }
        ],
    }

def parse_sse_stream(raw_text: str) -> tuple[str, str]:
    """Hàm trích xuất text từ định dạng SSE (Server-Sent Events)"""
    text_parts = []
    thinking_parts = []
    
    for line in raw_text.splitlines():
        line = line.strip()
        if line.startswith("data: "):
            json_str = line[6:]
            if json_str == "[DONE]":
                continue
            try:
                data = json.loads(json_str)
                # Bắt các đoạn text và thinking được stream về
                delta = data.get("delta", {})
                if delta.get("type") == "text_delta":
                    text_parts.append(delta.get("text", ""))
                elif delta.get("type") == "thinking_delta":
                    thinking_parts.append(delta.get("thinking", ""))
            except json.JSONDecodeError:
                continue
                
    return "".join(thinking_parts), "".join(text_parts)

def test_api_connection() -> None:
    print("=== BẮT ĐẦU TEST API ANTHROPIC ===")
    try:
        load_env()
        base_url, api_key = get_api_config()
    except Exception as e:
        print(f"❌ Lỗi cấu hình: {e}")
        return

    payload = build_test_payload()
    body = json.dumps(payload, ensure_ascii=False)

    print(f"URL: {base_url}/messages")
    print(f"Key format: {api_key[:10]}... (Độ dài: {len(api_key)})")
    print("Đang gửi request, vui lòng đợi...\n")

    result = subprocess.run(
        [
            "curl",
            "-sS",
            f"{base_url}/messages",
            "-H", "Content-Type: application/json",
            "-H", "Accept: application/json",
            "-H", f"x-api-key: {api_key}",
            "-H", "anthropic-version: 2023-06-01",
            "--data-binary", "@-",
        ],
        input=body,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
        timeout=30,
    )

    if result.returncode != 0:
        print(f"❌ Lỗi mạng hoặc cURL: {result.stderr.strip()}")
        return

    # KIỂM TRA XEM SERVER TRẢ VỀ DẠNG SSE HAY JSON THƯỜNG
    raw_output = result.stdout.strip()
    
    if raw_output.startswith("event:") or "data:" in raw_output:
        # Server trả về dạng Stream
        thinking, text = parse_sse_stream(raw_output)
        print("✅ KẾT NỐI THÀNH CÔNG (Dạng Stream)!")
        
        if thinking:
            print(f"🧠 Quá trình suy nghĩ:\n{thinking.strip()}\n")
            
        print(f"🤖 Claude phản hồi: {text.strip()}")
        
    else:
        # Server trả về dạng JSON thuần túy
        try:
            response_data = json.loads(raw_output)
            if "error" in response_data:
                error_info = response_data["error"]
                print("❌ KẾT NỐI THẤT BẠI!")
                print(f"- Loại lỗi: {error_info.get('type')}")
                print(f"- Tin nhắn: {error_info.get('message')}")
                return

            print("✅ KẾT NỐI THÀNH CÔNG (Dạng JSON)!")
            content = response_data.get("content", [])
            for block in content:
                if block.get("type") == "text":
                    print(f"🤖 Claude phản hồi: {block.get('text')}")
                    
        except json.JSONDecodeError:
            print("❌ Lỗi: Server trả về định dạng không xác định.")
            print(f"Raw output: {raw_output}")

if __name__ == "__main__":
    test_api_connection()