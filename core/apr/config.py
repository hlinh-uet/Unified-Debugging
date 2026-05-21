import os

from dotenv import load_dotenv


load_dotenv()

DEFAULT_LLM_PROVIDER = os.getenv("LLM_PROVIDER", "openrouter").strip().lower()

APR_TOP_K = int(os.getenv("APR_TOP_K", "3"))
APR_MAX_SOURCE_CHARS = int(os.getenv("APR_MAX_SOURCE_CHARS", "30000"))
APR_MAX_LOCAL_HEADER_CONTEXT_CHARS = int(os.getenv("APR_MAX_LOCAL_HEADER_CONTEXT_CHARS", "12000"))
APR_MAX_TEST_ID_STORE = int(os.getenv("APR_MAX_TEST_ID_STORE", "50"))
APR_MAX_FAILURE_SIGNAL_LINES = int(os.getenv("APR_MAX_FAILURE_SIGNAL_LINES", "20"))
APR_MAX_FAILURE_SIGNAL_LINE_CHARS = int(os.getenv("APR_MAX_FAILURE_SIGNAL_LINE_CHARS", "300"))
APR_SKIP_EXISTING = os.getenv("APR_SKIP_EXISTING", "1").strip().lower() not in ("0", "false", "no")
