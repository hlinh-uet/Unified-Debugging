#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# genprog-docker.sh
# Wrapper gọi GenProg binary bên trong Docker container squareslab/genprog,
# để pipeline apr_genprog có thể chạy trực tiếp trên macOS host.
#
# Cách dùng (tự động qua apr_genprog.py, không cần gọi tay):
#   Chỉ cần set trong .env:
#     GENPROG_BIN=/đường/dẫn/tới/scripts/genprog-docker.sh
# ---------------------------------------------------------------------------
set -euo pipefail

CONFIG_FILE="${1:-}"
if [[ -z "${CONFIG_FILE}" ]]; then
  echo "[genprog-docker] ERROR: Thiếu tham số config file" >&2
  exit 1
fi

# apr_genprog.py gọi binary với cwd=work_dir,
# nên $PWD lúc này chính là work_dir của bug đang xử lý.
WORK_DIR="$PWD"

exec docker run --rm \
  --platform linux/amd64 \
  -v "${WORK_DIR}:${WORK_DIR}" \
  -w "${WORK_DIR}" \
  squareslab/genprog \
  /opt/genprog/bin/genprog "${CONFIG_FILE}"
