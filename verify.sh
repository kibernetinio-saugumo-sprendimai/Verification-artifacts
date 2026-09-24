#!/usr/bin/env bash
# SafeStack Verifiable Ecosystem Engine Runner
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== SafeStack Cryptographic Verification Suite ==="
python3 "${SCRIPT_DIR}/verify_ecosystem.py"
