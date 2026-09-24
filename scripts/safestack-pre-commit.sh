#!/usr/bin/env bash
# SafeStack Zero-Leakage Pre-Commit Security Hook
# Prevents accidental commits of private keys, certificates, or private repository internal references.
set -euo pipefail

echo "[SafeStack Gate] Running pre-commit security verification..."

FORBIDDEN_PATTERNS=(
    "-----BEGIN RSA PRIVATE KEY-----"
    "-----BEGIN OPENSSH PRIVATE KEY-----"
    "-----BEGIN PRIVATE KEY-----"
    "-----BEGIN EC PRIVATE KEY-----"
)

# Private repository names that must never be committed to public repositories
FORBIDDEN_REPOS=(
    "safestack-PI5-VPN-Freedom"
    "safestack-Pi-5-VPN"
    "safestack_registry"
    "safestack-sertifikatai"
    "telegram-ai-bot"
    "safestack-web"
    "safestack-web-2"
)

# Staged files
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM || true)

if [ -z "${STAGED_FILES}" ]; then
    exit 0
fi

FAILED=0

for FILE in ${STAGED_FILES}; do
    # Skip binary files or deleted files
    if [ ! -f "${FILE}" ]; then
        continue
    fi
    if file "${FILE}" | grep -q 'binary'; then
        continue
    fi
    # Skip this pre-commit script itself
    if [[ "${FILE}" == *"safestack-pre-commit.sh"* ]]; then
        continue
    fi

    # Check for private keys
    for PATTERN in "${FORBIDDEN_PATTERNS[@]}"; do
        if grep -Fq "${PATTERN}" "${FILE}"; then
            echo "  ✗ ERROR: Private key pattern detected in staged file: ${FILE}" >&2
            FAILED=1
        fi
    done

    # Check for private repository references
    for PRIV in "${FORBIDDEN_REPOS[@]}"; do
        if grep -Fq "${PRIV}" "${FILE}"; then
            echo "  ✗ ERROR: Forbidden private repository reference '${PRIV}' in staged file: ${FILE}" >&2
            FAILED=1
        fi
    done
done

if [ ${FAILED} -ne 0 ]; then
    echo "[SafeStack Gate] Commit rejected: Zero-leakage policy violated." >&2
    echo "Remove forbidden private keys or private repo references before committing." >&2
    exit 1
fi

echo "[SafeStack Gate] Pre-commit security verification passed: OK"
exit 0
