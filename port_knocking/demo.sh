#!/usr/bin/env bash

set -euo pipefail

TARGET_IP=${1:-localhost}
SEQUENCE=${2:-"3474,5678,9012"}
PROTECTED_PORT=${3:-2222}

echo "[1/3] Attempting protected port before knocking"
nc -z -v "$TARGET_IP" "$PROTECTED_PORT" || true

echo "[2/3] Sending knock sequence: $SEQUENCE"
python3 knock_client.py --target "$TARGET_IP" --sequence "$SEQUENCE" --check

echo "[3/3] Attempting protected port after knocking"
nc -z -v "$TARGET_IP" "$PROTECTED_PORT" || true

