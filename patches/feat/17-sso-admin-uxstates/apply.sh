#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)" || cd /home/test/Data/GOLANG_VSP
python3 patches/feat/17-sso-admin-uxstates/17_patch.py
