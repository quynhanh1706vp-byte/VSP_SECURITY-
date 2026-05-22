#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)" || cd /home/test/Data/GOLANG_VSP
python3 patches/feat/15-conmon-uxstates/15_patch.py
