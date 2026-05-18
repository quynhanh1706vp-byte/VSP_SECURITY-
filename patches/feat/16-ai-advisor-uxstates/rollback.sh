#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)" || cd /home/test/Data/GOLANG_VSP
cp static/panels/ai_advisor.html.bak.feat16 static/panels/ai_advisor.html
