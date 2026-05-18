#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)" || cd /home/test/Data/GOLANG_VSP
cp static/panels/conmon.html.bak.feat15 static/panels/conmon.html
