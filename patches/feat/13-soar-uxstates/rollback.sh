#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)" || cd /home/test/Data/GOLANG_VSP
cp static/panels/soar.html.bak.feat13 static/panels/soar.html
