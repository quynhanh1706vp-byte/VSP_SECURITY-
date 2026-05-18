#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)" || cd /home/test/Data/GOLANG_VSP
cp static/panels/correlation.html.bak.feat12 static/panels/correlation.html
