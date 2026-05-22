#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)" || cd /home/test/Data/GOLANG_VSP
cp static/panels/sso_admin.html.bak.feat17 static/panels/sso_admin.html
