# Load test orchestration.
# Run individual tests or `make all` to chain everything in CI.
#
# Override BASE_URL / VSP_TOKEN per environment:
#   make slo BASE_URL=https://staging.vsp.vn VSP_TOKEN=xxx

BASE_URL ?= http://localhost:8921
VSP_TOKEN ?=

.PHONY: all basic spike slo chaos summary clean

all: basic slo chaos summary

basic:
	@echo "── k6 basic load ──"
	k6 run -e BASE_URL=$(BASE_URL) k6_basic.js

spike:
	@echo "── k6 spike load ──"
	k6 run -e BASE_URL=$(BASE_URL) k6_spike.js

slo:
	@echo "── k6 SLO smoke ──"
	k6 run -e BASE_URL=$(BASE_URL) -e VSP_TOKEN=$(VSP_TOKEN) k6_slo.js

chaos:
	@echo "── k6 chaos / fault-injection ──"
	k6 run -e BASE_URL=$(BASE_URL) k6_chaos.js

summary:
	@echo ""
	@echo "All load tests completed. Check exit codes; thresholds defined"
	@echo "in each script (k6_slo.js declares the production SLOs)."

clean:
	rm -f k6_*.json k6_*.html
