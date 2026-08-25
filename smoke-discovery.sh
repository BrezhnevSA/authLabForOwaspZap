#!/usr/bin/env sh
set -eu

check() {
  name="$1"; url="$2"
  code=$(curl -sS -o /dev/null -w '%{http_code}' "$url" || true)
  printf '%-26s %s\n' "$name" "$code"
  [ "$code" = 200 ]
}

check large-bundle-spa http://127.0.0.1:8705/
check many-states-spa http://127.0.0.1:8706/
check runtime-discovery-spa http://127.0.0.1:8707/
check large-api-response http://127.0.0.1:8708/
check bft-regression-spa http://127.0.0.1:8709/app/
check scope-noise http://127.0.0.1:8710/
check complex-react-auth http://127.0.0.1:8711/app/

for port in 8705 8706 8707 8708 8709 8710 8711; do
  check "coverage-$port" "http://127.0.0.1:${port}/__testbed/coverage"
done

small=$(curl -fsS http://127.0.0.1:8705/assets/bundle-900k.js | wc -c | tr -d ' ')
over=$(curl -fsS http://127.0.0.1:8705/assets/bundle-1150k.js | wc -c | tr -d ' ')
api_over=$(curl -fsS 'http://127.0.0.1:8708/api/size/1150k?q=smoke' | wc -c | tr -d ' ')
printf 'bundle-900k bytes:  %s\n' "$small"
printf 'bundle-1150k bytes: %s\n' "$over"
printf 'api-1150k bytes:    %s\n' "$api_over"
[ "$small" -lt 1048576 ]
[ "$over" -gt 1048576 ]
[ "$api_over" -gt 1048576 ]

printf '\nDiscovery fixtures are reachable and the 1 MiB boundary is straddled as intended.\n'
