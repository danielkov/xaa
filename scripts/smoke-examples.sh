#!/usr/bin/env bash
# Closed-loop smoke test for the three example binaries (RFC-001 §9).
#
# Builds `xaa-idp`, `xaa-resource-as` and `xaa-client`, starts the two servers
# on free loopback ports, and runs the client through the whole Cross App
# Access flow twice: once with bearer tokens and once with `--dpop`. Fails if
# either run fails or does not print the user's todos. The servers are always
# stopped on exit, and their logs are printed if anything went wrong.
#
# Needs only bash, cargo and curl. CI runs it in the `examples` job.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

work_dir="$(mktemp -d)"
pids=()

cleanup() {
  status=$?
  for pid in "${pids[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  if [ "$status" -ne 0 ]; then
    for log in "$work_dir"/*.log; do
      [ -e "$log" ] || continue
      echo "--- $(basename "$log") ---" >&2
      cat "$log" >&2
    done
    echo "smoke-examples: FAILED" >&2
  fi
  rm -rf "$work_dir"
  exit "$status"
}
trap cleanup EXIT

fail() {
  echo "smoke-examples: $*" >&2
  exit 1
}

# A loopback port nothing is listening on. There is a small window between
# this check and the server binding the port; a collision fails the readiness
# check below rather than passing by accident.
free_port() {
  local port
  for _ in $(seq 1 50); do
    port=$((20000 + RANDOM % 20000))
    if ! (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
      echo "$port"
      return 0
    fi
  done
  return 1
}

# Wait until `url` answers 200 and the server process is still ours.
wait_ready() {
  local name="$1" pid="$2" url="$3"
  for _ in $(seq 1 100); do
    kill -0 "$pid" 2>/dev/null || fail "$name exited during startup"
    if curl --silent --fail --output /dev/null --max-time 2 "$url"; then
      return 0
    fi
    sleep 0.1
  done
  fail "$name did not become ready at $url"
}

# Run the client, show its output, and check that it printed the todos.
run_client() {
  local label="$1" token_type="$2" output
  shift 2
  echo "== client ($label) =="
  output="$("$bin_dir/xaa-client" "$@" 2>&1)" || {
    echo "$output"
    fail "client ($label) exited with an error"
  }
  echo "$output"
  grep -q "token_type: $token_type" <<<"$output" ||
    fail "client ($label) did not get a $token_type access token"
  grep -q '"owner": "alice"' <<<"$output" ||
    fail "client ($label) did not print alice's todos"
  grep -q 'Review the ID-JAG draft' <<<"$output" ||
    fail "client ($label) did not print the expected todo"
}

echo "== build =="
cargo build -p xaa-idp -p xaa-resource-as -p xaa-client
bin_dir="${CARGO_TARGET_DIR:-$repo_root/target}/debug"

idp_port="$(free_port)" || fail "no free port for the IdP"
ras_port="$(free_port)" || fail "no free port for the Resource AS"
[ "$idp_port" != "$ras_port" ] || fail "picked the same port twice; run again"

export XAA_IDP_PORT="$idp_port"
export XAA_IDP_ISSUER="http://127.0.0.1:$idp_port"
export XAA_RESOURCE_AS_PORT="$ras_port"
export XAA_RESOURCE_AS_ISSUER="http://127.0.0.1:$ras_port"
export XAA_RESOURCE="http://127.0.0.1:$ras_port/"

echo "== start =="
"$bin_dir/xaa-idp" >"$work_dir/idp.log" 2>&1 &
idp_pid=$!
pids+=("$idp_pid")
"$bin_dir/xaa-resource-as" >"$work_dir/resource-as.log" 2>&1 &
ras_pid=$!
pids+=("$ras_pid")

wait_ready "xaa-idp" "$idp_pid" "$XAA_IDP_ISSUER/.well-known/openid-configuration"
wait_ready "xaa-resource-as" "$ras_pid" \
  "$XAA_RESOURCE_AS_ISSUER/.well-known/oauth-authorization-server"
echo "IdP at $XAA_IDP_ISSUER, Resource AS at $XAA_RESOURCE_AS_ISSUER"

# The API must refuse a request without a token, or the runs below prove
# nothing.
status="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 5 \
  "${XAA_RESOURCE}api/todos")"
[ "$status" = "401" ] || fail "the todo API answered $status without a token, expected 401"

run_client "bearer" "Bearer"
run_client "dpop" "DPoP" --dpop

echo "smoke-examples: OK"
