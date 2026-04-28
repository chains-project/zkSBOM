#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ALL_TARGETS=(go npm mvn rust)
ALL_METRICS=(downloads dependent_repos_count docker_dependents_count docker_downloads_count)

TOTAL=""
PAGE_SIZE=""
TARGETS=("${ALL_TARGETS[@]}")
METRICS=("${ALL_METRICS[@]}")
JOBS=""
LOGS_DIR=""
SKIP_EXISTING=0

usage() {
  cat <<'EOF'
USAGE:
  ./run-analysis-server.sh --total <N> --page-size <N> [options]

OPTIONS:
  --targets <csv>       Comma-separated subset of: go,npm,mvn,rust
  --metrics <csv>       Comma-separated subset of:
                        downloads,dependent_repos_count,docker_dependents_count,docker_downloads_count
  --jobs <N>            Max concurrent jobs (default: all selected jobs)
  --logs-dir <path>     Output directory for logs and summary
                        (default: logs/<timestamp>-<total>)
  --skip-existing       Skip jobs whose log file already exists
  -h, --help            Show this help

EXAMPLES:
  ./run-analysis-server.sh --total 500 --page-size 100
  ./run-analysis-server.sh --total 2000 --page-size 100 --targets go,npm --jobs 2
  nohup ./run-analysis-server.sh --total 5000 --page-size 100 > server-run.out 2>&1 &
EOF
}

fail() {
  echo "error: $*" >&2
  exit 1
}

contains() {
  local needle="$1"
  shift
  local item
  for item in "$@"; do
    [[ "${item}" == "${needle}" ]] && return 0
  done
  return 1
}

parse_csv_list() {
  local raw="$1"
  local -n output_ref="$2"
  local -n allowed_ref="$3"
  local parsed=()
  local item

  IFS=',' read -r -a parsed <<<"${raw}"
  [[ "${#parsed[@]}" -gt 0 ]] || fail "empty CSV list"

  output_ref=()
  for item in "${parsed[@]}"; do
    [[ -n "${item}" ]] || fail "empty value in CSV list '${raw}'"
    contains "${item}" "${allowed_ref[@]}" || fail "unsupported value '${item}'"
    output_ref+=("${item}")
  done
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --total)
      TOTAL="${2:-}"
      shift 2
      ;;
    --page-size)
      PAGE_SIZE="${2:-}"
      shift 2
      ;;
    --targets)
      parse_csv_list "${2:-}" TARGETS ALL_TARGETS
      shift 2
      ;;
    --metrics)
      parse_csv_list "${2:-}" METRICS ALL_METRICS
      shift 2
      ;;
    --jobs)
      JOBS="${2:-}"
      shift 2
      ;;
    --logs-dir)
      LOGS_DIR="${2:-}"
      shift 2
      ;;
    --skip-existing)
      SKIP_EXISTING=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument '$1'"
      ;;
  esac
done

[[ -n "${TOTAL}" ]] || fail "--total is required"
[[ -n "${PAGE_SIZE}" ]] || fail "--page-size is required"
[[ "${TOTAL}" =~ ^[0-9]+$ ]] || fail "--total must be a positive integer"
[[ "${PAGE_SIZE}" =~ ^[0-9]+$ ]] || fail "--page-size must be a positive integer"
(( TOTAL > 0 )) || fail "--total must be > 0"
(( PAGE_SIZE > 0 )) || fail "--page-size must be > 0"

if [[ -z "${JOBS}" ]]; then
  JOBS=$((${#TARGETS[@]} * ${#METRICS[@]}))
fi

[[ "${JOBS}" =~ ^[1-9][0-9]*$ ]] || fail "--jobs must be a positive integer"

TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
LOGS_DIR="${LOGS_DIR:-${ROOT_DIR}/logs/${TIMESTAMP}-${TOTAL}}"
WORKSPACES_DIR="${ROOT_DIR}/logs/workspaces"
mkdir -p "${LOGS_DIR}"
mkdir -p "${WORKSPACES_DIR}"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command '$1'"
}

require_cmd bash
require_cmd curl
require_cmd jq
require_cmd bc
require_cmd timeout

for target in "${TARGETS[@]}"; do
  [[ -x "${ROOT_DIR}/${target}/pipeline.sh" ]] || fail "missing executable ${target}/pipeline.sh"
  case "${target}" in
    go)
      require_cmd go
      ;;
    npm)
      require_cmd node
      require_cmd npm
      ;;
    mvn)
      require_cmd mvn
      ;;
    rust)
      require_cmd rustc
      require_cmd cargo
      ;;
  esac
done

summarize_logs() {
  local summary_path="${LOGS_DIR}/summary.md"
  local metric
  local target
  local log_file
  local value

  {
    echo "# Dependency Tree Analysis Summary"
    echo ""
    echo "total=${TOTAL}"
    echo "page_size=${PAGE_SIZE}"
    echo "targets=$(IFS=,; echo "${TARGETS[*]}")"
    echo "metrics=$(IFS=,; echo "${METRICS[*]}")"
    echo ""
    echo "## Transitive Dependency Metric"
    echo ""
    echo "| metric | go | npm | mvn | rust |"
    echo "| :--- | :---: | :---: | :---: | :---: |"

    for metric in "${ALL_METRICS[@]}"; do
      printf '| `%s` |' "${metric}"
      for target in "${ALL_TARGETS[@]}"; do
        log_file="${LOGS_DIR}/${target}-${metric}-${TOTAL}.log"
        if [[ -f "${log_file}" ]]; then
          value="$(grep '^avg # deps' "${log_file}" | head -1 | sed 's/^avg # deps : //')"
          printf ' %s |' "${value:--}"
        else
          printf ' - |'
        fi
      done
      echo
    done

    echo ""
    echo "## Peer Dependency Metric"
    echo ""
    echo "| metric | go | npm | mvn | rust |"
    echo "| :--- | :---: | :---: | :---: | :---: |"

    for metric in "${ALL_METRICS[@]}"; do
      printf '| `%s` |' "${metric}"
      for target in "${ALL_TARGETS[@]}"; do
        log_file="${LOGS_DIR}/${target}-${metric}-${TOTAL}.log"
        if [[ ! -f "${log_file}" ]]; then
          printf ' - |'
        elif [[ "${target}" == 'npm' || "${target}" == 'mvn' ]]; then
          value="$(grep '^avg # peers' "${log_file}" | head -1 | sed 's/^avg # peers: //')"
          printf ' %s |' "${value:--}"
        else
          printf ' - |'
        fi
      done
      echo
    done
  } >"${summary_path}"

  echo "Summary written to ${summary_path}"
}

run_job() {
  local target="$1"
  local metric="$2"
  local log_file="${LOGS_DIR}/${target}-${metric}-${TOTAL}.log"
  local status_file="${log_file}.status"
  local workspace_dir="${WORKSPACES_DIR}/${target}-${metric}"

  if [[ "${SKIP_EXISTING}" -eq 1 && -f "${log_file}" ]]; then
    echo "[skip] ${target}/${metric} -> ${log_file}"
    return 0
  fi

  echo "[start] ${target}/${metric}"
  mkdir -p "${workspace_dir}"
  cp -R "${ROOT_DIR}/${target}/." "${workspace_dir}/"
  (
    cd "${workspace_dir}"
    export RUSTUP_HOME="${RUSTUP_HOME:-${HOME}/.rustup}"
    _orig_cargo_home="${CARGO_HOME:-${HOME}/.cargo}"
    export HOME="${workspace_dir}/home"
    export XDG_CACHE_HOME="${workspace_dir}/home/.cache"
    export npm_config_cache="${workspace_dir}/home/.npm"
    export CARGO_HOME="${workspace_dir}/home/.cargo"
    export PATH="${_orig_cargo_home}/bin:${PATH}"
    export GOPATH="${workspace_dir}/home/go"
    export GOMODCACHE="${workspace_dir}/home/go/pkg/mod"
    mkdir -p "${HOME}" "${XDG_CACHE_HOME}"
    ./pipeline.sh "${TOTAL}" "${PAGE_SIZE}" "${metric}" clean
  ) | tee "${log_file}"
  local pipeline_status=${PIPESTATUS[0]}

  if [[ ${pipeline_status} -eq 0 ]]; then
    echo "ok" >"${status_file}"
    echo "[done] ${target}/${metric}"
  else
    echo "failed:${pipeline_status}" >"${status_file}"
    echo "[fail] ${target}/${metric} (exit ${pipeline_status})" >&2
  fi

  return "${pipeline_status}"
}

declare -a active_pids=()
declare -A pid_to_name=()
had_failure=0

wait_for_one() {
  local finished_pid
  local wait_status
  local remaining=()
  local pid
  local name

  if wait -n -p finished_pid; then
    wait_status=0
  else
    wait_status=$?
  fi
  name="${pid_to_name[${finished_pid}]}"

  if [[ ${wait_status} -eq 0 ]]; then
    echo "[ok] ${name}"
  else
    echo "[error] ${name}" >&2
    had_failure=1
  fi

  unset 'pid_to_name[$finished_pid]'
  for pid in "${active_pids[@]}"; do
    [[ "${pid}" != "${finished_pid}" ]] && remaining+=("${pid}")
  done
  active_pids=("${remaining[@]}")
}

echo "Running analysis in ${ROOT_DIR}"
echo "Logs directory: ${LOGS_DIR}"
echo "Targets: $(IFS=,; echo "${TARGETS[*]}")"
echo "Metrics: $(IFS=,; echo "${METRICS[*]}")"
echo "Parallel jobs: ${JOBS}"
echo ""

for target in "${TARGETS[@]}"; do
  for metric in "${METRICS[@]}"; do
    while [[ "${#active_pids[@]}" -ge "${JOBS}" ]]; do
      wait_for_one
    done

    run_job "${target}" "${metric}" &
    active_pids+=("$!")
    pid_to_name[$!]="${target}/${metric}"
  done
done

while [[ "${#active_pids[@]}" -gt 0 ]]; do
  wait_for_one
done

summarize_logs

if [[ "${had_failure}" -ne 0 ]]; then
  echo "One or more jobs failed. Inspect logs in ${LOGS_DIR}" >&2
  exit 1
fi

echo "All jobs completed successfully."
