#!/usr/bin/env bash
set -euo pipefail

URL=""
REPO=""
PROVIDER="openai"
API_KEY=""
BASE_URL=""
SMALL_MODEL=""
MEDIUM_MODEL=""
LARGE_MODEL=""
OUTBOUND_PROXY=""
OUTPUT=""
WORKSPACE=""
PIPELINE_TESTING="false"
DEBUG="false"
MONITOR="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --url) URL="$2"; shift 2 ;;
    --repo) REPO="$2"; shift 2 ;;
    --provider) PROVIDER="$2"; shift 2 ;;
    --api-key) API_KEY="$2"; shift 2 ;;
    --base-url) BASE_URL="$2"; shift 2 ;;
    --small-model) SMALL_MODEL="$2"; shift 2 ;;
    --medium-model) MEDIUM_MODEL="$2"; shift 2 ;;
    --large-model) LARGE_MODEL="$2"; shift 2 ;;
    --outbound-proxy) OUTBOUND_PROXY="$2"; shift 2 ;;
    --output) OUTPUT="$2"; shift 2 ;;
    --workspace) WORKSPACE="$2"; shift 2 ;;
    --pipeline-testing) PIPELINE_TESTING="true"; shift ;;
    --debug) DEBUG="true"; shift ;;
    --monitor) MONITOR="true"; shift ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

if [[ -z "$URL" || -z "$REPO" ]]; then
  echo "Usage: start-shannon-wsl.sh --url <target> --repo <repo-path> [--workspace name] [--monitor]" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is not available in WSL Ubuntu." >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "Docker is not running in WSL Ubuntu. Start dockerd inside Ubuntu and try again." >&2
  exit 1
fi

if ! command -v node.exe >/dev/null 2>&1; then
  if [[ -x /mnt/d/nodejs/node.exe ]]; then
    NODE_BIN="/mnt/d/nodejs/node.exe"
  else
    echo "Windows node.exe was not found at /mnt/d/nodejs/node.exe." >&2
    exit 1
  fi
else
  NODE_BIN="$(command -v node.exe)"
fi

if ! npm exec --yes pnpm@10.33.0 -- pnpm -v >/dev/null 2>&1; then
  echo "pnpm bootstrap failed." >&2
  exit 1
fi

npm exec --yes pnpm@10.33.0 -- pnpm install
npm exec --yes pnpm@10.33.0 -- pnpm build

args=("apps/cli/dist/index.mjs" "start" "-u" "$URL" "-r" "$REPO")
if [[ -n "$OUTPUT" ]]; then
  mkdir -p "$OUTPUT"
  args+=("-o" "$OUTPUT")
fi
if [[ -n "$WORKSPACE" ]]; then
  args+=("-w" "$WORKSPACE")
fi
if [[ "$PIPELINE_TESTING" == "true" ]]; then
  args+=("--pipeline-testing")
fi
if [[ "$DEBUG" == "true" ]]; then
  args+=("--debug")
fi

if [[ -n "$API_KEY" ]]; then export OPENAI_COMPAT_API_KEY="$API_KEY"; fi
if [[ -n "$BASE_URL" ]]; then export OPENAI_COMPAT_BASE_URL="$BASE_URL"; fi
if [[ -n "$SMALL_MODEL" ]]; then export OPENAI_COMPAT_SMALL_MODEL="$SMALL_MODEL"; fi
if [[ -n "$MEDIUM_MODEL" ]]; then export OPENAI_COMPAT_MEDIUM_MODEL="$MEDIUM_MODEL"; fi
if [[ -n "$LARGE_MODEL" ]]; then export OPENAI_COMPAT_LARGE_MODEL="$LARGE_MODEL"; fi
if [[ -n "$OUTBOUND_PROXY" ]]; then export OUTBOUND_PROXY="$OUTBOUND_PROXY"; fi
export SHANNON_AI_PROVIDER="$PROVIDER"

"$NODE_BIN" "${args[@]}"

if [[ "$MONITOR" == "true" ]]; then
  if [[ -z "$WORKSPACE" ]]; then
    echo "Monitor requires --workspace." >&2
    exit 0
  fi
  "$NODE_BIN" apps/cli/dist/index.mjs monitor "$WORKSPACE"
fi
