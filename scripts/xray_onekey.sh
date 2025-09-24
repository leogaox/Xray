#!/usr/bin/env bash
set -euo pipefail

LOG_PREFIX="[xray-onekey]"

info() {
  echo "$LOG_PREFIX $*"
}

warn() {
  echo "$LOG_PREFIX WARN: $*" >&2
}

error() {
  echo "$LOG_PREFIX ERROR: $*" >&2
}

# Dry-run globals and helpers
DRY_RUN=0
XRAY_MOCK_DISTRO=""
XRAY_DRYRUN_FORCE_EXISTING=0
XRAY_DRYRUN_CONTEXT="manual"

SELFTEST_LAST_RESULT=""

declare -a DRY_PLAN=()
declare -a DRY_WARNINGS=()
declare -a DRY_PREVIEW_KEYS=()
declare -a DRY_PREVIEW_VALUES=()

dry_run_active() {
  [[ "$DRY_RUN" == "1" ]]
}

dry_bool_from_string() {
  local value=${1:-0}
  case "$value" in
    1|true|TRUE|yes|YES|on|ON)
      printf '1'
      ;;
    *)
      printf '0'
      ;;
  esac
}

reset_dry_context() {
  if ! dry_run_active; then
    return
  fi
  DRY_PLAN=()
  DRY_WARNINGS=()
  DRY_PREVIEW_KEYS=()
  DRY_PREVIEW_VALUES=()
}

dry_plan_action() {
  if ! dry_run_active; then
    return
  fi
  DRY_PLAN+=("$1")
}

dry_plan_skip() {
  if ! dry_run_active; then
    return
  fi
  DRY_PLAN+=("$1 (SKIPPED - DRY-RUN)")
}

dry_add_warning() {
  if ! dry_run_active; then
    warn "$1"
    return
  fi
  DRY_WARNINGS+=("$1")
  warn "$1"
}

dry_record_preview() {
  if ! dry_run_active; then
    return
  fi
  local name=$1
  local content=$2
  local i
  for i in "${!DRY_PREVIEW_KEYS[@]}"; do
    if [[ "${DRY_PREVIEW_KEYS[$i]}" == "$name" ]]; then
      DRY_PREVIEW_VALUES[i]="$content"
      return
    fi
  done
  DRY_PREVIEW_KEYS+=("$name")
  DRY_PREVIEW_VALUES+=("$content")
}

capitalize() {
  local input=$1
  if [[ -z "$input" ]]; then
    printf '%s' "$input"
    return
  fi
  local first=${input:0:1}
  local rest=${input:1}
  first=$(printf '%s' "$first" | tr '[:lower:]' '[:upper:]')
  printf '%s%s' "$first" "$rest"
}

printf_with_prefix() {
  local line
  while IFS= read -r line; do
    printf '%s %s\n' "$LOG_PREFIX" "$line"
  done
}

generate_socks_credentials() {
  if [[ -n "$SOCKS_USERNAME" && -n "$SOCKS_PASSWORD" ]]; then
    return 0  # User provided credentials, no generation needed
  fi

  if dry_run_active; then
    SOCKS_USERNAME="dryrun-user-$(dry_hash_from_seed "socks" | head -c 8)"
    SOCKS_PASSWORD="<redacted>"
    info "Dry-run: Would generate SOCKS5 credentials"
    return 0
  fi

  # Generate username: 8-12 characters [a-z0-9]
  SOCKS_USERNAME=$(openssl rand -base64 9 | tr -dc 'a-z0-9' | head -c $((8 + RANDOM % 5)))

  # Generate password: 16-24 characters with mixed case and numbers
  SOCKS_PASSWORD=$(openssl rand -base64 18 | tr -dc 'A-Za-z0-9' | head -c $((16 + RANDOM % 9)))

  info "Generated SOCKS5 credentials: username=${SOCKS_USERNAME}, password=<redacted>"
}

print_dry_report() {
  if ! dry_run_active; then
    return
  fi

  info "Dry-run action plan:"
  local idx=1
  local step
  for step in "${DRY_PLAN[@]}"; do
    printf '%s %2d. %s\n' "$LOG_PREFIX" "$idx" "$step"
    ((idx++))
  done

  if [[ ${#DRY_PREVIEW_KEYS[@]} -gt 0 ]]; then
    info "Configuration previews (sanitized):"
    local i name value
    for i in "${!DRY_PREVIEW_KEYS[@]}"; do
      name=${DRY_PREVIEW_KEYS[$i]}
      value=${DRY_PREVIEW_VALUES[i]}
      printf '%s --- %s ---\n' "$LOG_PREFIX" "$name"
      printf '%s\n' "$value" | printf_with_prefix
    done
  fi

  if [[ ${#DRY_WARNINGS[@]} -gt 0 ]]; then
    info "Dry-run warnings:"
    local w
    for w in "${DRY_WARNINGS[@]}"; do
      printf '%s   - %s\n' "$LOG_PREFIX" "$w"
    done
  fi
}

# Placeholder helpers used during dry-run rendering
dry_hash_from_seed() {
  local seed=$1
  local result=""
  local i char hex
  if [[ -z "$seed" ]]; then
    seed="dryrun"
  fi
  for ((i = 0; i < ${#seed}; i++)); do
    char=${seed:i:1}
    printf -v hex '%02x' "'${char}"
    result+="$hex"
  done
  while [[ ${#result} -lt 32 ]]; do
    result+="$result"
  done
  printf '%s' "${result:0:32}"
}

dry_placeholder_uuid() {
  local seed=$1
  local hash
  hash=$(dry_hash_from_seed "$seed")
  printf '%s-%s-%s-%s-%s\n' "${hash:0:8}" "${hash:8:4}" "${hash:12:4}" "${hash:16:4}" "${hash:20:12}"
}

dry_placeholder_short_id() {
  local seed=$1
  local hash
  hash=$(dry_hash_from_seed "$seed")
  printf '%s\n' "${hash:0:16}"
}

dry_placeholder_public_key() {
  local seed=$1
  local hash
  hash=$(dry_hash_from_seed "$seed")
  printf 'dryrun-public-%s\n' "${hash:0:22}"
}

CONFIG_DIR=${CONFIG_DIR:-/srv/docker/xray}
CONFIG_FILE=${CONFIG_FILE:-$CONFIG_DIR/config.json}
ENV_FILE=${ENV_FILE:-$CONFIG_DIR/reality.env}
XRAY_IMAGE=${XRAY_IMAGE:-ghcr.io/xtls/xray-core:latest}
CONTAINER_NAME=${CONTAINER_NAME:-xray-reality}
LISTEN_PORT_VLESS=${LISTEN_PORT_VLESS:-8443}
LISTEN_PORT_SOCKS=${LISTEN_PORT_SOCKS:-1080}
SOCKS_LISTEN_ADDR=${SOCKS_LISTEN_ADDR:-127.0.0.1}
SOCKS_USERNAME=${SOCKS_USERNAME:-}
SOCKS_PASSWORD=${SOCKS_PASSWORD:-}
XRAY_ENABLE_SOCKS=${XRAY_ENABLE_SOCKS:-1}
REALITY_DEST=${REALITY_DEST:-www.microsoft.com:443}
REALITY_SERVER_NAMES=${REALITY_SERVER_NAMES:-www.microsoft.com}
DNF_BIN=${DNF_BIN:-dnf}
SYSTEMCTL_BIN=${SYSTEMCTL_BIN:-systemctl}
IPTABLES_BIN=${IPTABLES_BIN:-iptables}
UUIDGEN_BIN=${UUIDGEN_BIN:-uuidgen}
DOCKER_BIN=${DOCKER_BIN:-docker}
CHRONY_SERVICE=${CHRONY_SERVICE:-chronyd}
APT_GET_BIN=${APT_GET_BIN:-apt-get}
OS_FAMILY=unknown
OS_DISTRO=unknown

# Backwards-compatible shorthand environment variables
if [[ -n "${SNI:-}" ]]; then
  REALITY_SERVER_NAMES=$SNI
fi
if [[ -n "${VLESS_PORT:-}" ]]; then
  LISTEN_PORT_VLESS=$VLESS_PORT
fi
if [[ -n "${SOCKS_PORT:-}" ]]; then
  LISTEN_PORT_SOCKS=$SOCKS_PORT
fi
if [[ -n "${UUID:-}" ]]; then
  XRAY_UUID=$UUID
fi
if [[ -n "${PRIVATE_KEY:-}" ]]; then
  XRAY_PRIVATE_KEY=$PRIVATE_KEY
fi
if [[ -n "${PUBLIC_KEY:-}" ]]; then
  XRAY_PUBLIC_KEY=$PUBLIC_KEY
fi
if [[ -n "${SHORT_ID:-}" ]]; then
  XRAY_SHORT_ID=$SHORT_ID
fi
if [[ -n "${SOCKS_ADDR:-}" ]]; then
  SOCKS_LISTEN_ADDR=$SOCKS_ADDR
fi

require_root() {
  if dry_run_active; then
    dry_plan_skip "Verify script is run as root"
    return
  fi

  if [[ "${SKIP_ROOT_CHECK:-0}" == "1" ]]; then
    return
  fi

  if [[ "$(id -u)" -ne 0 ]]; then
    error "This script must be run as root. Try again with sudo."
    exit 1
  fi
}

ensure_binary() {
  local name=$1
  local bin=$2
  if dry_run_active; then
    dry_plan_skip "Check requirement: ${name} (binary: ${bin})"
    return
  fi
  if ! command -v "$bin" >/dev/null 2>&1; then
    error "$name is required but was not found in PATH"
    exit 1
  fi
}

ensure_config_dir() {
  if dry_run_active; then
    dry_plan_action "Ensure configuration directory ${CONFIG_DIR} exists with mode 750"
    return
  fi
  mkdir -p "$CONFIG_DIR"
  chmod 750 "$CONFIG_DIR"
}

ensure_prereqs() {
  detect_os_family
  ensure_binary "openssl" openssl
  ensure_binary "uuidgen" "$UUIDGEN_BIN"

  if dry_run_active; then
    case "$OS_FAMILY" in
      rocky)
        dry_plan_skip "Install Docker packages via ${DNF_BIN}"
        dry_plan_skip "Enable docker service with systemctl"
        dry_plan_skip "Install and enable ${CHRONY_SERVICE} for time sync"
        dry_plan_action "Time sync guidance: inspect chronyc/timedatectl output (no changes)"
        ;;
      *)
        dry_plan_action "Manual prerequisite check for unknown distro"
        ;;
    esac
    return
  fi

  case "$OS_FAMILY" in
    rocky)
      ensure_prereqs_rocky
      ;;
    *)
      warn "未检测到受支持的包管理器，请手动确认 docker 与时间同步服务已安装。"
      if ! command -v "$DOCKER_BIN" >/dev/null 2>&1; then
        warn "Docker 未安装，脚本将继续但可能无法启动容器。"
      fi
      report_time_sync_status
      ;;
  esac
}

detect_os_family() {
  if dry_run_active && [[ -n "$XRAY_MOCK_DISTRO" ]]; then
    case "$XRAY_MOCK_DISTRO" in
      rocky)
        OS_FAMILY=rocky
        OS_DISTRO=rocky
        info "Dry-run: using mocked distro rocky"
        return
        ;;
      *)
        OS_FAMILY=unknown
        OS_DISTRO=$XRAY_MOCK_DISTRO
        warn "Dry-run: unknown mock distro ${XRAY_MOCK_DISTRO}, falling back to manual path"
        return
        ;;
    esac
  fi

  OS_DISTRO=unknown
  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_DISTRO=${ID:-unknown}
  fi

  if command -v "$DNF_BIN" >/dev/null 2>&1; then
    OS_FAMILY=rocky
  else
    OS_FAMILY=unknown
    warn "未适配的系统：请手动安装 Docker 与时间同步组件。"
  fi
}

ensure_prereqs_rocky() {
  ensure_binary "dnf" "$DNF_BIN"
  ensure_binary "systemctl" "$SYSTEMCTL_BIN"

  if ! command -v "$DOCKER_BIN" >/dev/null 2>&1; then
    info "Docker 未检测到，使用 $DNF_BIN 安装 docker 组件..."
    "$DNF_BIN" -y install dnf-plugins-core || warn "dnf-plugins-core 安装失败，可忽略。"
    "$DNF_BIN" config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo || warn "Docker CE 仓库可能已存在。"
    "$DNF_BIN" -y install docker-ce docker-ce-cli containerd.io docker-compose-plugin
  fi

  if ! "$SYSTEMCTL_BIN" enable --now docker >/dev/null 2>&1; then
    warn "无法自动启动 docker 服务，请手动确认。"
  fi

  ensure_chrony_rocky
  report_time_sync_status
}

ensure_chrony_rocky() {
  if ! command -v chronyc >/dev/null 2>&1; then
    info "安装 chrony 以保持时间同步..."
    "$DNF_BIN" -y install chrony || warn "chrony 安装失败，请手动检查时间同步。"
  fi

  if command -v "$SYSTEMCTL_BIN" >/dev/null 2>&1; then
    if ! "$SYSTEMCTL_BIN" enable --now "$CHRONY_SERVICE" >/dev/null 2>&1; then
      warn "无法启用 $CHRONY_SERVICE 服务，请手动确认时间同步。"
    fi
  fi
}


report_time_sync_status() {
  if dry_run_active; then
    dry_plan_skip "Inspect time synchronization via timedatectl / chronyc"
    return
  fi

  if command -v timedatectl >/dev/null 2>&1; then
    local ntp sync
    ntp=$(timedatectl show -p NTPSynchronized 2>/dev/null | cut -d'=' -f2)
    sync=$(timedatectl show -p SystemClockSynchronized 2>/dev/null | cut -d'=' -f2)
    info "timedatectl: NTPSynchronized=${ntp:-unknown} SystemClockSynchronized=${sync:-unknown}"
  fi

  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet systemd-timesyncd; then
      info "systemd-timesyncd: active"
    fi
    if systemctl is-active --quiet chronyd; then
      info "chronyd: active"
    elif systemctl is-active --quiet chrony; then
      info "chrony: active"
    fi
  fi

  if command -v chronyc >/dev/null 2>&1; then
    local tracking
    tracking=$(chronyc tracking 2>/dev/null | head -n 3)
    if [[ -n "$tracking" ]]; then
      info "chronyc tracking (前 3 行)："
      printf '%s\n' "$tracking" | sed 's/^/  /'
    fi
  fi
}

pull_xray_image() {
  if dry_run_active; then
    dry_plan_skip "Pull docker image ${XRAY_IMAGE}"
    return
  fi

  if [[ "${XRAY_SKIP_PULL:-0}" == "1" ]]; then
    return
  fi

  info "Pulling Xray image ${XRAY_IMAGE}..."
  "$DOCKER_BIN" pull "$XRAY_IMAGE"
}

server_names_json() {
  local IFS=','
  # shellcheck disable=SC2206
  local names=($REALITY_SERVER_NAMES)
  local trimmed=()
  local name

  for name in "${names[@]}"; do
    name=${name//[[:space:]]/}
    [[ -z "$name" ]] && continue
    trimmed+=("$name")
  done

  if [[ ${#trimmed[@]} -eq 0 ]]; then
    trimmed=("www.microsoft.com")
  fi

  local json="["
  for name in "${trimmed[@]}"; do
    json="$json\"$name\"," 
  done
  json="${json%,}"
  json="$json]"
  printf '%s' "$json"
}

load_identity_file() {
  if dry_run_active; then
    dry_plan_skip "Load existing identity from ${ENV_FILE}"
    return
  fi

  if [[ -f "$ENV_FILE" ]]; then
    # shellcheck disable=SC1090
    . "$ENV_FILE"
  fi
}

load_identity_dry_run() {
  local seed="$XRAY_DRYRUN_CONTEXT"
  if [[ "${XRAY_DRYRUN_FORCE_EXISTING:-0}" == "1" ]]; then
    dry_plan_action "Reuse existing identity from ${ENV_FILE} (simulated)"
  else
    dry_plan_action "Generate new identity (UUID, short ID, key pair) without touching disk"
  fi

  XRAY_UUID=${XRAY_UUID:-$(dry_placeholder_uuid "$seed")}
  XRAY_SHORT_ID=${XRAY_SHORT_ID:-$(dry_placeholder_short_id "$seed")}
  XRAY_PUBLIC_KEY=${XRAY_PUBLIC_KEY:-$(dry_placeholder_public_key "$seed")}
  XRAY_PRIVATE_KEY=${XRAY_PRIVATE_KEY:-"<dryrun-private-key>"}
}

persist_identity_env() {
  if dry_run_active; then
    local preview
    preview=$(cat <<EOF
XRAY_UUID=${XRAY_UUID}
XRAY_SHORT_ID=${XRAY_SHORT_ID}
XRAY_PRIVATE_KEY=<redacted>
XRAY_PUBLIC_KEY=${XRAY_PUBLIC_KEY}
EOF
)
    dry_plan_action "Render ${ENV_FILE} (no write in dry-run)"
    dry_record_preview "reality.env" "$preview"
    return
  fi

  umask 077
  cat >"$ENV_FILE" <<EOF
XRAY_UUID=$XRAY_UUID
XRAY_SHORT_ID=$XRAY_SHORT_ID
XRAY_PRIVATE_KEY=$XRAY_PRIVATE_KEY
XRAY_PUBLIC_KEY=$XRAY_PUBLIC_KEY
EOF
}

parse_key_output() {
  local output="$1"
  local _private_key=""
  local _public_key=""

  while IFS= read -r line; do
    # 解析 Private key（支持 Private key: 和 PrivateKey:）
    if [[ -z "$_private_key" ]]; then
      if [[ "$line" =~ ^[[:space:]]*[Pp][Rr][Ii][Vv][Aa][Tt][Ee][[:space:]]*[Kk][Ee][Yy][[:space:]]*[:=][[:space:]]*([^[:space:]]+) ]]; then
        _private_key="${BASH_REMATCH[1]}"
        continue
      elif [[ "$line" =~ ^[[:space:]]*[Pp][Rr][Ii][Vv][Aa][Tt][Ee][Kk][Ee][Yy][[:space:]]*[:=][[:space:]]*([^[:space:]]+) ]]; then
        _private_key="${BASH_REMATCH[1]}"
        continue
      fi
    fi

    # 解析 Public key（支持 Public key: 和 PublicKey:）
    if [[ -z "$_public_key" ]]; then
      if [[ "$line" =~ ^[[:space:]]*[Pp][Uu][Bb][Ll][Ii][Cc][[:space:]]*[Kk][Ee][Yy][[:space:]]*[:=][[:space:]]*([^[:space:]]+) ]]; then
        _public_key="${BASH_REMATCH[1]}"
        continue
      elif [[ "$line" =~ ^[[:space:]]*[Pp][Uu][Bb][Ll][Ii][Cc][Kk][Ee][Yy][[:space:]]*[:=][[:space:]]*([^[:space:]]+) ]]; then
        _public_key="${BASH_REMATCH[1]}"
        continue
      fi
    fi

    # 处理一行包含多个键值对的情况
    if [[ "$line" =~ ([Pp][Rr][Ii][Vv][Aa][Tt][Ee][[:space:]]*[Kk][Ee][Yy][[:space:]]*[:=][[:space:]]*[^[:space:]]+) ]]; then
      if [[ -z "$_private_key" ]]; then
        _private_key=$(echo "${BASH_REMATCH[1]}" | sed -E 's/^[^:=]*[:=][[:space:]]*//')
      fi
    fi
    if [[ "$line" =~ ([Pp][Rr][Ii][Vv][Aa][Tt][Ee][Kk][Ee][Yy][[:space:]]*[:=][[:space:]]*[^[:space:]]+) ]]; then
      if [[ -z "$_private_key" ]]; then
        _private_key=$(echo "${BASH_REMATCH[1]}" | sed -E 's/^[^:=]*[:=][[:space:]]*//')
      fi
    fi
    if [[ "$line" =~ ([Pp][Uu][Bb][Ll][Ii][Cc][[:space:]]*[Kk][Ee][Yy][[:space:]]*[:=][[:space:]]*[^[:space:]]+) ]]; then
      if [[ -z "$_public_key" ]]; then
        _public_key=$(echo "${BASH_REMATCH[1]}" | sed -E 's/^[^:=]*[:=][[:space:]]*//')
      fi
    fi
    if [[ "$line" =~ ([Pp][Uu][Bb][Ll][Ii][Cc][Kk][Ee][Yy][[:space:]]*[:=][[:space:]]*[^[:space:]]+) ]]; then
      if [[ -z "$_public_key" ]]; then
        _public_key=$(echo "${BASH_REMATCH[1]}" | sed -E 's/^[^:=]*[:=][[:space:]]*//')
      fi
    fi
  done <<< "$output"

  # 更新全局变量（仅在函数内部使用）
  if [[ -n "$_private_key" ]]; then
    private_key="$_private_key"
  fi
  if [[ -n "$_public_key" ]]; then
    public_key="$_public_key"
  fi
}

load_or_generate_identity() {
  if dry_run_active; then
    load_identity_dry_run
    persist_identity_env
    return
  fi

  if [[ -f "$ENV_FILE" ]]; then
    load_identity_file
    return
  fi

  XRAY_UUID=${XRAY_UUID:-$($UUIDGEN_BIN)}
  XRAY_SHORT_ID=${XRAY_SHORT_ID:-$(openssl rand -hex 8)}

  if [[ -z "${XRAY_PRIVATE_KEY:-}" || -z "${XRAY_PUBLIC_KEY:-}" ]]; then
    local all_attempts_output=""
    local private_key=""
    local public_key=""
    local attempt_output=""

    # 尝试 A：默认 entrypoint
    attempt_output=$("$DOCKER_BIN" run --rm "$XRAY_IMAGE" x25519 2>&1 || true)
    if [[ -n "$attempt_output" ]]; then
      all_attempts_output+="=== Attempt A (default entrypoint) ===\n$attempt_output\n"
      info "Attempt A (default entrypoint) output captured"
      parse_key_output "$attempt_output"
      if [[ -n "$private_key" && -n "$public_key" ]]; then
        info "Successfully obtained both keys from Attempt A"
      fi
    fi

    # 尝试 B：显式入口名为 xray
    if [[ -z "$private_key" || -z "$public_key" ]]; then
      attempt_output=$("$DOCKER_BIN" run --rm --entrypoint xray "$XRAY_IMAGE" x25519 2>&1 || true)
      if [[ -n "$attempt_output" ]]; then
        all_attempts_output+="=== Attempt B (explicit entrypoint) ===\n$attempt_output\n"
        info "Attempt B (explicit entrypoint) output captured"
        parse_key_output "$attempt_output"
        if [[ -n "$private_key" && -n "$public_key" ]]; then
          info "Successfully obtained both keys from Attempt B"
        fi
      fi
    fi

    # 尝试 C：备用镜像
    if [[ -z "$private_key" || -z "$public_key" ]]; then
      attempt_output=$("$DOCKER_BIN" run --rm teddysun/xray:1.8.23 xray x25519 2>&1 || true)
      if [[ -n "$attempt_output" ]]; then
        all_attempts_output+="=== Attempt C (fallback image) ===\n$attempt_output\n"
        info "Attempt C (fallback image) output captured"
        parse_key_output "$attempt_output"
        if [[ -n "$private_key" && -n "$public_key" ]]; then
          info "Successfully obtained both keys from Attempt C"
        fi
      fi
    fi

    # 尝试 D：私钥转公钥（如果只有私钥没有公钥）
    if [[ -n "$private_key" && -z "$public_key" ]]; then
      info "Private key found but public key missing, attempting derivation"

      # 尝试 D1：默认镜像私钥转公钥
      attempt_output=$("$DOCKER_BIN" run --rm "$XRAY_IMAGE" x25519 -i "$private_key" 2>&1 || true)
      if [[ -n "$attempt_output" ]]; then
        all_attempts_output+="=== Attempt D1 (private to public derivation) ===\n$attempt_output\n"
        info "Attempt D1 (private to public derivation) output captured"
        parse_key_output "$attempt_output"
        if [[ -n "$public_key" ]]; then
          info "Successfully derived public key from private key"
        fi
      fi

      # 尝试 D2：备用镜像私钥转公钥
      if [[ -z "$public_key" ]]; then
        attempt_output=$("$DOCKER_BIN" run --rm teddysun/xray:1.8.23 xray x25519 -i "$private_key" 2>&1 || true)
        if [[ -n "$attempt_output" ]]; then
          all_attempts_output+="=== Attempt D2 (fallback private to public) ===\n$attempt_output\n"
          info "Attempt D2 (fallback private to public) output captured"
          parse_key_output "$attempt_output"
          if [[ -n "$public_key" ]]; then
            info "Successfully derived public key from fallback image"
          fi
        fi
      fi
    fi

    # 仅在成功解析时设置变量
    if [[ -n "$private_key" ]]; then
      XRAY_PRIVATE_KEY=$private_key
    fi
    if [[ -n "$public_key" ]]; then
      XRAY_PUBLIC_KEY=$public_key
    fi

    if [[ -z "${XRAY_PRIVATE_KEY:-}" || -z "${XRAY_PUBLIC_KEY:-}" ]]; then
      error "Unable to determine Reality key pair."
      error "Raw output from all attempts:"
      printf_with_prefix <<<"$all_attempts_output"
      exit 1
    fi
  fi

  persist_identity_env
}

backup_config_if_exists() {
  if dry_run_active; then
    if [[ "${XRAY_DRYRUN_FORCE_EXISTING:-0}" == "1" || -f "$CONFIG_FILE" ]]; then
      local backup="${CONFIG_FILE}.bak.<timestamp>"
      dry_plan_action "Backup existing configuration to ${backup} (simulated)"
    fi
    return
  fi

  if [[ -f "$CONFIG_FILE" ]]; then
    local ts backup
    ts=$(date +%Y%m%d%H%M%S)
    backup="${CONFIG_FILE}.bak.${ts}"
    cp "$CONFIG_FILE" "$backup"
    info "已备份现有配置到 ${backup}."
  fi
}


generate_config_json() {
  local mode=${1:-actual}
  local private_value
  if [[ "$mode" == "preview" ]]; then
    private_value="<redacted>"
  else
    private_value=${XRAY_PRIVATE_KEY}
  fi

  # Build SOCKS5 configuration based on enable flag
  local socks_inbound=""

  if [[ "${XRAY_ENABLE_SOCKS:-1}" == "1" ]]; then
    # Validate SOCKS5 configuration
    if [[ "$SOCKS_LISTEN_ADDR" == "0.0.0.0" ]] && [[ -z "$SOCKS_USERNAME" || -z "$SOCKS_PASSWORD" ]]; then
      error "SOCKS5 cannot listen on 0.0.0.0 without authentication. Please set SOCKS_USERNAME and SOCKS_PASSWORD."
      exit 1
    fi

    # Build SOCKS5 settings - always use password auth when credentials exist
    local socks_auth="password"
    local socks_accounts=""

    if [[ -n "$SOCKS_USERNAME" && -n "$SOCKS_PASSWORD" ]]; then
      local password_value="$SOCKS_PASSWORD"
      if [[ "$mode" == "preview" ]]; then
        password_value="<redacted>"
      fi
      socks_accounts=",
          \"accounts\": [
            {
              \"user\": \"${SOCKS_USERNAME}\",
              \"pass\": \"${password_value}\"
            }
          ]"
    else
      # Generate credentials if not provided
      generate_socks_credentials
      local password_value="$SOCKS_PASSWORD"
      if [[ "$mode" == "preview" ]]; then
        password_value="<redacted>"
      fi
      socks_accounts=",
          \"accounts\": [
            {
              \"user\": \"${SOCKS_USERNAME}\",
              \"pass\": \"${password_value}\"
            }
          ]"
    fi

    socks_inbound=",
    {
      \"listen\": \"${SOCKS_LISTEN_ADDR}\",
      \"port\": ${LISTEN_PORT_SOCKS},
      \"protocol\": \"socks\",
      \"settings\": {
        \"auth\": \"${socks_auth}\"${socks_accounts},
        \"udp\": true,
        \"ip\": \"127.0.0.1\"
      }
    }"
  fi

  cat <<EOF
{
  "log": {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": ${LISTEN_PORT_VLESS},
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${XRAY_UUID}",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "dest": "${REALITY_DEST}",
          "serverNames": $(server_names_json),
          "privateKey": "${private_value}",
          "shortIds": [
            "${XRAY_SHORT_ID}"
          ],
          "maxTimeDiff": 0,
          "minClientVersion": "1.8.0"
        }
      }
    }${socks_inbound}
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "tag": "blocked"
    }
  ]
}
EOF
}

write_config() {
  if dry_run_active; then
    backup_config_if_exists
    local config_actual
    config_actual=$(generate_config_json actual)
    local config_preview
    config_preview=$(generate_config_json preview)
    local bytes=${#config_actual}
    dry_plan_action "Write ${CONFIG_FILE} (~${bytes} bytes)"
    dry_record_preview "config.json" "$config_preview"
    return
  fi

  backup_config_if_exists
  generate_config_json actual > "$CONFIG_FILE"
  chmod 640 "$CONFIG_FILE"
}

container_exists() {
  if dry_run_active; then
    dry_plan_skip "Inspect docker container ${CONTAINER_NAME} state"
    return 1
  fi
  local result
  result=$("$DOCKER_BIN" ps --all --filter "name=^/${CONTAINER_NAME}$" --format '{{.Names}}' | grep -Fx "$CONTAINER_NAME" || true)
  [[ -n "$result" ]]
}


stop_existing_container() {
  if dry_run_active; then
    dry_plan_skip "Remove existing container ${CONTAINER_NAME}"
    return
  fi
  if container_exists; then
    info "Removing existing container ${CONTAINER_NAME}..."
    "$DOCKER_BIN" rm -f "$CONTAINER_NAME" >/dev/null
  fi
}

start_container() {
  if dry_run_active; then
    stop_existing_container
    dry_plan_skip "Start container ${CONTAINER_NAME} from image ${XRAY_IMAGE} with ports ${LISTEN_PORT_VLESS}/${LISTEN_PORT_SOCKS}"
    return
  fi

  stop_existing_container

  # Build port mapping arguments
  local port_args="-p ${LISTEN_PORT_VLESS}:${LISTEN_PORT_VLESS}"

  # SOCKS port mapping based on listen address and enable flag
  if [[ "${XRAY_ENABLE_SOCKS:-1}" == "1" ]]; then
    if [[ "$SOCKS_LISTEN_ADDR" == "127.0.0.1" ]]; then
      port_args="$port_args -p 127.0.0.1:${LISTEN_PORT_SOCKS}:${LISTEN_PORT_SOCKS}"
    else
      port_args="$port_args -p ${LISTEN_PORT_SOCKS}:${LISTEN_PORT_SOCKS}"
    fi
  fi

  "$DOCKER_BIN" run -d     --name "$CONTAINER_NAME"     --restart unless-stopped     $port_args     -v "$CONFIG_FILE":/etc/xray/config.json:ro     --entrypoint /usr/local/bin/xray     --user "$(id -u):$(id -g)"     "$XRAY_IMAGE"     run -c /etc/xray/config.json >/dev/null
  info "Started container ${CONTAINER_NAME} using image ${XRAY_IMAGE}."
}

ensure_mss_clamp() {
  if [[ "${XRAY_DISABLE_MSS_CLAMP:-0}" == "1" ]]; then
    return
  fi

  if dry_run_active; then
    dry_plan_skip "Ensure iptables TCPMSS clamp rule present"
    return
  fi

  if ! command -v "$IPTABLES_BIN" >/dev/null 2>&1; then
    warn "iptables not available; skipping MSS clamp configuration."
    return
  fi

  if "$IPTABLES_BIN" -t mangle -C POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu >/dev/null 2>&1; then
    return
  fi

  if ! "$IPTABLES_BIN" -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu >/dev/null 2>&1; then
    warn "Failed to configure MSS clamp; continuing without it."
  else
    info "Applied MSS clamp rule via iptables."
  fi
}

print_firewall_hint() {
  if dry_run_active; then
    dry_plan_skip "Adjust firewalld to allow TCP 8443/1080"
    return
  fi

  info "防火墙放行示例（firewalld，可选）："
  info "  sudo firewall-cmd --permanent --add-port=8443/tcp"
  info "  sudo firewall-cmd --permanent --add-port=1080/tcp"
  info "  sudo firewall-cmd --reload"
}

listening_ports() {
  if dry_run_active; then
    dry_plan_skip "Inspect listening ports via ss/netstat"
    return 0
  fi

  if command -v ss >/dev/null 2>&1; then
    ss -tuln | grep -E ":(${LISTEN_PORT_VLESS}|${LISTEN_PORT_SOCKS})" || true
  elif command -v netstat >/dev/null 2>&1; then
    netstat -tuln | grep -E ":(${LISTEN_PORT_VLESS}|${LISTEN_PORT_SOCKS})" || true
  else
    warn "Neither ss nor netstat is available to verify listening ports."
    return 1
  fi
}

print_client_details() {
  if [[ -n "${XRAY_PUBLIC_KEY:-}" ]]; then
    info "Reality public key: ${XRAY_PUBLIC_KEY}"
  fi
  if [[ -n "${XRAY_SHORT_ID:-}" ]]; then
    info "Reality short ID: ${XRAY_SHORT_ID}"
  fi
  if [[ -n "${XRAY_UUID:-}" ]]; then
    info "Client UUID: ${XRAY_UUID}"
  fi
}

install_cmd() {
  if dry_run_active; then
    reset_dry_context
  fi

  require_root
  ensure_prereqs
  ensure_config_dir
  pull_xray_image
  load_or_generate_identity
  write_config
  ensure_mss_clamp
  start_container
  print_client_details

  # Display SOCKS5 status and credentials
  info "SOCKS5: listen=${SOCKS_LISTEN_ADDR}:${LISTEN_PORT_SOCKS}, auth=password"
  if [[ -n "$SOCKS_USERNAME" && -n "$SOCKS_PASSWORD" ]]; then
    if dry_run_active; then
      info "SOCKS5 credentials - Username: ${SOCKS_USERNAME}, Password: <redacted>"
    else
      info "SOCKS5 credentials - Username: ${SOCKS_USERNAME}, Password: ${SOCKS_PASSWORD}"
      info "Note: These credentials are displayed once and not saved to logs."
    fi
  fi

  info "Configuration saved to ${CONFIG_FILE}."
  print_firewall_hint

  if dry_run_active; then
    print_dry_report
  fi
}

status_cmd() {
  if dry_run_active; then
    reset_dry_context
    dry_plan_action "Inspect docker container ${CONTAINER_NAME} status"
    dry_plan_action "Inspect listeners for ports ${LISTEN_PORT_VLESS}/${LISTEN_PORT_SOCKS}"
    dry_plan_action "Summarize cached identity values"
    print_dry_report
    return
  fi

  require_root
  load_identity_file

  if ! container_exists; then
    warn "Container ${CONTAINER_NAME} is not running."
    exit 1
  fi

  local container_status
  container_status=$("$DOCKER_BIN" inspect -f '{{.State.Status}}' "$CONTAINER_NAME")
  info "Container ${CONTAINER_NAME} status: ${container_status}"

  local ports_output
  ports_output=$(listening_ports || true)
  if [[ -n "$ports_output" ]]; then
    info "Active listeners:"
    printf '%s\n' "$ports_output"
  else
    warn "Ports ${LISTEN_PORT_VLESS} and ${LISTEN_PORT_SOCKS} are not currently listening."
  fi

  # Display SOCKS5 status
  info "SOCKS5: ${SOCKS_LISTEN_ADDR}:${LISTEN_PORT_SOCKS} (auth=password)"

  print_client_details
}

uninstall_cmd() {
  if dry_run_active; then
    reset_dry_context
    dry_plan_skip "Remove docker container ${CONTAINER_NAME}"
    dry_plan_action "Configuration preserved at ${CONFIG_DIR}"
    print_dry_report
    return
  fi

  require_root

  if container_exists; then
    "$DOCKER_BIN" rm -f "$CONTAINER_NAME" >/dev/null
    info "Removed container ${CONTAINER_NAME}."
  else
    warn "Container ${CONTAINER_NAME} not found."
  fi

  info "Configuration preserved at ${CONFIG_DIR}."
}

purge_cmd() {
  if dry_run_active; then
    reset_dry_context
    dry_plan_skip "Remove docker container ${CONTAINER_NAME}"
    dry_plan_action "Delete configuration directory ${CONFIG_DIR}"
    dry_plan_action "Delete environment file ${ENV_FILE}"
    dry_plan_action "Delete configuration file ${CONFIG_FILE}"
    print_dry_report
    return
  fi

  require_root

  # Confirm with user before deleting configuration files
  info "WARNING: This will permanently delete all Xray configuration files and data."
  info "This action cannot be undone."

  # Skip confirmation if XRAY_PURGE_CONFIRM=1 is set
  if [[ "${XRAY_PURGE_CONFIRM:-0}" != "1" ]]; then
    local confirm
    read -p "Type 'PURGE' to confirm deletion: " confirm

    if [[ "$confirm" != "PURGE" ]]; then
      info "Purge cancelled. Configuration files preserved."
      return
    fi
  else
    info "Skipping confirmation (XRAY_PURGE_CONFIRM=1)"
  fi

  # Remove container first
  if container_exists; then
    "$DOCKER_BIN" rm -f "$CONTAINER_NAME" >/dev/null
    info "Removed container ${CONTAINER_NAME}."
  else
    warn "Container ${CONTAINER_NAME} not found."
  fi

  # Delete configuration files
  if [[ -f "$CONFIG_FILE" ]]; then
    rm -f "$CONFIG_FILE"
    info "Deleted configuration file ${CONFIG_FILE}."
  fi

  if [[ -f "$ENV_FILE" ]]; then
    rm -f "$ENV_FILE"
    info "Deleted environment file ${ENV_FILE}."
  fi

  # Delete config directory if empty
  if [[ -d "$CONFIG_DIR" ]]; then
    if [[ -z "$(ls -A "$CONFIG_DIR" 2>/dev/null)" ]]; then
      rmdir "$CONFIG_DIR" 2>/dev/null && info "Removed empty configuration directory ${CONFIG_DIR}."
    else
      info "Configuration directory ${CONFIG_DIR} contains other files and was not removed."
    fi
  fi

  info "Purge completed. All Xray configuration files have been deleted."
}


assess_dry_run_state() {
  local require_backup=${1:-0}
  local status="PASS"
  local notes=()
  local plan_steps=${#DRY_PLAN[@]}

  if [[ $plan_steps -eq 0 ]]; then
    status="WARN"
    notes+=("no-actions")
  fi

  local config_preview=""
  local env_preview=""
  local i key
  for i in "${!DRY_PREVIEW_KEYS[@]}"; do
    key=${DRY_PREVIEW_KEYS[$i]}
    case "$key" in
      config.json) config_preview=${DRY_PREVIEW_VALUES[i]} ;;
      reality.env) env_preview=${DRY_PREVIEW_VALUES[i]} ;;
    esac
  done

  if [[ -z "$config_preview" ]]; then
    status="WARN"
    notes+=("config-preview-missing")
  elif [[ $config_preview != *'"privateKey": "<redacted>"'* ]]; then
    status="WARN"
    notes+=("config-privateKey-not-redacted")
  fi

  if [[ -z "$env_preview" ]]; then
    status="WARN"
    notes+=("reality.env-preview-missing")
  elif [[ $env_preview != *'XRAY_PRIVATE_KEY=<redacted>'* ]]; then
    status="WARN"
    notes+=("env-privateKey-not-redacted")
  fi

  if [[ "$require_backup" == "1" ]]; then
    local found=0
    local step
    for step in "${DRY_PLAN[@]}"; do
      if [[ "$step" == *"config.json.bak"* ]]; then
        found=1
        break
      fi
    done
    if [[ $found -eq 0 ]]; then
      status="WARN"
      notes+=("missing-backup-step")
    fi
  fi

  local summary="plan_steps=${plan_steps}"
  if [[ ${#notes[@]} -gt 0 ]]; then
    summary+=";notes=$(IFS=','; echo "${notes[*]}")"
  fi
  printf '%s|%s
' "$status" "$summary"
}

run_selftest_for() {
  local scenario=$1
  local scenario_label
  scenario_label=$(capitalize "$scenario")
  XRAY_DRYRUN_CONTEXT=$scenario
  info "===== Self-test: ${scenario_label} (initial install) ====="
  XRAY_MOCK_DISTRO=$scenario
  XRAY_DRYRUN_FORCE_EXISTING=0
  reset_dry_context
  install_cmd
  local initial_result
  initial_result=$(assess_dry_run_state 0)

  info "===== Self-test: ${scenario_label} (repeat install) ====="
  XRAY_DRYRUN_FORCE_EXISTING=1
  reset_dry_context
  install_cmd
  local repeat_result
  repeat_result=$(assess_dry_run_state 1)

  local initial_status initial_summary repeat_status repeat_summary
  IFS='|' read -r initial_status initial_summary <<<"$initial_result"
  IFS='|' read -r repeat_status repeat_summary <<<"$repeat_result"

  local combined_status="PASS"
  if [[ "$initial_status" != "PASS" || "$repeat_status" != "PASS" ]]; then
    combined_status="WARN"
  fi

  info "Self-test summary for ${scenario_label}: initial=${initial_status} (${initial_summary}), repeat=${repeat_status} (${repeat_summary})"
  SELFTEST_LAST_RESULT="$scenario:$combined_status:initial=$initial_status repeat=$repeat_status"
}




selftest_cmd() {
  local previous_dry=$DRY_RUN
  local previous_mock=$XRAY_MOCK_DISTRO

  DRY_RUN=1

  local scenarios=(rocky ubuntu debian)
  local summary=()
  local final_status="PASS"
  local entry result scenario_status

  for entry in "${scenarios[@]}"; do
    SELFTEST_LAST_RESULT=""
    run_selftest_for "$entry"
    local result=${SELFTEST_LAST_RESULT}
    summary+=("$result")
    scenario_status=${result#*:}
    scenario_status=${scenario_status%%:*}
    if [[ "$scenario_status" != "PASS" ]]; then
      final_status="WARN"
    fi
  done

  info "===== Self-test Summary ====="
  for entry in "${summary[@]}"; do
    IFS=':' read -r scenario scenario_status rest <<<"$entry"
    local scenario_label
    scenario_label=$(capitalize "$scenario")
    info "  ${scenario_label}: ${scenario_status}"${rest:+" (${rest})"}
  done

  if [[ "$final_status" == "PASS" ]]; then
    info "Self-test verdict: PASS"
  else
    warn "Self-test verdict: NEEDS ATTENTION"
  fi

  DRY_RUN=$previous_dry
  XRAY_MOCK_DISTRO=$previous_mock
  }

show_usage() {
  cat <<'USAGE'
Usage: xray_onekey.sh [options] <install|status|uninstall|selftest>

Options:
  --dry-run              Render configuration and action plan without applying changes.
  --mock-distro <name>   Override OS detection (rocky|ubuntu|debian) in dry-run mode.
  -h, --help             Show this help message.

Commands:
  install    Install or upgrade the Xray VLESS Reality + SOCKS5 stack.
  status     Show container status and active listeners.
  uninstall  Remove the Xray container but keep configuration files.
  purge      Remove the Xray container and delete all configuration files.
  selftest   Run dry-run simulations across supported distros.
USAGE
}

ACTION=""
declare -a REMAINING_ARGS=()

parse_args() {
  local positional=()
  DRY_RUN=$(dry_bool_from_string "${XRAY_DRY_RUN:-0}")
  XRAY_MOCK_DISTRO=${XRAY_MOCK_DISTRO:-}
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dry-run)
        DRY_RUN=1
        shift
        ;;
      --dry-run=*)
        DRY_RUN=$(dry_bool_from_string "${1#*=}")
        shift
        ;;
      --mock-distro)
        if [[ $# -lt 2 ]]; then
          error "--mock-distro requires a value"
          exit 1
        fi
        XRAY_MOCK_DISTRO=$2
        shift 2
        ;;
      --mock-distro=*)
        XRAY_MOCK_DISTRO=${1#*=}
        shift
        ;;
      -h|--help)
        show_usage
        exit 0
        ;;
      --)
        shift
        positional+=("$@")
        break
        ;;
      *)
        positional+=("$1")
        shift
        ;;
    esac
  done

  set -- "${positional[@]}"
  ACTION=${1:-}
  if [[ $# -gt 0 ]]; then
    REMAINING_ARGS=()
    shift
    while [[ $# -gt 0 ]]; do
      REMAINING_ARGS+=("$1")
      shift
    done
  else
    REMAINING_ARGS=()
  fi
}

main() {
  parse_args "$@"

  case "$ACTION" in
    install)
      install_cmd "${REMAINING_ARGS[@]:-}"
      ;;
    status)
      status_cmd "${REMAINING_ARGS[@]:-}"
      ;;
    uninstall)
      uninstall_cmd "${REMAINING_ARGS[@]:-}"
      ;;
    purge)
      purge_cmd "${REMAINING_ARGS[@]:-}"
      ;;
    selftest)
      selftest_cmd
      ;;
    *)
      show_usage
      exit 1
      ;;
  esac
}

main "$@"
