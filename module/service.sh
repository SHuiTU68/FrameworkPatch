#!/system/bin/sh
# service.sh - FKTee-rs late_start service
# 参考 OMK 的 start_daemon 模式：pid_matches_script 验证存活，
# restart 文件机制触发重启。
#
# 两种模式（互斥）：
#   1. HAL 模式（/data/adb/Tee-rs/hal.enabled 存在）：
#      vintf 重写真 HAL → fktee-real，fktee-hal 抢注 default。
#      inject 路径不启动。
#   2. inject 模式（默认）：启动 fktee backend + injector。
#
# 两种模式都应用 props.conf / usb.conf，响应 restart 信号。

MODDIR=${0%/*}
TEERS_DIR=/data/adb/Tee-rs
ARCH=$(getprop ro.product.cpu.abi)
HAL_BIN="$MODDIR/libs/$ARCH/fktee-hal"
PID_FKTEE="$TEERS_DIR/data/fktee.pid"
PID_INJECTOR="$TEERS_DIR/data/injector.pid"
PID_HAL="$TEERS_DIR/data/hal.pid"
HAL_ENABLED=0
[ -f "$TEERS_DIR/hal.enabled" ] && HAL_ENABLED=1

mkdir -p "$TEERS_DIR" "$TEERS_DIR/data" "$TEERS_DIR/logs"

# ---------- pid_matches_script (参考 OMK) ----------
# 检查 pid 对应的 cmdline 是否包含 script 名，避免 pid 复用误判。
# 注意：部分 Android 版本的 cmdline 只显示 "sh" 不包含脚本路径，
# 因此放宽检查：如果 cmdline 不可读或脚本名（basename）匹配则通过。
pid_matches_script() {
  pid=$1
  script=$2
  [ -r "/proc/$pid/cmdline" ] || return 1
  cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)
  # 先查完整路径，再查 basename（兼容 cmdline 只显示 "sh" 的情况）
  echo "$cmdline" | grep -F "$script" >/dev/null 2>&1 && return 0
  # 如果 cmdline 中不含完整路径，用 basename 宽松匹配
  local base=$(basename "$script" 2>/dev/null)
  [ -n "$base" ] && echo "$cmdline" | grep -F "$base" >/dev/null 2>&1
}

# ---------- start_daemon (参考 OMK) ----------
# 启动一个 daemon 脚本并记录 pid。若 pidfile 指向的进程仍存活且 cmdline
# 匹配则不重启。启动后 sleep 1 验证存活。
start_daemon() {
  script=$1
  pidfile=$2

  if [ -f "$pidfile" ]; then
    pid=$(cat "$pidfile" 2>/dev/null)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && pid_matches_script "$pid" "$script"; then
      return 0
    fi
    rm -f "$pidfile"
  fi

  sh "$script" &
  pid=$!
  echo $pid > "$pidfile"
  sleep 1
  if ! kill -0 "$pid" 2>/dev/null || ! pid_matches_script "$pid" "$script"; then
    rm -f "$pidfile"
    return 1
  fi
  return 0
}

# ---------- kill_pidfile ----------
kill_pidfile() {
  pid=$(cat "$1" 2>/dev/null)
  [ -n "$pid" ] && kill "$pid" 2>/dev/null
  rm -f "$1"
}

# ---------- Prop hiding (resetprop, config-driven) ----------
# 读取 props.conf，支持 key=value / key~match=value / once:key=value
# once: 条目仅开机执行一次（避免持续压回值导致系统异常）
apply_props() {
  local conf="$TEERS_DIR/props.conf"
  [ -f "$conf" ] || return 0
  command -v resetprop >/dev/null 2>&1 || return 0
  local mode="${1:-all}"

  local enabled=1
  while IFS= read -r line; do
    case "$line" in ''|\#*) continue;; esac
    [ "${line%%=*}" = "enabled" ] && { enabled=${line#*=}; break; }
  done < "$conf"
  [ "$enabled" = "1" ] || return 0

  local spec key val match cur is_once
  while IFS= read -r line; do
    case "$line" in ''|\#*|enabled=*) continue;; esac
    spec=${line%%=*}; val=${line#*=}
    is_once=0
    case "$spec" in
      once:*) is_once=1; spec=${spec#once:};;
    esac
    case "$mode:$is_once" in
      once:0) continue;;
      loop:1) continue;;
    esac
    case "$spec" in
      *~*)
        key=${spec%%~*}; match=${spec#*~}
        cur=$(getprop "$key" 2>/dev/null)
        case "$cur" in
          *"$match"*)
            resetprop --delete "$key" 2>/dev/null
            resetprop "$key" "$val" 2>/dev/null
            ;;
        esac
        ;;
      *)
        resetprop --delete "$spec" 2>/dev/null
        resetprop "$spec" "$val" 2>/dev/null
        ;;
    esac
  done < "$conf"
}

# ---------- USB 调试开关 ----------
apply_usb() {
  local conf="$TEERS_DIR/usb.conf"
  [ -f "$conf" ] || return 0
  local adb=1
  while IFS= read -r line; do
    case "$line" in ''|\#*) continue;; esac
    [ "${line%%=*}" = "adb_enabled" ] && { adb=${line#*=}; break; }
  done < "$conf"
  command -v settings >/dev/null 2>&1 && settings put global adb_enabled "$adb" 2>/dev/null
}

# ---------- HAL 模式：vintf 重写（late_start 阶段执行）----------
# 把真 HAL 的 default 实例改名为 fktee-real，让 fktee-hal 抢注 default。
# 在 service.sh（late_start）执行而非 post-fs-data，因 SELinux 此时已就绪。
# 用 mount --bind 覆盖 vintf manifest（vendor 分区只读，bind mount 不需要写权限）。
rewrite_vintf_for_hal() {
  [ "$HAL_ENABLED" = "1" ] || return 0
  [ -f "$TEERS_DIR/data/hal.vintf-rewritten" ] && return 0

  local real_instance="fktee-real"
  local changed=0
  local f manifests=""

  for d in /vendor/etc/vintf /odm/etc/vintf; do
    [ -d "$d" ] || continue
    [ -f "$d/manifest.xml" ] && manifests="$manifests $d/manifest.xml"
    if [ -d "$d/manifest" ]; then
      for f in "$d"/manifest/*.xml; do
        [ -f "$f" ] && manifests="$manifests $f"
      done
    fi
  done

  mkdir -p "$TEERS_DIR/data/vintf-overlay"
  for f in $manifests; do
    grep -q "android.hardware.security.keymint" "$f" 2>/dev/null || continue
    local base=$(echo "$f" | tr '/' '_')
    local tmp="$TEERS_DIR/data/vintf-overlay/$base"
    if sed -E "s|IKeyMintDevice/[^<\"[:space:]]+|IKeyMintDevice/${real_instance}|g" "$f" > "$tmp" 2>/dev/null; then
      if mount --bind "$tmp" "$f" 2>/dev/null; then
        changed=1
        echo "[fktee-hal] vintf bind-mounted: $f" >>"$TEERS_DIR/logs/hal.log"
      else
        echo "[fktee-hal] bind mount 失败: $f" >>"$TEERS_DIR/logs/hal.log"
      fi
    fi
  done

  [ "$changed" = "1" ] && touch "$TEERS_DIR/data/hal.vintf-rewritten"
}

# ---------- HAL 模式：启动 fktee-hal ----------
start_hal() {
  if [ ! -x "$HAL_BIN" ]; then
    echo "[fktee-hal] 二进制不存在: $HAL_BIN" >>"$TEERS_DIR/logs/hal.log"
    return 1
  fi
  rewrite_vintf_for_hal
  if [ ! -f "$TEERS_DIR/data/hal.vintf-rewritten" ]; then
    echo "[fktee-hal] 警告: vintf 未重写，真 HAL 可能仍占 default" >>"$TEERS_DIR/logs/hal.log"
  fi
  nohup "$HAL_BIN" >>"$TEERS_DIR/logs/hal.log" 2>&1 &
  echo $! > "$PID_HAL"
  echo "[fktee-hal] started pid=$(cat $PID_HAL)" >>"$TEERS_DIR/logs/hal.log"
}

# ---------- 等待 boot completed（带超时，避免死循环）----------
# 不用 while+sleep 死等，改为最多等 60s 后继续（即使 boot_completed 异常
# 也不应卡死 service.sh 导致其他服务无法启动）。
wait_boot() {
  local i=0
  while [ "$(getprop sys.boot_completed)" != "1" ] && [ "$i" -lt 60 ]; do
    sleep 1
    i=$((i + 1))
  done
}

wait_boot
sleep 2

# ---------- 开机应用 props + usb ----------
apply_props all
apply_usb

# ---------- 启动模式选择 ----------
if [ "$HAL_ENABLED" = "1" ]; then
  echo "[fktee] HAL 模式启用，启动 fktee-hal" >>"$TEERS_DIR/logs/hal.log"
  start_hal
else
  echo "[fktee] inject 模式（默认），启动 daemon + daemon-injector"
  start_daemon "$MODDIR/daemon" "$PID_FKTEE"
  start_daemon "$MODDIR/daemon-injector" "$PID_INJECTOR"
fi

# ---------- 检查守护进程是否存活 ----------
is_daemon_alive() {
  local pidfile=$1
  [ -f "$pidfile" ] || return 1
  local pid=$(cat "$pidfile" 2>/dev/null)
  [ -n "$pid" ] || return 1
  kill -0 "$pid" 2>/dev/null || return 1
  # 不检查 pid_matches_script（cmdline 可能不含完整路径），
  # 只靠 pidfile 和 kill -0 判断，简单可靠。
  return 0
}

# ---------- 主循环：restart 信号 + daemon 存活监控 + props 变更检测 ----------
# props 不再每 5s 全量重应用（耗 CPU），改为检测 props.conf mtime 变更时重应用。
PROPS_MTIME=0
check_props_change() {
  local conf="$TEERS_DIR/props.conf"
  [ -f "$conf" ] || return 1
  local mtime=$(stat -c %Y "$conf" 2>/dev/null || echo 0)
  if [ "$mtime" != "$PROPS_MTIME" ]; then
    PROPS_MTIME=$mtime
    return 0
  fi
  return 1
}

while true; do
  if [ -f "$TEERS_DIR/restart.all" ]; then
    rm -f "$TEERS_DIR/restart.all"
    kill_pidfile "$PID_FKTEE"
    kill_pidfile "$PID_INJECTOR"
    kill_pidfile "$PID_HAL"
    if [ "$HAL_ENABLED" = "1" ]; then
      start_hal
    else
      start_daemon "$MODDIR/daemon" "$PID_FKTEE"
      start_daemon "$MODDIR/daemon-injector" "$PID_INJECTOR"
    fi
  fi

  if [ -f "$TEERS_DIR/restart.fktee" ]; then
    rm -f "$TEERS_DIR/restart.fktee"
    kill_pidfile "$PID_FKTEE"
    [ "$HAL_ENABLED" != "1" ] && start_daemon "$MODDIR/daemon" "$PID_FKTEE"
  fi

  if [ -f "$TEERS_DIR/restart.injector" ]; then
    rm -f "$TEERS_DIR/restart.injector"
    kill_pidfile "$PID_INJECTOR"
    [ "$HAL_ENABLED" != "1" ] && start_daemon "$MODDIR/daemon-injector" "$PID_INJECTOR"
  fi

  if [ -f "$TEERS_DIR/restart.hal" ]; then
    rm -f "$TEERS_DIR/restart.hal"
    kill_pidfile "$PID_HAL"
    [ "$HAL_ENABLED" = "1" ] && start_hal
  fi

  # ---------- daemon 存活监控（崩溃后自动重启）----------
  if [ "$HAL_ENABLED" != "1" ]; then
    if ! is_daemon_alive "$PID_FKTEE"; then
      echo "[fktee] daemon 未运行，自动重启" >>"$TEERS_DIR/logs/fktee.log" 2>/dev/null
      start_daemon "$MODDIR/daemon" "$PID_FKTEE"
    fi
    if ! is_daemon_alive "$PID_INJECTOR"; then
      echo "[fktee] injector daemon 未运行，自动重启" >>"$TEERS_DIR/logs/injector.log" 2>/dev/null
      start_daemon "$MODDIR/daemon-injector" "$PID_INJECTOR"
    fi
  else
    if ! is_daemon_alive "$PID_HAL"; then
      echo "[fktee-hal] HAL daemon 未运行，自动重启" >>"$TEERS_DIR/logs/hal.log" 2>/dev/null
      start_hal
    fi
  fi

  # props 仅在文件变更时重应用（loop 模式），减少 CPU 占用
  if check_props_change; then
    apply_props loop
  fi

  sleep 5
done
