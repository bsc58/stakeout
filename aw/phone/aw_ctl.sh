#!/system/bin/sh
# aw_ctl.sh — runs on the phone as root. Starts and stops the Stakeout monitors.
#
#   aw_ctl.sh start <uid> <package> [net: 1|0] [filetrace: 1|0] [max seconds, default 3600] [decrypt: 1|0, default 0]
#   aw_ctl.sh start all - [net] [filetrace] [max seconds] [decrypt]      the whole phone, every app
#   aw_ctl.sh stop
#   aw_ctl.sh status
#   aw_ctl.sh clean
#
# Everything it creates lives in /data/local/tmp/appwatch (raw output in out/)
# plus one ftrace instance. It changes no settings and touches no other path.
#
# Monitors are tracked by pid files. Never use `pkill -f <pattern>` here: the
# pattern also matches the shell that runs the command and kills it.
#
# `start` also starts aw_watchdog.sh, which runs `stop` itself after <max seconds> or when
# /data runs low, so that a capture whose computer went away does not run on for ever.
# `stop` can therefore run twice; the second one changes nothing.
#
# decrypt 1 runs eCapture ($D/ecapture, pushed by the computer) in keylog mode with the one
# invocation that was tested on this phone: it writes the TLS keys of the app's handshakes to
# out/tls_keys.log, and the computer decrypts net.pcap with them. Never give it -i/--ifname,
# -w/--pcapfile or a pcap/pcapng mode: their cleanup removed the system's own clsact qdisc
# from wlan0 in a test.
#
# `start all -` watches the whole phone instead of one app (out/scope says `phone`): the poll
# is aw_poll_all.sh, appops is dumped for every package, out/packages.txt lists every package
# with its APK path and uid, and eCapture runs without -u, so it records the keys of every
# app (tested on this phone: same clean start and stop, clsact untouched).

D=/data/local/tmp/appwatch
O=$D/out
T=/sys/kernel/tracing/instances/appwatch
LIBSSL=/apex/com.android.conscrypt/lib64/libssl.so
EV="f2fs/f2fs_dataread_start f2fs/f2fs_datawrite_start"
MON="watchdog poll tcpdump logcat trace ecapture"

# stime <pid>: the process's start time, field 22 of /proc/<pid>/stat (field 20 after
# "(comm) "; exec keeps it). Empty when there is no such process.
stime() {
  sed 's/.*) //' "/proc/$1/stat" 2>/dev/null | awk '{print $20}'
}

# spawn <name> <stdout file> <command...>: detached from the adb session.
# $D/<name>.pid gets "<pid> <start time>", read the same way as in stime.
spawn() {
  name="$1"; out="$2"; shift 2
  setsid sh -c 'echo $$ $(sed "s/.*) //" /proc/$$/stat | awk "{print \$20}") > "$0"; exec "$@"' "$D/$name.pid" "$@" < /dev/null > "$out" 2>> "$O/errors.log" &
}

# alive <name>: true while the process in $D/<name>.pid still runs; sets p to its pid.
# The start time must match: a pid file can outlive its monitor (the monitor exited
# early, or the run was aborted; the files survive a reboot), and on this phone pids
# come round again within minutes, so the pid alone may now be any other process.
# The shell running this script is never one to stop: the watchdog execs `stop` itself.
alive() {
  p=; s=
  [ -f "$D/$1.pid" ] && read -r p s < "$D/$1.pid"
  [ -n "$p" ] && [ -n "$s" ] && [ "$p" != "$$" ] && [ "$(stime "$p")" = "$s" ]
}

# eCapture with SIGINT: it then detaches its probes, finishes tls_keys.log and prints
# "bye bye.". Same 5 s wait and SIGKILL fallback as for the other monitors.
stop_ecapture() {
  i=0
  if alive ecapture; then
    kill -INT "$p" 2>/dev/null
    while alive ecapture && [ $i -lt 50 ]; do sleep 0.1; i=$((i+1)); done
    alive ecapture && kill -9 "$p" 2>/dev/null
  fi
  rm -f "$D/ecapture.pid"
}

# Prints an ERR line and returns 1 when the trace instance could not be removed.
stop_monitors() {
  # eCapture first; the other monitors are stopped only after it is gone.
  stop_ecapture
  for n in $MON; do
    alive "$n" && kill "$p" 2>/dev/null
  done
  # kill only sends the signal; mksh acts on it after its current command. Seen on
  # the phone: aw_poll.sh, killed during `sleep 1`, was still alive in ps_after.txt.
  # Wait until the monitors are gone, so that nothing runs and the output files are
  # final when stop returns. After 5 s, SIGKILL what is left.
  i=0
  for n in $MON; do
    while alive "$n" && [ $i -lt 50 ]; do sleep 0.1; i=$((i+1)); done
    alive "$n" && kill -9 "$p" 2>/dev/null
    rm -f "$D/$n.pid"
  done
  if [ -d "$T" ]; then
    echo 0 > "$T/tracing_on"
    for e in $EV; do echo 0 > "$T/events/$e/enable"; done
    i=0
    while [ -d "$T" ] && [ $i -lt 5 ]; do rmdir "$T" 2>/dev/null || sleep 1; i=$((i+1)); done
  fi
  if [ -d "$T" ]; then echo "ERR trace instance $T still present"; return 1; fi
}

# filters_ok: true when both events read back the filter that keeps the trace from
# recording its own output. A rejected filter reads back as "none" or with an error text.
filters_ok() {
  for e in $EV; do
    grep -q pathbuf "$T/events/$e/filter" 2>/dev/null || return 1
    grep -qi error "$T/events/$e/filter" 2>/dev/null && return 1
  done
  return 0
}

case "$1" in
start)
  U="$2"; PKG="$3"; NET="${4:-1}"; FT="${5:-1}"; MAX="${6:-3600}"; DEC="${7:-0}"
  [ -n "$U" ] && [ -n "$PKG" ] || { echo "ERR usage: aw_ctl.sh start <uid> <package> [net] [filetrace] [max seconds] [decrypt]"; exit 2; }
  [ -f "$D/aw_poll.sh" ] || { echo "ERR $D/aw_poll.sh missing"; exit 2; }
  [ -f "$D/aw_watchdog.sh" ] || { echo "ERR $D/aw_watchdog.sh missing"; exit 2; }
  if [ "$U" = all ]; then
    [ -f "$D/aw_poll_all.sh" ] || { echo "ERR $D/aw_poll_all.sh missing"; exit 2; }
  fi
  if [ -f "$D/running" ]; then echo "ERR already running (run: aw_ctl.sh stop)"; exit 3; fi
  rm -rf "$O"; mkdir -p "$O"
  : > "$O/errors.log"
  echo "$PKG" > "$O/package"; echo "$U" > "$O/uid"
  if [ "$U" = all ]; then echo phone > "$O/scope"; else echo app > "$O/scope"; fi
  for k in ro.product.brand ro.product.model ro.build.version.release ro.build.version.sdk ro.build.display.id; do
    echo "$k=$(getprop $k)"
  done > "$O/device_props.txt"
  uname -r > "$O/kernel.txt"
  ps -A -o PID,PPID,USER,NAME > "$O/ps_before.txt" 2>&1
  if [ "$U" = all ]; then
    pm list packages -f -U > "$O/packages.txt" 2>&1
    pm list packages -3 > "$O/packages_third.txt" 2>&1
    dumpsys appops > "$O/appops_before.txt" 2>&1
  else
    dumpsys package "$PKG" > "$O/package_dump.txt" 2>&1
    dumpsys appops --package "$PKG" > "$O/appops_before.txt" 2>&1
  fi
  date '+%F %T' > "$O/start_time"; date +%s > "$O/start_epoch"; date +%z > "$O/utc_offset"
  spawn watchdog /dev/null sh "$D/aw_watchdog.sh" "$MAX"

  if [ "$FT" != 1 ]; then
    echo none > "$O/filetrace_backend"
  elif [ ! -d /sys/kernel/tracing/events/f2fs/f2fs_dataread_start ]; then
    echo "WARN unavailable f2fs_events"; echo f2fs_events >> "$O/unavailable"
    echo none > "$O/filetrace_backend"
  else
    mkdir -p "$T"
    echo 0 > "$T/tracing_on"; echo > "$T/trace"
    echo 1 > "$T/options/record-tgid"
    echo 8192 > "$T/buffer_size_kb"
    # Exclude our own output files: `cat trace_pipe > file` on f2fs would trace its own
    # writes and loop (seen on the phone: 845 MB in 11 seconds without this filter).
    # The filter form is only known to work on this phone's kernel: check that both
    # events took it, and trace nothing otherwise.
    for e in $EV; do echo '!(pathbuf ~ "/local/tmp/appwatch/*")' > "$T/events/$e/filter"; done
    if filters_ok; then
      for e in $EV; do echo 1 > "$T/events/$e/enable"; done
      echo 1 > "$T/tracing_on"
      echo "AW_SYNC $(date +%s)" > "$T/trace_marker"
      spawn trace "$O/filetrace_f2fs.txt" cat "$T/trace_pipe"
      echo f2fs > "$O/filetrace_backend"
    else
      rmdir "$T"
      echo "WARN unavailable trace_filter"; echo trace_filter >> "$O/unavailable"
      echo none > "$O/filetrace_backend"
    fi
  fi

  spawn logcat "$O/logcat.txt" logcat -b all -v threadtime -v year -T 1
  if [ "$NET" = 1 ] && command -v tcpdump > /dev/null 2>&1; then
    spawn tcpdump "$O/tcpdump.log" tcpdump -i any -s 0 -w "$O/net.pcap"
  elif [ "$NET" = 1 ]; then
    echo "WARN unavailable tcpdump"; echo tcpdump >> "$O/unavailable"
  fi
  if [ "$U" = all ]; then
    spawn poll "$O/poll.txt" sh "$D/aw_poll_all.sh" "$O/appops_all.txt.gz"
  else
    spawn poll "$O/poll.txt" sh "$D/aw_poll.sh" "$U" "$PKG"
  fi

  # A failed eCapture start does not fail the capture: it runs on without decryption.
  if [ "$DEC" != 1 ]; then
    echo none > "$O/decrypt"
  elif [ ! -f "$D/ecapture" ] || [ ! -f "$LIBSSL" ]; then
    echo "WARN unavailable ecapture"; echo ecapture >> "$O/unavailable"
    echo none > "$O/decrypt"
  else
    # Working directory $D. stderr joins stdout in ecapture_keylog_stdout.log: a crash prints
    # its Go panic trace there. One app: -u <uid>. The whole phone: no -u (UF stays empty and,
    # unquoted, adds no argument).
    UF=; [ "$U" = all ] || UF="-u $U"
    ( cd "$D" && spawn ecapture "$O/ecapture_keylog_stdout.log" sh -c 'exec "$0" "$@" 2>&1' \
        ./ecapture tls -m keylog \
        -k "$O/tls_keys.log" \
        --libssl="$LIBSSL" \
        $UF -b 2 \
        -l "$O/ecapture_keylog.log" )
    # Only handshakes made while it runs give keys, so the capture counts as started only once
    # its log says the probe is attached (about 2 s on this phone). Up to 10 s; it exits at
    # once when it cannot load. spawn returns before the pid file is written.
    i=0
    while [ $i -lt 100 ] && ! grep -q '"message":"probe started successfully."' "$O/ecapture_keylog.log" 2>/dev/null; do
      [ -s "$D/ecapture.pid" ] && ! alive ecapture && break
      sleep 0.1; i=$((i+1))
    done
    if alive ecapture && grep -q '"message":"probe started successfully."' "$O/ecapture_keylog.log" 2>/dev/null; then
      echo keylog > "$O/decrypt"
    else
      # Still running without that line after 10 s: it records nothing useful; stop it now.
      if alive ecapture; then stop_ecapture; fi
      echo "WARN unavailable ecapture"; echo ecapture >> "$O/unavailable"
      echo none > "$O/decrypt"
    fi
  fi

  touch "$D/running"
  echo "OK started $(cat "$O/start_time")"
  ;;

stop)
  [ -d "$O" ] || { echo "ERR nothing to stop"; exit 3; }
  stop_monitors
  # Already stopped (by the watchdog): keep that end time and the files written then.
  if [ -f "$D/running" ] || [ ! -f "$O/end_time" ]; then
    date '+%F %T' > "$O/end_time"; date +%s > "$O/end_epoch"
    PKG="$(cat "$O/package" 2>/dev/null)"
    if [ "$(cat "$O/scope" 2>/dev/null)" = phone ]; then
      dumpsys appops > "$O/appops_after.txt" 2>&1
    elif [ -n "$PKG" ]; then
      dumpsys appops --package "$PKG" > "$O/appops_after.txt" 2>&1
    fi
    ps -A -o PID,PPID,USER,NAME > "$O/ps_after.txt" 2>&1
    rm -f "$D/running"
  fi
  echo "OK stopped $(cat "$O/end_time")"
  ;;

status)
  if [ -f "$D/running" ]; then echo "running since $(cat "$O/start_time" 2>/dev/null)"; else echo "idle"; fi
  for n in $MON; do
    if [ -f "$D/$n.pid" ]; then
      if alive "$n"; then echo "$n pid=$p alive"; else echo "$n pid=$p dead"; fi
    fi
  done
  [ -d "$T" ] && echo "trace instance present"
  ;;

clean)
  stop_monitors; r=$?
  rm -rf /data/local/tmp/appwatch
  if [ $r = 0 ]; then echo "OK cleaned"; fi
  ;;

*)
  echo "usage: aw_ctl.sh start <uid> <package> [net] [filetrace] [max seconds] [decrypt] | stop | status | clean"
  exit 2
  ;;
esac
