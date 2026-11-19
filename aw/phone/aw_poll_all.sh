#!/system/bin/sh
# aw_poll_all.sh <appops file> — the whole-phone poll (aw_poll.sh watches one app).
# Runs on the phone as root. Prints one block per second to stdout.
# Line kinds (see docs/CONTRACT_PHONE.md, "poll.txt of a phone run"):
#   === <YYYY-MM-DD HH:MM:SS>          block start
#   topResumedActivity=...             raw line from dumpsys (front activity)
#   P <pid> <ppid> <uid> <name>        every process that runs under an app's uid (>= 10000)
#   S tcp|udp <raw ss line>            every socket; the line carries uid:<n> (none: uid 0)
# Every 10th block it also appends to <appops file> one gzip member holding
#   === <epoch> <YYYY-MM-DD HH:MM:SS>
# followed by the full output of `dumpsys appops` (every package; about 2 MB of text).
A="$1"
[ -n "$A" ] || { echo "usage: aw_poll_all.sh <appops file>" >&2; exit 2; }

n=0
while true; do
  echo "=== $(date '+%F %T')"
  dumpsys activity activities 2>/dev/null | grep -m1 topResumedActivity
  ps -A -o PID,PPID,UID,NAME 2>/dev/null | awk '$3 + 0 >= 10000 { printf "P %s %s %s", $1, $2, $3; for (i = 4; i <= NF; i++) printf " %s", $i; print "" }'
  ss -tneH 2>/dev/null | sed 's/^/S tcp /'
  ss -uneH 2>/dev/null | sed 's/^/S udp /'
  if [ $((n % 10)) = 0 ]; then
    { echo "=== $(date +%s) $(date '+%F %T')"; dumpsys appops 2>&1; } | gzip >> "$A"
  fi
  n=$((n+1))
  sleep 1
done
