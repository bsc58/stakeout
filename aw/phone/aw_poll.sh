#!/system/bin/sh
# aw_poll.sh <uid> <package>
# Runs on the phone as root. Prints one block per second to stdout.
# Line kinds (see docs/CONTRACT.md, "poll.txt"):
#   === <YYYY-MM-DD HH:MM:SS>          block start
#   topResumedActivity=...             raw line from dumpsys (front activity)
#   P <pid> <cmdline>| k=v ... | rchar: N syscr: N read_bytes: N
#     FD -> <path>                     open file on shared storage outside the app's own dirs
#   S tcp|udp <raw ss line>            socket owned by the uid
#   OT <epoch>                         wall clock right before the appops query
#   O <raw `appops get` line>
U="$1"
PKG="$2"
[ -n "$U" ] && [ -n "$PKG" ] || { echo "usage: aw_poll.sh <uid> <package>" >&2; exit 2; }

while true; do
  echo "=== $(date '+%F %T')"
  dumpsys activity activities 2>/dev/null | grep -m1 topResumedActivity
  for p in $(pgrep -u "$U"); do
    [ -r /proc/$p/stat ] || continue
    n=$(tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null)
    # fields after the "(comm) " part: 1=state 2=ppid ... 12=utime 13=stime
    st=$(sed 's/.*) //' /proc/$p/stat 2>/dev/null | awk '{print "ppid="$2" ut="$12" st="$13}')
    io=$(grep -E '^(rchar|syscr|read_bytes)' /proc/$p/io 2>/dev/null | tr '\n' ' ')
    adj=$(cat /proc/$p/oom_score_adj 2>/dev/null)
    fz=$(cat /sys/fs/cgroup/uid_$U/pid_$p/cgroup.freeze 2>/dev/null)
    echo "P $p $n| adj=$adj frozen=$fz $st | $io"
    ls -l /proc/$p/fd 2>/dev/null | grep -E '/storage/|/sdcard|/data/media/|/mnt/' | grep -v "$PKG" | sed 's/^.* -> /  FD -> /'
  done
  ss -tneH 2>/dev/null | grep "uid:$U " | sed 's/^/S tcp /'
  ss -uneH 2>/dev/null | grep "uid:$U " | sed 's/^/S udp /'
  echo "OT $(date +%s)"
  appops get "$PKG" 2>/dev/null | sed 's/^/O /'
  sleep 1
done
