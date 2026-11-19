#!/system/bin/sh
# aw_watchdog.sh <seconds>
# Runs on the phone as root, started by `aw_ctl.sh start` like the other monitors.
# Ends the capture with `aw_ctl.sh stop` when the computer has not ended it within
# <seconds> (cable pulled, computer asleep, terminal closed), or as soon as /data has
# less than MIN_FREE_KB free. Writes the reason into out/autostop. The data stays in
# out/ until `stakeout.py fetch` takes it home. `aw_ctl.sh stop` from the computer
# ends this script first.
D=/data/local/tmp/appwatch
MIN_FREE_KB=1048576
[ -n "$1" ] || { echo "usage: aw_watchdog.sh <seconds>" >&2; exit 2; }
end=$(( $(date +%s) + $1 ))
why=deadline
while [ "$(date +%s)" -lt "$end" ]; do
  # df -k: "Filesystem 1K-blocks Used Available Use% Mounted on"; a long device name may
  # wrap the line, so take the 3rd field from the end of the last line.
  free=$(df -k /data 2>/dev/null | tail -n 1 | awk '{print $(NF-2)}')
  if [ -n "$free" ] && [ "$free" -lt "$MIN_FREE_KB" ] 2>/dev/null; then why=disk; break; fi
  sleep 1
done
echo "$why" > "$D/out/autostop"
exec sh "$D/aw_ctl.sh" stop > /dev/null
