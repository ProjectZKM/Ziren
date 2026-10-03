#!/bin/bash
# run_mod.sh PREFIX MOD: elaborate $R/PREFIX/MOD.lean (writing its .olean unless MOD is Check),
# where R is this script's directory (the split root the Makefile lives in).
#
# Environment: LEAN_PROJECT (the lake project whose `lake env` provides Mathlib and ZirenDet,
# required), LEAN_THREADS (default 2), MIN_FREE (GB of MemAvailable a module waits for, default
# 60), MOD_TIMEOUT (seconds, default 1800), CPUS (taskset list, default all).  Two makes may run on
# one root: a module lock makes the second wait and skip a module the first has built.  Starts are
# serialised 2 s apart so a burst of ready modules cannot all pass the memory check at once.
R=$(cd "$(dirname "$0")" && pwd); p=$1; m=$2
: "${LEAN_PROJECT:?set LEAN_PROJECT to the lake project directory}"
export LEAN_NUM_THREADS=${LEAN_THREADS:-2}
avail(){ awk '/MemAvailable/ {print int($2/1048576)}' /proc/meminfo; }
mkdir -p $R/logs; out=$R/logs/$m.out
exec 8>$R/.mod.$m.lock; flock 8
if [ "$m" != Check ] && [ -f $R/$p/$m.olean ] && [ $R/$p/$m.olean -nt $R/$p/$m.lean ]; then exit 0; fi
exec 9>$R/.startlock; flock 9
while [ "$(avail)" -lt "${MIN_FREE:-60}" ]; do sleep 30; done
ulimit -s unlimited
o="-o $R/$p/$m.olean"; [ "$m" = Check ] && o=""
s=$(date +%s)
echo "$(date -u +%T) START $m avail=$(avail)" >> $R/progress.log
cd "$LEAN_PROJECT"
pin=(); [ -n "${CPUS:-}" ] && pin=(taskset -c "$CPUS")
"${pin[@]}" nice -n 10 timeout ${MOD_TIMEOUT:-1800} lake env bash -c "LEAN_PATH=$R:\$LEAN_PATH exec lean --tstack=4000000 -R $R $o $R/$p/$m.lean" > $out 2>&1 9>&- 8>&- &
pid=$!
sleep 2; flock -u 9; exec 9>&-
wait $pid; rc=$?
echo "$(date -u +%T) END $m rc=$rc wall=$(( $(date +%s)-s ))s sorry=$(grep -ac "declaration uses .sorry" $out) open=$(grep -ac PICUS_OPEN $out) err=$(grep -ac ": error" $out)" >> $R/progress.log
exit $rc
