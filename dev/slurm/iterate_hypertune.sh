#!/bin/bash

trap 'kill $(jobs -p)' EXIT;

BASEDIR=$(dirname "$0")
JOB_FILE="$BASEDIR/hypertune.job"
ARGS="$*"
MAX_JOB_COUNT=20

cd "$BASEDIR/../.." || exit

mkdir -p slurmlogs

START=${START:-0}
for i in {0..1000}; do
  if [ $i -lt $START ]; then
    continue
  fi
  for f in ./hypertune/activated/*.json; do
    NAME="$f-$i-$ARGS"
    JOB_ARGS=$(echo "hypertune --only-index $i -f $f $ARGS" | base64)
    echo "Start $NAME with '$(echo "$JOB_ARGS" | base64 -d)'"
    sbatch --output="slurmlogs/%j.out" --export="ARGS=$JOB_ARGS" "$JOB_FILE"

    # backoff wait and assure that only max num of jobs are running/pending at the same time
    sleep 10
    CURRENT_JOBS=$(sacct --allocation | grep -c -E "(RUNNING|PENDING)")
    while [ $CURRENT_JOBS -ge $MAX_JOB_COUNT ]; do
      sleep 5
      CURRENT_JOBS=$(sacct --allocation | grep -c -E "(RUNNING|PENDING)")
    done
  done


done