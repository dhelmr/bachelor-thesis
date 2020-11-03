#!/bin/bash

trap 'kill $(jobs -p)' EXIT;

BASEDIR=$(dirname "$0")
JOB_FILE="$BASEDIR/hypertune.job"
ARGS="$*"
MAX_JOB_COUNT=10

cd "$BASEDIR/../.." || exit

mkdir -p slurmlogs

for i in {0..1000}; do
  for f in ./hypertune/activated/*.json; do
    NAME="$f-$i-$ARGS"
    JOB_ARGS=$(echo "--only-index $i -f $f $ARGS" | base64)
    echo "Start $NAME with '$JOB_ARGS'"
    sbatch --output="slurmlogs/%j.out" --export="HYPERTUNE_ARGS=$JOB_ARGS" "$JOB_FILE"
  done
  sleep 10
  CURRENT_JOBS=$(sacct --allocation | grep -c -E "(RUNNING|PENDING)")
  while [ $CURRENT_JOBS -ge $MAX_JOB_COUNT ]; do
    sleep 5
    CURRENT_JOBS=$(sacct --allocation | grep -c -E "(RUNNING|PENDING)")
  done

done