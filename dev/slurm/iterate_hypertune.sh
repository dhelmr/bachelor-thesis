#!/bin/bash

BASEDIR=$(dirname "$0")
JOB_FILE="$BASEDIR/hypertune.job"
ARGS="$*"
MAX_JOB_COUNT=10

cd "$BASEDIR/../.." || exit

mkdir -p slurmlogs

for i in {0..1000}; do
  for f in ./hypertune/*; do
    NAME="$f-$i-$ARGS"
    JOB_ARGS="--only-index $i -f $f $ARGS"
    echo "Start $NAME with '$JOB_ARGS'"
    sbatch --output="slurmlogs/%j.out" --export="HYPERTUNE_ARGS=$JOB_ARGS" "$JOB_FILE"
  done
  CURRENT_JOBS=$(sacct --allocation | grep -c RUNNING)
  while [ $CURRENT_JOBS -ge $MAX_JOB_COUNT ]; do
    sleep 5
    CURRENT_JOBS=$(sacct --allocation | grep -c RUNNING)
  done
  sleep 3
done