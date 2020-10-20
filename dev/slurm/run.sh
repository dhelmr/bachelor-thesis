#!/bin/bash

BASEDIR=$(dirname "$0")
JOB_FILE="$BASEDIR/hypertune.job"
ARGS="$@"

cd "$BASEDIR/../.." || exit

mkdir -p slurmlogs

for i in {0..1000}; do
  for f in ./hypertune/*; do
    NAME="$f-$i-$ARGS"
    JOB_ARGS="$ARGS --only-id=$i"
    echo "Start $NAME with '$JOB_ARGS'"
    sbatch --job-name="$NAME.run" --output="slurmlogs/$NAME.out" --export="HYPERTUNE_ARGS=$JOB_ARGS" "$JOB_FILE"
  done
  sleep 1800
done