#!/bin/bash

BASEDIR=$(dirname "$0")
JOB_FILE="$BASEDIR/hypertune.job"
ARGS="$*"

cd "$BASEDIR/../.." || exit

mkdir -p slurmlogs

for i in {0..1000}; do
  for f in ./hypertune/*; do
    NAME="$f-$i-$ARGS"
    JOB_ARGS="$ARGS --only-index=$i -f $f"
    echo "Start $NAME with '$JOB_ARGS'"
    sbatch --output="slurmlogs/%a.out" --export="HYPERTUNE_ARGS=$JOB_ARGS" "$JOB_FILE"
  done
  sleep 1800
done