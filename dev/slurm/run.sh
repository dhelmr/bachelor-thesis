#!/bin/bash

BASEDIR=$(dirname "$0")
JOB_FILE="$BASEDIR/hypertune.job"
ARGS="$@"

cd "$BASEDIR/../.." || exit

mkdir slurmlogs

for f in ./hypertune/*; do
  for i in {0..1000}; do
    NAME="$f_$i_$ARGS"
    JOB_ARGS="$ARGS --only-id=$i"
    sbatch --job-name="$NAME.run" --output="slurmlogs/$NAME.out" --export="HYPERTUNE_ARGS=$JOB_ARGS" "$JOB_FILE"
  done
done