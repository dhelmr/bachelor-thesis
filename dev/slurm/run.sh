#!/bin/bash
BASEDIR=$(dirname "$0")
JOB_ARGS=$(echo "$*" | base64)
JOB_FILE="$BASEDIR/custom.job"

echo "Start $NAME with '$JOB_ARGS'"
JOB_ID=$(sbatch --output="slurmlogs/%j.out" --export="ARGS=$JOB_ARGS" "$JOB_FILE" | cut -d " " -f 4)
watch "sacct | tail && echo '-----output-----' && tail -n 15 slurmlogs/$JOB_ID.out"
echo "JOB_ID=$JOB_ID"
