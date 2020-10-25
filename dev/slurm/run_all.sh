#!/bin/bash

BASEDIR=$(dirname "$0")
EXEC="$BASEDIR/iterate_hypertune.sh"

($EXEC --db data/sqlite.db --dataset cic-ids-2017 --subset wednesday) &
$EXEC --db data/sqlite.db --dataset unsw-nb15 --src unsw-nb15