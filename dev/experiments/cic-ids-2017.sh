#!/usr/bin/env bash

DB_FILE="db/2021_cic_ids_2017.db"

if [ ! -f "$DB_FILE" ]; then
  echo "database $DB_FILE does not exist, create it first"
  exit 1
fi

dev/slurm/iterate_hypertune.sh --dataset cic-ids-2017 --subset tuesday --src cic-ids-2017 --db "$DB_FILE" &
dev/slurm/iterate_hypertune.sh --dataset cic-ids-2017 --subset wednesday --src cic-ids-2017 --db "$DB_FILE" &
dev/slurm/iterate_hypertune.sh --dataset cic-ids-2017 --subset thursday --src cic-ids-2017 --db "$DB_FILE" &
dev/slurm/iterate_hypertune.sh --dataset cic-ids-2017 --subset friday --src cic-ids-2017 --db "$DB_FILE" &

while :
do
 sleep 86400 # wait 1 day
 timestamp=$(date +"%Y-%m-%d")
 REPORT_DIR="data/reports/cic-ids-2017/$timestamp"
 VIS_DIR="data/visualizations/cic-ids-2017/$timestamp/"
 mkdir -p "$REPORT_DIR"
 mkdir -p "$VIS_DIR"
 # create reports
 dev/slurm/run_small_mem.sh report --db "$DB_FILE" --model-part-name autoencoder --output "$REPORT_DIR" --format csv
 dev/slurm/run_small_mem.sh report --db "$DB_FILE" --model-part-name one_class_svm --output "$REPORT_DIR" --format csv
 dev/slurm/run_small_mem.sh report --db "$DB_FILE" --model-part-name payl_flows --output "$REPORT_DIR" --format csv
 dev/slurm/run_small_mem.sh report --db "$DB_FILE" --model-part-name flows_payload --output "$REPORT_DIR" --format csv
 dev/slurm/run_small_mem.sh report --db "$DB_FILE" --model-part-name flow_extractor --output "$REPORT_DIR" --format csv
 # create visualizations
 dev/slurm/run_small_mem.sh visualize --model-part-name flow_extractor -o "$VIS_DIR" --db "$DB_FILE"
 dev/slurm/run_small_mem.sh visualize --model-part-name one_class_svm -o "$VIS_DIR" --db "$DB_FILE"
 dev/slurm/run_small_mem.sh visualize --model-part-name payl_flows -o "$VIS_DIR" --db "$DB_FILE"
 dev/slurm/run_small_mem.sh visualize --model-part-name flows_payload -o "$VIS_DIR" --db "$DB_FILE"
 dev/slurm/run_small_mem.sh visualize --model-part-name autoencoder -o "$VIS_DIR" --db "$DB_FILE"
done