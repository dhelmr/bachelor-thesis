#!/usr/bin/env bash

DB_FILE="data/2021_unsw_nb15.db"

if [ ! -f "$DB_FILE" ]; then
  echo "database $DB_FILE does not exist, create it first"
  exit 1
fi

dev/slurm/iterate_hypertune.sh --dataset unsw-nb15 --subset 10-24/1-9 --src unsw-nb15 --db "$DB_FILE" &
dev/slurm/iterate_hypertune.sh --dataset unsw-nb15 --subset 10-24/54-67 --src unsw-nb15 --db "$DB_FILE" &
dev/slurm/iterate_hypertune.sh --dataset unsw-nb15 --subset 10-24/68-80 --src unsw-nb15 --db "$DB_FILE" &

dev/slurm/iterate_hypertune.sh --dataset unsw-nb15 --subset 25-53/1-9 --src unsw-nb15 --db "$DB_FILE" &
dev/slurm/iterate_hypertune.sh --dataset unsw-nb15 --subset 25-53/54-67 --src unsw-nb15 --db "$DB_FILE" &
dev/slurm/iterate_hypertune.sh --dataset unsw-nb15 --subset 25-53/68-80 --src unsw-nb15 --db "$DB_FILE" &


while :
do
 sleep 86400 # wait 1 day
 timestamp=$(date +"%Y-%m-%d")
 REPORT_DIR="data/reports/unsw-nb15/$timestamp"
 VIS_DIR="data/visualizations/unsw-nb15/$timestamp/"
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