#!/bin/bash

# This script is supposed to be run inside the docker container

# Warning! Before changing paths, keep in mind that the data might be mounted from /data, i.e. is accessing the datasets
# as well on the file system, not just inside the docker container

set -eux
set -o pipefail

cp /data/assert.py /app
cd /app

bin/run_canids migrate-db --db /sqlite.db
python bin/run_canids list-fe
python bin/run_canids list-de
python bin/run_canids train --dataset unsw-nb15 --subset tiny --db /sqlite.db -m model-test-1234
./assert.py 3 --eq "$(python bin/run_canids list-models --db /sqlite.db | wc -l)"
./assert.py 1 --eq "$(python bin/run_canids list-models --db /sqlite.db | grep -c model-test-1234)"
python bin/run_canids classify --dataset unsw-nb15 --subset tiny --db /sqlite.db --id model-test-1234/cl-1 -m model-test-1234
python bin/run_canids classify --dataset unsw-nb15 --subset tiny --db /sqlite.db --id model-test-1234/cl-2 -m model-test-1234
python bin/run_canids evaluate --dataset unsw-nb15 --subset tiny --db /sqlite.db --id model-test-1234/cl-2
python bin/run_canids evaluate --dataset unsw-nb15 --subset tiny --db /sqlite.db --id model-test-1234/cl-1


# just test whether all hyperparameter configurations can be run without problems
for f in hypertune/activated/*.json; do
  python bin/run_canids hypertune --dataset unsw-nb15 --subset tiny --db /sqlite.db -f "$f"
  python bin/run_canids hypertune --dataset unsw-nb15 --subset tiny --db /sqlite.db -f "$f" --only-index 1
done

VIS_DIR=$(mktemp -d)
bin/run_canids list-de -s | xargs -L 1 bin/run_canids visualize --db /sqlite.db -o "$VIS_DIR" --model-part-name
bin/run_canids list-fe -s | xargs -L 1 bin/run_canids visualize --db /sqlite.db -o "$VIS_DIR" --model-part-name

bin/run_canids stats --dataset unsw-nb15

# list evaluation for every model
OUTPUT="$(bin/run_canids list-models | cut -f 1 -d " " | tail -n +3 | xargs -L 1 bin/run_canids list-evaluations --db /sqlite.db --model )"
./assert.py "None" --not-in "$OUTPUT"

# list evaluation for every classification
OUTPUT="$(bin/run_canids list-classifications | cut -f 1 -d " " | tail -n +3 | xargs -L 1 bin/run_canids list-evaluations --db /sqlite.db --id )"
./assert.py "None" --not-in "$OUTPUT"

# should check if it still works; should not do anything
./assert.py "" --eq "$(bin/run_canids migrate-db --db /sqlite.db)"

bin/run_canids --help