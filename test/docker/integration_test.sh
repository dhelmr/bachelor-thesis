#!/bin/bash

# This script is supposed to be run inside the docker container

# Warning! Before changing paths, keep in mind that the data might be mounted from /data, i.e. is accessing the datasets
# as well on the file system, not just inside the docker container

set -eux
set -o pipefail

cp /integration_test/assert.py /app
cd /app

python bin/run_canids migrate-db --db /sqlite.db
python bin/run_canids list-fe
python bin/run_canids list-de
python bin/run_canids train --dataset unsw-nb15 --subset tiny --db /sqlite.db -m model-test-1234
./assert.py 3 --eq "$(python bin/run_canids list-models --db /sqlite.db | wc -l)"
./assert.py 1 --eq "$(python bin/run_canids list-models --db /sqlite.db | grep -c model-test-1234)"
python bin/run_canids classify --dataset unsw-nb15 --subset tiny --db /sqlite.db --id model-test-1234/cl-1 -m model-test-1234
python bin/run_canids classify --dataset unsw-nb15 --subset tiny --db /sqlite.db --id model-test-1234/cl-2 -m model-test-1234
python bin/run_canids evaluate --dataset unsw-nb15 --subset tiny --db /sqlite.db --id model-test-1234/cl-2
python bin/run_canids evaluate --dataset unsw-nb15 --subset tiny --db /sqlite.db --id model-test-1234/cl-1
python bin/run_canids migrate-db --db /sqlite.db