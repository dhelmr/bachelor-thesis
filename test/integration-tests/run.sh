#!/bin/bash

set -eux
set -o pipefail

cd $(dirname "$0")

docker run -v $(pwd)/data:/data -v -it --entrypoint /data/integration_test.sh dhelmr/canids:latest

data/assert.py 0 --eq "$?" --msg "Integration test failed!"
echo "Integration tests ran successfully"
