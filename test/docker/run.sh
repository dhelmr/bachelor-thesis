#!/bin/bash

set -eux
set -o pipefail

cd $(dirname "$0")

docker run -v $(pwd)/../../data:/data -v $(pwd):/integration_test/ -it --entrypoint /integration_test/integration_test.sh canids:latest

./assert.py 0 --eq "$?" --msg "Integration test failed!"
echo "Integration tests ran successfully"