#!/bin/bash

set -ex

# Enter temporary directory.
pushd /tmp

# Install Node.
wget --output-document install-node.sh "https://deb.nodesource.com/setup_14.x"
sudo bash install-node.sh
sudo apt-get install --yes nodejs
rm install-node.sh

# Exit temporary directory.
popd

# Build icx
cargo build -p icx
ICX="$(pwd)/target/debug/icx"
echo "ICX=$ICX" >> "$GITHUB_ENV"
