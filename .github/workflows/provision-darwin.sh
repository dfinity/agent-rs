#!/bin/bash

set -ex

# Enter temporary directory.
pushd /tmp

# Install Node.
version=14.15.4
curl --location --output node.pkg "https://nodejs.org/dist/v$version/node-v$version.pkg"
sudo installer -pkg node.pkg -store -target /
rm node.pkg

# Exit temporary directory.
popd

# Build icx
cargo build -p icx
ICX="$(pwd)/target/debug/icx"
echo "ICX=$ICX" >> "$GITHUB_ENV"
