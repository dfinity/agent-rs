#!/bin/bash

set -ex

# Enter temporary directory.
pushd /tmp

# Install Node.
version=14.15.4
curl --location --output node.pkg "https://nodejs.org/dist/v$version/node-v$version.pkg"
sudo installer -pkg node.pkg -store -target /
rm node.pkg

# Install Bats.
if [ "$(uname -r)" = "19.6.0" ]; then
    brew unlink bats
fi
brew install bats-core

# Install Bats support.
version=0.3.0
curl --location --output bats-support.tar.gz https://github.com/ztombol/bats-support/archive/v$version.tar.gz
mkdir /usr/local/lib/bats-support
tar --directory /usr/local/lib/bats-support --extract --file bats-support.tar.gz --strip-components 1
rm bats-support.tar.gz

# Install DFINITY SDK.
version=0.7.2
curl --location --output install-dfx.sh "https://sdk.dfinity.org/install.sh"
DFX_VERSION=$version bash install-dfx.sh < <(yes Y)
rm install-dfx.sh

# Set environment variables.
BATS_SUPPORT="/usr/local/lib/bats-support"
echo "BATS_SUPPORT=${BATS_SUPPORT}" >> "$GITHUB_ENV"

# Exit temporary directory.
popd

# Build icx-asset
cargo build -p icx-asset
ICX_ASSET="$(pwd)/target/debug/icx-asset"
echo "ICX_ASSET=$ICX_ASSET" >> "$GITHUB_ENV"

# Build icx
cargo build -p icx
ICX="$(pwd)/target/debug/icx"
echo "ICX=$ICX" >> "$GITHUB_ENV"
