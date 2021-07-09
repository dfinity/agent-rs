#!/bin/bash

set -ex

# Enter temporary directory.
pushd /tmp

# Install Node.
wget --output-document install-node.sh "https://deb.nodesource.com/setup_14.x"
sudo bash install-node.sh
sudo apt-get install --yes nodejs
rm install-node.sh

# Install Bats.
sudo apt-get install --yes bats

# Install Bats support.
version=0.3.0
wget https://github.com/ztombol/bats-support/archive/v$version.tar.gz
sudo mkdir /usr/local/lib/bats-support
sudo tar --directory /usr/local/lib/bats-support --extract --file v$version.tar.gz --strip-components 1
rm v$version.tar.gz

# Install DFINITY SDK.
version=0.7.2
wget --output-document install-dfx.sh "https://sdk.dfinity.org/install.sh"
DFX_VERSION=$version bash install-dfx.sh < <(yes Y)
rm install-dfx.sh

# Set environment variables.
BATS_SUPPORT="/usr/local/lib/bats-support"
echo "BATS_SUPPORT=${BATS_SUPPORT}" >> ${GITHUB_ENV}
echo "$HOME/bin" >> $GITHUB_PATH

# Exit temporary directory.
popd

# Build icx-asset
cargo build -p icx-asset
ICX_ASSET="$(pwd)/target/debug/icx-asset"
echo "ICX_ASSET=$ICX_ASSET" >> $GITHUB_ENV
echo $PATH
$ICX_ASSET help

