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
curl --location --output bats-support.tar.gz https://github.com/ztombol/bats-support/archive/v$version.tar.gz
sudo mkdir /usr/local/lib/bats-support
sudo tar --directory /usr/local/lib/bats-support --extract --file bats-support.tar.gz --strip-components 1
rm bats-support.tar.gz

# Install DFINITY SDK.
wget --output-document install-dfx.sh "https://sdk.dfinity.org/install.sh"
DFX_VERSION="$INSTALL_DFX_VERSION" bash install-dfx.sh < <(yes Y)
rm install-dfx.sh

# Set environment variables.
BATS_SUPPORT="/usr/local/lib/bats-support"
echo "BATS_SUPPORT=${BATS_SUPPORT}" >> "$GITHUB_ENV"
echo "$HOME/bin" >> "$GITHUB_PATH"

# Exit temporary directory.
popd

# Build icx
cargo build -p icx
ICX="$(pwd)/target/debug/icx"
echo "ICX=$ICX" >> "$GITHUB_ENV"
