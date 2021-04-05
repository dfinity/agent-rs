let
  # Pinned nixpkgs, deterministic. Last updated: 2/12/21.
  frameworks = pkgs.darwin.apple_sdk.frameworks;
  pkgs = import (fetchTarball
    ("https://github.com/NixOS/nixpkgs/archive/a58a0b5098f0c2a389ee70eb69422a052982d990.tar.gz"))
    { };
  # Rolling updates, not deterministic.
  # pkgs = import (fetchTarball("channel:nixpkgs-unstable")) {};
in pkgs.mkShell {
  buildInputs =
    [ pkgs.cargo pkgs.rustc pkgs.openssl.dev pkgs.openssl pkgs.pkgconfig pkgs.libiconv ]
    ++ (pkgs.lib.optionals pkgs.stdenv.isDarwin [
      frameworks.Security
      frameworks.CoreServices
      frameworks.CoreFoundation
      frameworks.Foundation
      frameworks.AppKit
    ]);
}
